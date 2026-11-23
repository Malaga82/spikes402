package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/config"
	"github.com/Choffolo/spikes402/internal/gate"
	"github.com/Choffolo/spikes402/internal/lightning"
)

//go:embed web
var webFiles embed.FS

// Role is who is calling the API.
type Role string

// Roles. The AI may read and propose changes; it may apply them only if
// "admin.ai_can_apply" is set, and only when the change does not reduce
// protection or need confirmation against the last settings a person
// applied. It can never withdraw or approve proposals.
const (
	RoleAdmin Role = "admin"
	RoleAI    Role = "ai"
)

// Options build a Server.
type Options struct {
	Config     *config.Config
	ConfigFile string // path passed to -config; overrides are written next to it
	Gate       *gate.Gate
	Monitor    *Monitor
	Node       lightning.Inspector  // may be nil
	Withdrawer lightning.Withdrawer // nil unless withdrawals are enabled
	// IntentStore records withdrawal intents on disk (optional; tests may omit it).
	IntentStore IntentStore
}

// Server is the admin API and dashboard.
type Server struct {
	gate       *gate.Gate
	mon        *Monitor
	node       lightning.Inspector
	withdrawer lightning.Withdrawer
	allowed    []*net.IPNet
	adminHash  [32]byte
	aiHash     [32]byte
	aiEnabled  bool
	started    time.Time
	now        func() time.Time

	mu          sync.Mutex // guards cfg, baseline, and changes to the gate's settings
	cfg         *config.Config
	configFile  string
	baseline    *config.Config // last settings a person applied; AI drift is measured against this
	baselineErr error          // set if the confirmed file exists but could not be read

	nodeMu    sync.Mutex
	nodeAt    time.Time
	nodeInfo  *lightning.NodeInfo
	nodeError string

	proposals *proposals
	wd        *withdrawals
}

// New returns a Server. Only call it when cfg.AdminEnabled().
func New(o Options) *Server {
	allowed, _ := o.Config.AdminAllowedNets() // validated by config.Load
	s := &Server{
		gate: o.Gate, mon: o.Monitor, node: o.Node, withdrawer: o.Withdrawer, allowed: allowed,
		adminHash: sha256.Sum256([]byte(o.Config.Admin.Key)),
		aiEnabled: o.Config.Admin.AIKey != "",
		started:   time.Now(), now: time.Now, cfg: o.Config, configFile: o.ConfigFile,
		proposals: newProposals(),
	}
	if s.aiEnabled {
		s.aiHash = sha256.Sum256([]byte(o.Config.Admin.AIKey))
	}
	if o.Config.Withdraw.Enabled && o.Withdrawer != nil {
		s.wd = newWithdrawals(o.Config.Withdraw.Destination, o.Config.Withdraw.Password, o.IntentStore)
		s.loadIntent()
	}
	s.initBaseline()
	return s
}

// initBaseline loads the last human-applied settings, or records the
// current config as that baseline when the file is not there yet.
func (s *Server) initBaseline() {
	s.baseline = s.cfg
	path := s.cfg.ConfirmedFile()
	if path == "" {
		return
	}
	b, err := config.ReadSnapshotFile(path, s.cfg)
	if err == nil {
		s.baseline = b
		return
	}
	if !os.IsNotExist(err) {
		s.baselineErr = err
		log.Printf("admin: could not read confirmed settings from %s: %v (AI apply is blocked until a human saves settings)", path, err)
		return
	}
	if err := config.WriteOverrides(path, s.cfg); err != nil {
		log.Printf("admin: could not save confirmed settings to %s: %v", path, err)
	}
}

// rememberConfirmed records n as the last settings a person applied.
// Called under s.mu after a successful human apply.
func (s *Server) rememberConfirmed(n *config.Config) {
	s.baseline = n
	s.baselineErr = nil
	if path := n.ConfirmedFile(); path != "" {
		if err := config.WriteOverrides(path, n); err != nil {
			log.Printf("admin: settings applied but confirmed baseline not saved to %s: %v", path, err)
		}
	}
}

// Handler returns the HTTP handler: the dashboard at "/" and the API at "/api/".
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web")
	files := http.FileServerFS(static)
	for _, p := range []string{"GET /{$}", "GET /app.js", "GET /style.css"} {
		mux.Handle(p, files)
	}

	mux.HandleFunc("GET /api/whoami", s.api(false, s.whoami))
	mux.HandleFunc("GET /api/status", s.api(false, s.status))
	mux.HandleFunc("GET /api/siege", s.api(false, s.siege))
	mux.HandleFunc("GET /api/stats", s.api(false, s.stats))
	mux.HandleFunc("GET /api/settings", s.api(false, s.getSettings))
	mux.HandleFunc("PUT /api/settings", s.api(false, s.putSettings))
	mux.HandleFunc("GET /api/proposals", s.api(false, s.listProposals))
	mux.HandleFunc("POST /api/proposals", s.api(false, s.propose))
	mux.HandleFunc("POST /api/proposals/{id}/approve", s.api(true, s.approve))
	mux.HandleFunc("POST /api/proposals/{id}/reject", s.api(true, s.reject))
	mux.HandleFunc("GET /api/withdraw", s.api(true, s.withdrawInfo))
	mux.HandleFunc("POST /api/withdraw/prepare", s.api(true, s.withdrawPrepare))
	mux.HandleFunc("POST /api/withdraw/confirm", s.api(true, s.withdrawConfirm))
	mux.HandleFunc("POST /api/withdraw/resolve", s.api(true, s.withdrawResolve))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint")
	})
	return s.guard(mux)
}

// guard applies the IP allowlist and security headers to everything.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ipAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ipAllowed only looks at the TCP peer address, never at headers.
func (s *Server) ipAllowed(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range s.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// role checks "Authorization: Bearer <key>" in constant time.
func (s *Server) role(r *http.Request) (Role, bool) {
	scheme, key, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || key == "" {
		return "", false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(key)))
	isAdmin := subtle.ConstantTimeCompare(got[:], s.adminHash[:]) == 1
	isAI := subtle.ConstantTimeCompare(got[:], s.aiHash[:]) == 1 && s.aiEnabled
	switch {
	case isAdmin:
		return RoleAdmin, true
	case isAI:
		return RoleAI, true
	}
	return "", false
}

type apiFunc func(w http.ResponseWriter, r *http.Request, role Role) (any, error)

// httpError carries a status code.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func fail(status int, format string, args ...any) error {
	return &httpError{status, fmt.Sprintf(format, args...)}
}

// api wraps an endpoint: authentication, role check, JSON in and out.
func (s *Server) api(adminOnly bool, f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, ok := s.role(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="spikes402-admin"`)
			writeError(w, http.StatusUnauthorized, "missing or wrong admin key")
			return
		}
		if adminOnly && role != RoleAdmin {
			writeError(w, http.StatusForbidden, "only the human admin can do this")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		out, err := f(w, r, role)
		if err != nil {
			var he *httpError
			if errors.As(err, &he) {
				writeError(w, he.status, he.msg)
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "bad JSON: %v", err)
	}
	return nil
}

func (s *Server) config() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// --- read endpoints ---

func (s *Server) whoami(_ http.ResponseWriter, _ *http.Request, role Role) (any, error) {
	return map[string]any{"role": role, "can_apply": s.canApply(role), "withdraw_enabled": s.wd != nil && role == RoleAdmin}, nil
}

func (s *Server) canApply(role Role) bool {
	return role == RoleAdmin || (role == RoleAI && s.config().Admin.AICanApply)
}

type statusOut struct {
	Role           Role                `json:"role"`
	UptimeSeconds  int64               `json:"uptime_seconds"`
	Counts         Counts              `json:"counts"`
	Gate           gate.Status         `json:"gate"`
	Node           *lightning.NodeInfo `json:"node,omitempty"`
	NodeError      string              `json:"node_error,omitempty"`
	Settings       config.Public       `json:"settings"`
	PendingChanges int                 `json:"pending_proposals"`
}

func (s *Server) status(_ http.ResponseWriter, _ *http.Request, role Role) (any, error) {
	info, nodeErr := s.nodeStatus()
	return statusOut{
		Role: role, UptimeSeconds: int64(s.now().Sub(s.started).Seconds()),
		Counts: s.mon.Counts(), Gate: s.gate.Status(), Node: info, NodeError: nodeErr,
		Settings: s.config().Public(), PendingChanges: s.proposals.pending(s.now()),
	}, nil
}

func (s *Server) stats(_ http.ResponseWriter, r *http.Request, _ Role) (any, error) {
	return struct {
		Report
		Lottery any `json:"lottery,omitempty"` // the Bitcoin lottery's counters, if it is on
	}{s.mon.Stats(r.URL.Query().Get("range"), r.URL.Query().Get("kind"), s.now()), s.gate.Status().Lottery}, nil
}

// nodeStatus asks the node at most every 10 seconds, with a short timeout.
func (s *Server) nodeStatus() (*lightning.NodeInfo, string) {
	if s.node == nil {
		return nil, "node status not available for this backend"
	}
	s.nodeMu.Lock()
	defer s.nodeMu.Unlock()
	if s.now().Sub(s.nodeAt) < 10*time.Second {
		return s.nodeInfo, s.nodeError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := s.node.NodeInfo(ctx)
	s.nodeAt = s.now()
	if err != nil {
		s.nodeInfo, s.nodeError = nil, truncate(err.Error(), 200)
	} else {
		s.nodeInfo, s.nodeError = &info, ""
	}
	return s.nodeInfo, s.nodeError
}

func (s *Server) siege(_ http.ResponseWriter, r *http.Request, _ Role) (any, error) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	visits, next := s.mon.Since(since)
	return map[string]any{"visits": visits, "next": next, "counts": s.mon.Counts()}, nil
}

func (s *Server) getSettings(_ http.ResponseWriter, _ *http.Request, _ Role) (any, error) {
	return s.config().Public(), nil
}

// --- changes ---

func (s *Server) putSettings(_ http.ResponseWriter, r *http.Request, role Role) (any, error) {
	if !s.canApply(role) {
		return nil, fail(http.StatusForbidden, `the AI may only propose changes ("admin.ai_can_apply" is off)`)
	}
	var ch config.Changes
	if err := decode(r, &ch); err != nil {
		return nil, err
	}
	if ch.Paused != nil && role != RoleAdmin {
		return nil, fail(http.StatusForbidden, "only the human admin can toggle pause; the AI may propose it")
	}
	return s.apply(ch, role)
}

// apply validates the resulting config, writes the overrides file, then
// publishes to the running gate. A change that fails validation or cannot
// be saved is not published.
func (s *Server) apply(ch config.Changes, by Role) (config.Public, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch.BotPolicies != nil {
		merged := mergeBotPolicies(s.cfg.BotPolicies, *ch.BotPolicies)
		ch.BotPolicies = &merged
	}
	n, err := s.cfg.Apply(ch)
	if err != nil {
		return config.Public{}, err
	}
	if by == RoleAI {
		if why := config.WeakensProtection(s.cfg, n); len(why) > 0 {
			return config.Public{}, fail(http.StatusForbidden, "this would reduce protection (%s); propose it for the human admin to approve", strings.Join(why, "; "))
		}
		if s.baselineErr != nil {
			return config.Public{}, fail(http.StatusForbidden, "confirmed settings could not be read; propose this for the human admin to approve")
		}
		base := s.baseline
		if base == nil {
			base = s.cfg
		}
		if why := config.NeedsConfirmation(base, n); len(why) > 0 {
			return config.Public{}, fail(http.StatusForbidden, "this needs a human to confirm it (%s); propose it for the human admin to approve", strings.Join(why, "; "))
		}
	}
	path := s.cfg.OverridesFile()
	if path == "" && s.configFile != "" {
		path = config.OverridesPath(s.configFile)
	}
	if path == "" {
		return config.Public{}, fail(http.StatusInternalServerError, "no state_dir to save overrides; not applying")
	}
	if err := config.WriteOverrides(path, n); err != nil {
		log.Printf("admin: settings not saved to %s: %v (not applied)", path, err)
		return config.Public{}, fail(http.StatusInternalServerError, "settings were not saved: %v", err)
	}
	if err := s.gate.UpdateSettings(n.GateSettings()); err != nil {
		log.Printf("admin: settings saved to %s but not applied: %v", path, err)
		return config.Public{}, fail(http.StatusInternalServerError, "settings were saved but could not be applied: %v", err)
	}
	s.cfg = n
	if by == RoleAdmin {
		s.rememberConfirmed(n)
	}
	b, _ := json.Marshal(ch)
	log.Printf("admin: settings changed by %s: %s (saved to %s)", by, b, path)
	return n.Public(), nil
}

// mergeBotPolicies keeps named-bot and URL policies that the dashboard
// does not edit. The four class keys in incoming are authoritative
// (omitting one reverts it to the default "pay").
func mergeBotPolicies(current, incoming map[string]gate.Policy) map[string]gate.Policy {
	out := maps.Clone(current)
	if out == nil {
		out = map[string]gate.Policy{}
	}
	for k, v := range incoming {
		out[k] = v
	}
	for _, k := range []string{string(botid.Unknown), string(botid.Impostor), string(botid.Verified), string(botid.Signed)} {
		if _, ok := incoming[k]; !ok {
			delete(out, k)
		}
	}
	return out
}

// proposalOut is a proposal plus what a human should look at before
// approving it, judged against the last settings a person applied.
type proposalOut struct {
	Proposal
	Risks []string `json:"risks,omitempty"`
}

// risks lists why approving ch needs an explicit confirmation.
func (s *Server) risks(ch config.Changes) []string {
	s.mu.Lock()
	cur, base, baseErr := s.cfg, s.baseline, s.baselineErr
	s.mu.Unlock()
	n, err := cur.Apply(ch)
	if err != nil {
		return nil
	}
	if base == nil || baseErr != nil {
		base = cur
	}
	return config.NeedsConfirmation(base, n)
}

func (s *Server) listProposals(_ http.ResponseWriter, _ *http.Request, _ Role) (any, error) {
	list := s.proposals.list(s.now())
	out := make([]proposalOut, len(list))
	for i, p := range list {
		out[i] = proposalOut{Proposal: p}
		if p.Status == "pending" {
			out[i].Risks = s.risks(p.Changes)
		}
	}
	return out, nil
}

func (s *Server) propose(_ http.ResponseWriter, r *http.Request, role Role) (any, error) {
	var in struct {
		Changes config.Changes `json:"changes"`
		Reason  string         `json:"reason"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if _, err := s.config().Apply(in.Changes); err != nil { // dry run
		return nil, err
	}
	p, err := s.proposals.add(in.Changes, truncate(in.Reason, 500), role, s.now())
	if err != nil {
		return nil, fail(http.StatusTooManyRequests, "%v", err)
	}
	log.Printf("admin: change proposed by %s (%s)", role, p.ID)
	return p, nil
}

func (s *Server) approve(_ http.ResponseWriter, r *http.Request, role Role) (any, error) {
	// A proposal that could take the site down is only applied when the
	// request says "confirm=1" (the dashboard asks the human first).
	if r.URL.Query().Get("confirm") != "1" {
		if p, ok := s.proposals.peek(r.PathValue("id")); ok {
			if why := s.risks(p.Changes); len(why) > 0 {
				return nil, fail(http.StatusConflict, "needs explicit confirmation (%s); repeat with ?confirm=1", strings.Join(why, "; "))
			}
		}
	}
	p, err := s.proposals.take(r.PathValue("id"), s.now())
	if err != nil {
		return nil, fail(http.StatusNotFound, "%v", err)
	}
	if _, err := s.apply(p.Changes, role); err != nil {
		s.proposals.finish(p.ID, "failed", err.Error())
		return nil, err
	}
	return s.proposals.finish(p.ID, "applied", ""), nil
}

func (s *Server) reject(_ http.ResponseWriter, r *http.Request, _ Role) (any, error) {
	p, err := s.proposals.take(r.PathValue("id"), s.now())
	if err != nil {
		return nil, fail(http.StatusNotFound, "%v", err)
	}
	return s.proposals.finish(p.ID, "rejected", ""), nil
}
