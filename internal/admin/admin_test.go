package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/config"
	"github.com/Choffolo/spikes402/internal/gate"
	"github.com/Choffolo/spikes402/internal/lightning"
)

var (
	adminKey = strings.Repeat("A", 40)
	aiKey    = strings.Repeat("B", 40)
	wdPass   = "correct horse battery"
)

type env struct {
	srv  *Server
	h    http.Handler
	gate *gate.Gate
	ln   *lightning.Fake
	mon  *Monitor
	now  time.Time
	file string
}

func newEnv(t *testing.T, extra string) *env {
	return newEnvJSON(t, extra, "")
}

func newEnvJSON(t *testing.T, adminExtra, rootExtra string) *env {
	t.Helper()
	file := filepath.Join(t.TempDir(), "c.json")
	js := `{"origin":"http://o","price_sats":10,"protect":["/premium/**"],"pow_difficulty":4,` + rootExtra + `
		"admin":{"key":"` + adminKey + `","ai_key":"` + aiKey + `"` + adminExtra + `},"lightning":{"backend":"fake"}}`
	if err := os.WriteFile(file, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{ln: lightning.NewFake(), now: time.Unix(1_800_000_000, 0), file: file}
	e.mon = NewMonitor(cfg.Admin.VisitorIPs, e.now)
	e.gate = gate.New(gate.Options{
		PriceSats: cfg.PriceSats, Protect: cfg.Protect, Prices: cfg.Prices, Paused: cfg.Paused, PoW: cfg.PoW, ChallengeTTL: cfg.ChallengeTTL(), PassTTL: cfg.PassTTL(),
		SecretKey: []byte(strings.Repeat("s", 32)), Lightning: e.ln, Next: http.NotFoundHandler(),
		ChallengesPerMinute: cfg.ChallengesPerMinute, MaxInvoicesPerMinute: 1000, MaxPendingInvoices: 1000,
		Observer: e.mon.Observe,
	})
	opt := Options{Config: cfg, ConfigFile: file, Gate: e.gate, Monitor: e.mon, Node: e.ln}
	if cfg.Withdraw.Enabled {
		opt.Withdrawer = e.ln
	}
	e.srv = New(opt)
	e.srv.now = func() time.Time { return e.now }
	e.h = e.srv.Handler()
	return e
}

// call makes an API request from localhost.
func (e *env) call(method, path, key string, body any) (*httptest.ResponseRecorder, map[string]any) {
	return e.callFrom("127.0.0.1:5000", method, path, key, body)
}

func (e *env) callFrom(remote, method, path, key string, body any) (*httptest.ResponseRecorder, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = remote
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestDashboardStatic(t *testing.T) {
	e := newEnv(t, "")
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		rec, _ := e.call("GET", p, "", nil)
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") ||
			rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: %d %v", p, rec.Code, rec.Header())
		}
	}
	// One main page (the siege field) with settings behind a link, no inline script.
	rec, _ := e.call("GET", "/", "", nil)
	if body := rec.Body.String(); !strings.Contains(body, `id="field"`) || !strings.Contains(body, `href="#settings"`) ||
		strings.Contains(body, "<script>") {
		t.Fatal("unexpected index.html")
	}
	// Visitor-controlled text (paths, bot names) must never be parsed as HTML.
	if rec, _ := e.call("GET", "/app.js", "", nil); strings.Contains(rec.Body.String(), "innerHTML") {
		t.Fatal("app.js uses innerHTML")
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t, "")
	for _, key := range []string{"", "wrong", adminKey + "x", strings.ToLower(adminKey)} {
		if rec, _ := e.call("GET", "/api/status", key, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("key %q: got %d", key, rec.Code)
		}
	}
	if _, out := e.call("GET", "/api/whoami", adminKey, nil); out["role"] != "admin" {
		t.Fatalf("%v", out)
	}
	if _, out := e.call("GET", "/api/whoami", aiKey, nil); out["role"] != "ai" || out["can_apply"] != false || out["withdraw_enabled"] != false {
		t.Fatalf("%v", out)
	}
	if rec, _ := e.call("GET", "/api/nope", adminKey, nil); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}

func TestIPAllowlist(t *testing.T) {
	e := newEnv(t, `,"listen":"0.0.0.0:8404","allowed_ips":["10.0.0.0/8"]`)
	cases := map[string]int{"127.0.0.1:1": 200, "[::1]:1": 200, "10.1.2.3:1": 200, "192.0.2.1:1": 403, "[2001:db8::1]:1": 403}
	for remote, want := range cases {
		if rec, _ := e.callFrom(remote, "GET", "/api/whoami", adminKey, nil); rec.Code != want {
			t.Errorf("%s: got %d, want %d", remote, rec.Code, want)
		}
	}
	// Even the dashboard page is hidden from others.
	if rec, _ := e.callFrom("192.0.2.1:1", "GET", "/", "", nil); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
}

func TestStatusAndSiege(t *testing.T) {
	e := newEnv(t, "")
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/premium/p%d?email=secret", i), nil)
		req.RemoteAddr = "203.0.113.7:1234"
		e.gate.ServeHTTP(httptest.NewRecorder(), req)
	}
	rec, out := e.call("GET", "/api/status", aiKey, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), adminKey) || strings.Contains(rec.Body.String(), aiKey) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	counts := out["counts"].(map[string]any)
	if counts["total"].(float64) != 3 || out["gate"].(map[string]any)["open_invoices"].(float64) != 3 {
		t.Fatalf("%v", out)
	}
	rec, out = e.call("GET", "/api/siege?since=1", adminKey, nil)
	visits := out["visits"].([]any)
	if len(visits) != 2 || out["next"].(float64) != 3 {
		t.Fatalf("%v", out)
	}
	v := visits[0].(map[string]any)
	if v["outcome"] != "challenged" || v["path"] != "/premium/p1" || v["class"] != "unknown" || !strings.HasPrefix(v["visitor"].(string), "v-") {
		t.Fatalf("%v", v)
	}
	if body := rec.Body.String(); strings.Contains(body, "203.0.113") || strings.Contains(body, "secret") {
		t.Fatalf("private data in %s", body)
	}
}

func TestSettingsRoles(t *testing.T) {
	e := newEnv(t, "")
	if rec, _ := e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 1}); rec.Code != 403 {
		t.Fatalf("AI applied a change: %d", rec.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"price_sats": 0}); rec.Code != 400 {
		t.Fatalf("invalid change: %d", rec.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"secret_key": "x"}); rec.Code != 400 {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	rec, out := e.call("PUT", "/api/settings", adminKey, map[string]any{"price_sats": 25, "bot_policies": map[string]any{"impostor": map[string]any{"action": "pow-only"}}})
	if rec.Code != 200 || out["price_sats"].(float64) != 25 {
		t.Fatalf("%d %v", rec.Code, out)
	}
	if s := e.gate.Settings(); s.PriceSats != 25 || s.Policies["impostor"].Action != gate.ActionPoWOnly {
		t.Fatalf("gate not updated: %+v", s)
	}

	e = newEnv(t, `,"ai_can_apply":true`)
	if rec, _ := e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 15}); rec.Code != 200 || e.gate.Settings().PriceSats != 15 {
		t.Fatalf("AI with ai_can_apply: %d", rec.Code)
	}
}

func TestProposals(t *testing.T) {
	e := newEnv(t, "")
	if rec, _ := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": -1}}); rec.Code != 400 {
		t.Fatalf("invalid proposal: %d", rec.Code)
	}
	rec, p := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 50}, "reason": "lots of impostors"})
	if rec.Code != 200 || p["status"] != "pending" || p["by"] != "ai" {
		t.Fatalf("%d %v", rec.Code, p)
	}
	id := p["id"].(string)
	if e.gate.Settings().PriceSats != 10 {
		t.Fatal("a proposal changed the settings")
	}
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve", aiKey, nil); rec.Code != 403 {
		t.Fatalf("AI approved its own proposal: %d", rec.Code)
	}
	// 10 -> 50 sats is a big jump: the human must confirm it explicitly.
	if rec, out := e.call("POST", "/api/proposals/"+id+"/approve", adminKey, nil); rec.Code != 409 {
		t.Fatalf("unconfirmed risky approve: %d %v", rec.Code, out)
	}
	if e.gate.Settings().PriceSats != 10 {
		t.Fatal("an unconfirmed approve changed the settings")
	}
	if rec, out := e.call("POST", "/api/proposals/"+id+"/approve?confirm=1", adminKey, nil); rec.Code != 200 || out["status"] != "applied" {
		t.Fatalf("%d %v", rec.Code, out)
	}
	if e.gate.Settings().PriceSats != 50 {
		t.Fatal("approved proposal not applied")
	}
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve", adminKey, nil); rec.Code != 404 {
		t.Fatalf("approved twice: %d", rec.Code)
	}
	_, p = e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 1}})
	if rec, out := e.call("POST", "/api/proposals/"+p["id"].(string)+"/reject", adminKey, nil); rec.Code != 200 || out["status"] != "rejected" {
		t.Fatalf("%d %v", rec.Code, out)
	}
	// Proposals expire and are bounded.
	_, p = e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 2}})
	e.now = e.now.Add(25 * time.Hour)
	if rec, _ := e.call("POST", "/api/proposals/"+p["id"].(string)+"/approve", adminKey, nil); rec.Code != 404 {
		t.Fatalf("expired proposal approved: %d", rec.Code)
	}
	for i := 0; i < maxProposals; i++ {
		e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 2}})
	}
	if rec, _ := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 2}}); rec.Code != 429 {
		t.Fatalf("unbounded proposals: %d", rec.Code)
	}
	if n := len(e.srv.proposals.items); n > maxProposals {
		t.Fatalf("%d proposals stored", n)
	}
}

const wdConfig = `},"withdraw":{"enabled":true,"destination":"me@wallet.example","password":"correct horse battery"`

// newWithdrawEnv enables withdrawals; extra closes the admin object.
func newWithdrawEnv(t *testing.T) *env {
	e := newEnv(t, "")
	file := filepath.Join(t.TempDir(), "c.json")
	js := `{"origin":"http://o","price_sats":10,"protect":["/premium/**"],
		"admin":{"key":"` + adminKey + `","ai_key":"` + aiKey + `"` + wdConfig + `},"lightning":{"backend":"fake"}}`
	os.WriteFile(file, []byte(js), 0o600)
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	e.ln = lightning.NewFake()
	e.srv = New(Options{Config: cfg, Gate: e.gate, Monitor: e.mon, Node: e.ln, Withdrawer: e.ln})
	e.srv.now = func() time.Time { return e.now }
	e.h = e.srv.Handler()
	inv, _ := e.ln.CreateInvoice(context.Background(), 1000, "", time.Hour)
	e.ln.Pay(inv.PaymentRequest) // balance: 1000 sats
	return e
}

func TestWithdrawDisabled(t *testing.T) {
	e := newEnv(t, "")
	if rec, _ := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 1, "password": "x"}); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}

func TestWithdrawFlow(t *testing.T) {
	e := newWithdrawEnv(t)
	prep := func(amount int64, pw string) (*httptest.ResponseRecorder, map[string]any) {
		return e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": amount, "password": pw})
	}
	confirm := func(id string, amount int64, pw string) (*httptest.ResponseRecorder, map[string]any) {
		return e.call("POST", "/api/withdraw/confirm", adminKey, map[string]any{"confirm_id": id, "amount_sat": amount, "password": pw})
	}
	// Never for the AI, whatever it sends.
	for _, p := range []string{"/api/withdraw/prepare", "/api/withdraw/confirm", "/api/withdraw"} {
		if rec, _ := e.call("POST", p, aiKey, map[string]any{"amount_sat": 1, "password": wdPass}); rec.Code != 403 && rec.Code != 404 {
			t.Fatalf("%s: AI got %d", p, rec.Code)
		}
	}
	if rec, _ := e.call("GET", "/api/withdraw", aiKey, nil); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	// The destination cannot be chosen by the caller.
	if rec, _ := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 1, "password": wdPass, "destination": "thief@evil.example"}); rec.Code != 400 {
		t.Fatalf("destination accepted: %d", rec.Code)
	}
	if rec, _ := prep(5000, wdPass); rec.Code != 400 {
		t.Fatalf("more than the balance: %d", rec.Code)
	}
	if rec, _ := prep(100, "wrong"); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	rec, p := prep(400, wdPass)
	if rec.Code != 200 || p["destination"] != "me@wallet.example" {
		t.Fatalf("%d %v", rec.Code, p)
	}
	id := p["confirm_id"].(string)
	if rec, _ := confirm(id, 401, wdPass); rec.Code != 409 {
		t.Fatalf("amount mismatch: %d", rec.Code)
	}
	if rec, _ := confirm(id, 400, wdPass); rec.Code != 409 {
		t.Fatalf("id reused after a failed confirm: %d", rec.Code)
	}
	_, p = prep(400, wdPass)
	if rec, _ := confirm(p["confirm_id"].(string), 400, "wrong"); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	_, p = prep(400, wdPass)
	e.now = e.now.Add(3 * time.Minute)
	if rec, _ := confirm(p["confirm_id"].(string), 400, wdPass); rec.Code != 409 {
		t.Fatalf("expired confirmation: %d", rec.Code)
	}
	if len(e.ln.Withdrawals()) != 0 {
		t.Fatal("money left before a valid confirmation")
	}
	_, p = prep(400, wdPass)
	rec, out := confirm(p["confirm_id"].(string), 400, wdPass)
	if rec.Code != 200 || out["ok"] != true {
		t.Fatalf("%d %v", rec.Code, out)
	}
	if w := e.ln.Withdrawals(); len(w) != 1 || w[0].Destination != "me@wallet.example" || w[0].AmountSat != 400 {
		t.Fatalf("%+v", w)
	}
	if rec, _ := confirm(p["confirm_id"].(string), 400, wdPass); rec.Code != 409 {
		t.Fatalf("confirmed twice: %d", rec.Code)
	}
	_, info := e.call("GET", "/api/withdraw", adminKey, nil)
	if h := info["history"].([]any); len(h) != 1 {
		t.Fatalf("%v", info)
	}
}

func TestWithdrawLockout(t *testing.T) {
	e := newWithdrawEnv(t)
	for i := 0; i < withdrawMaxFailures; i++ {
		e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 1, "password": "guess"})
	}
	if rec, _ := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 1, "password": wdPass}); rec.Code != 429 {
		t.Fatalf("not locked: %d", rec.Code)
	}
	e.now = e.now.Add(withdrawLockout + time.Second)
	if rec, _ := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 1, "password": wdPass}); rec.Code != 200 {
		t.Fatalf("still locked: %d", rec.Code)
	}
}

func TestMonitorRingAndPrivacy(t *testing.T) {
	ev := gate.Event{Time: time.Now(), Client: "203.0.113.7", IP: net.ParseIP("203.0.113.7"), Resource: "GET /a?x=1",
		Class: botid.Class{Kind: botid.Impostor, Name: "GPTBot"}, Outcome: gate.OutcomeChallenged}
	for mode, want := range map[string]string{"truncate": "203.0.113.0/24", "full": "203.0.113.7"} {
		m := NewMonitor(mode, time.Now())
		m.Observe(ev)
		if v, _ := m.Since(0); v[0].Visitor != want || v[0].Path != "/a" {
			t.Errorf("%s: %+v", mode, v[0])
		}
	}
	m := NewMonitor("truncate", time.Now())
	m.Observe(gate.Event{IP: net.ParseIP("2001:db8:1:2::5"), Client: "2001:db8:1:2::/64"})
	if v, _ := m.Since(0); v[0].Visitor != "2001:db8:1::/48" {
		t.Errorf("%+v", v[0])
	}

	m = NewMonitor("hash", time.Now())
	m2 := NewMonitor("hash", time.Now())
	m.Observe(ev)
	m2.Observe(ev)
	a, _ := m.Since(0)
	b, _ := m2.Since(0)
	if a[0].Visitor == b[0].Visitor || strings.Contains(a[0].Visitor, "203") {
		t.Fatal("hash must be salted per process and hide the address")
	}
	for i := 0; i < ringSize*3; i++ {
		ev.Class.Name = fmt.Sprintf("bot%d", i) // also floods the bot counter
		ev.Resource = "GET /" + strings.Repeat("x", 500) + "\n"
		m.Observe(ev)
	}
	got, next := m.Since(0)
	if len(got) != maxPerPoll || next != uint64(ringSize*3+1) || got[len(got)-1].Seq != next {
		t.Fatalf("len %d next %d", len(got), next)
	}
	if got[0].Path != "/"+strings.Repeat("x", maxPathLen-2)+"…" {
		t.Fatalf("path %q", got[0].Path)
	}
	if c := m.Counts(); len(c.ByBot) > maxBotKeys+1 || c.ByBot["other"] == 0 || c.Total != uint64(ringSize*3+1) {
		t.Fatalf("bots %d", len(c.ByBot))
	}
	if v, n := m.Since(next); len(v) != 0 || n != next {
		t.Fatal("since=next must be empty")
	}
	if v, _ := m.Since(next - 5); len(v) != 5 {
		t.Fatalf("got %d", len(v))
	}
	if v, _ := m.Since(1 << 40); len(v) != 0 { // client from before a restart
		t.Fatal("future seq")
	}
}

func TestSignedBotName(t *testing.T) {
	if got := botName(botid.Class{Kind: botid.Signed, Name: "https://bot.example/.well-known/http-message-signatures-directory"}); got != "bot.example" {
		t.Fatal(got)
	}
}

func TestWithdrawReservesFee(t *testing.T) {
	e := newWithdrawEnv(t) // balance 1000, Lightning destination
	max := lightning.MaxWithdrawSat("me@wallet.example", 1000)
	rec, out := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": max + 1, "password": wdPass})
	if rec.Code != 400 || !strings.Contains(fmt.Sprint(out), "routing fee") || !strings.Contains(fmt.Sprint(out), fmt.Sprintf("at most %d sat", max)) {
		t.Fatalf("%d %v", rec.Code, out)
	}
	rec, out = e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": max, "password": wdPass})
	if rec.Code != 200 || out["fee_sat"] != float64(lightning.EstimatedFeeSat("me@wallet.example", max)) {
		t.Fatalf("%d %v", rec.Code, out)
	}
}

// unsureWithdrawer never knows whether the money left.
type unsureWithdrawer struct{ calls int }

func (u *unsureWithdrawer) Withdraw(context.Context, string, int64) (string, error) {
	u.calls++
	return "", fmt.Errorf("%w: phoenixd: timeout", lightning.ErrUncertain)
}

func TestWithdrawUnknownOutcome(t *testing.T) {
	e := newWithdrawEnv(t)
	u := &unsureWithdrawer{}
	e.srv.withdrawer = u
	send := func() (*httptest.ResponseRecorder, map[string]any) {
		rec, p := e.call("POST", "/api/withdraw/prepare", adminKey, map[string]any{"amount_sat": 100, "password": wdPass})
		if rec.Code != 200 {
			return rec, p
		}
		return e.call("POST", "/api/withdraw/confirm", adminKey, map[string]any{"confirm_id": p["confirm_id"], "amount_sat": 100, "password": wdPass})
	}
	if rec, _ := send(); rec.Code != 504 || u.calls != 1 {
		t.Fatalf("%d, %d calls", rec.Code, u.calls)
	}
	_, info := e.call("GET", "/api/withdraw", adminKey, nil)
	h := info["history"].([]any)[0].(map[string]any)
	if h["unknown"] != true || h["ok"] != false || !strings.HasPrefix(h["result"].(string), "unknown — check the node") || info["unresolved"] == nil {
		t.Fatalf("%v", info)
	}
	// Blocked until resolved: no second payment can start.
	if rec, _ := send(); rec.Code != 409 || u.calls != 1 {
		t.Fatalf("%d, %d calls", rec.Code, u.calls)
	}
	resolve := func(body map[string]any) int {
		rec, _ := e.call("POST", "/api/withdraw/resolve", aiKey, body)
		if rec.Code != 403 {
			t.Fatalf("AI resolved: %d", rec.Code)
		}
		rec, _ = e.call("POST", "/api/withdraw/resolve", adminKey, body)
		return rec.Code
	}
	if c := resolve(map[string]any{"sent": true, "password": "wrong"}); c != 403 {
		t.Fatal(c)
	}
	if c := resolve(map[string]any{"password": wdPass}); c != 400 {
		t.Fatal(c)
	}
	if c := resolve(map[string]any{"sent": true, "password": wdPass}); c != 200 {
		t.Fatal(c)
	}
	_, info = e.call("GET", "/api/withdraw", adminKey, nil)
	h = info["history"].([]any)[0].(map[string]any)
	if h["ok"] != true || h["unknown"] != nil || info["unresolved"] != nil {
		t.Fatalf("%v", info)
	}
	if c := resolve(map[string]any{"sent": false, "password": wdPass}); c != 409 {
		t.Fatalf("nothing to resolve: %d", c)
	}
	// Unblocked: the next attempt reaches the node again.
	if rec, _ := send(); rec.Code != 504 || u.calls != 2 {
		t.Fatalf("%d, %d calls", rec.Code, u.calls)
	}
}

func TestPathPriceSettings(t *testing.T) {
	e := newEnv(t, "")
	rules := []any{
		map[string]any{"pattern": "/premium/special/**", "price_sats": 1},
		map[string]any{"pattern": "/premium/**", "price_sats": 20},
	}
	if rec, _ := e.call("PUT", "/api/settings", aiKey, map[string]any{"prices": rules}); rec.Code != 403 {
		t.Fatalf("AI applied prices: %d", rec.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"prices": []any{map[string]any{"pattern": "premium", "price_sats": 2}}}); rec.Code != 400 {
		t.Fatalf("bad pattern: %d", rec.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"prices": []any{map[string]any{"pattern": "/premium/**", "price_sats": 0}}}); rec.Code != 400 {
		t.Fatalf("zero price: %d", rec.Code)
	}
	rec, out := e.call("PUT", "/api/settings", adminKey, map[string]any{"prices": rules})
	if rec.Code != 200 {
		t.Fatalf("admin apply: %d %v", rec.Code, out)
	}
	got, _ := out["prices"].([]any)
	if len(got) != 2 {
		t.Fatalf("public prices: %v", out["prices"])
	}
	if s := e.gate.Settings(); len(s.Prices) != 2 || s.Prices[0].PriceSats != 1 || s.Prices[1].Pattern != "/premium/**" {
		t.Fatalf("gate: %+v", s.Prices)
	}
	req := httptest.NewRequest(http.MethodGet, "/premium/a", nil)
	wr := httptest.NewRecorder()
	e.gate.ServeHTTP(wr, req)
	if wr.Code != http.StatusPaymentRequired {
		t.Fatalf("challenge: %d", wr.Code)
	}
	var body struct {
		PriceSats int64 `json:"price_sats"`
	}
	if err := json.NewDecoder(wr.Body).Decode(&body); err != nil || body.PriceSats != 20 {
		t.Fatalf("live price %d (%v), want 20", body.PriceSats, err)
	}

	rec, out = e.call("PUT", "/api/settings", adminKey, map[string]any{"prices": []any{}})
	if rec.Code != 200 || len(e.gate.Settings().Prices) != 0 {
		t.Fatalf("clear: %d %+v", rec.Code, e.gate.Settings().Prices)
	}

	e = newEnv(t, `,"ai_can_apply":true`)
	strict := []any{
		map[string]any{"pattern": "/premium/special/**", "price_sats": 20},
		map[string]any{"pattern": "/premium/**", "price_sats": 15},
	}
	if rec, _ := e.call("PUT", "/api/settings", aiKey, map[string]any{"prices": strict}); rec.Code != 200 || len(e.gate.Settings().Prices) != 2 {
		t.Fatalf("AI with ai_can_apply: %d", rec.Code)
	}

	e = newEnv(t, "")
	rec, p := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"prices": rules}, "reason": "section prices"})
	if rec.Code != 200 || len(e.gate.Settings().Prices) != 0 {
		t.Fatalf("proposal applied early: %d %+v", rec.Code, e.gate.Settings().Prices)
	}
	id := p["id"].(string)
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve", aiKey, nil); rec.Code != 403 {
		t.Fatalf("AI approved prices: %d", rec.Code)
	}
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve", adminKey, nil); rec.Code != 200 {
		t.Fatalf("approve: %d", rec.Code)
	}
	if len(e.gate.Settings().Prices) != 2 {
		t.Fatalf("approved proposal not applied: %+v", e.gate.Settings().Prices)
	}
}

func TestWebmasterSettings(t *testing.T) {
	e := newEnvJSON(t, "", `"bot_policies":{"GPTBot":{"action":"block"},"impostor":{"action":"pow-only"}},`)
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"protect": []string{"premium"}}); rec.Code != 400 {
		t.Fatalf("bad protect: %d", rec.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"protect": []string{}}); rec.Code != 400 {
		t.Fatalf("empty protect: %d", rec.Code)
	}
	rec, out := e.call("PUT", "/api/settings", adminKey, map[string]any{"protect": []string{"/articles/**", "/premium/**"}})
	if rec.Code != 200 {
		t.Fatalf("protect: %d %v", rec.Code, out)
	}
	if got, _ := out["protect"].([]any); len(got) != 2 {
		t.Fatalf("public protect: %v", out["protect"])
	}
	if s := e.gate.Settings(); len(s.Protect) != 2 || s.Protect[0] != "/articles/**" {
		t.Fatalf("gate protect: %+v", s.Protect)
	}
	req := httptest.NewRequest(http.MethodGet, "/articles/a", nil)
	wr := httptest.NewRecorder()
	e.gate.ServeHTTP(wr, req)
	if wr.Code != http.StatusPaymentRequired {
		t.Fatalf("new path: %d", wr.Code)
	}

	// Category dropdowns must not wipe named-bot rules from the config file.
	rec, out = e.call("PUT", "/api/settings", adminKey, map[string]any{"bot_policies": map[string]any{"unknown": map[string]any{"action": "block"}}})
	if rec.Code != 200 {
		t.Fatalf("policies: %d %v", rec.Code, out)
	}
	pol, _ := out["bot_policies"].(map[string]any)
	if pol["unknown"].(map[string]any)["action"] != "block" || pol["GPTBot"].(map[string]any)["action"] != "block" {
		t.Fatalf("merged policies: %v", pol)
	}
	if _, ok := pol["impostor"]; ok {
		t.Fatalf("omitted class should revert to default: %v", pol)
	}
}

func TestPausePermissions(t *testing.T) {
	e := newEnv(t, `,"ai_can_apply":true`)
	if rec, out := e.call("PUT", "/api/settings", aiKey, map[string]any{"paused": true}); rec.Code != 403 {
		t.Fatalf("AI applied pause: %d %v", rec.Code, out)
	}
	if rec, _ := e.call("PUT", "/api/settings", aiKey, map[string]any{"paused": true, "price_sats": 2}); rec.Code != 403 || e.gate.Settings().PriceSats != 10 || e.gate.Settings().Paused {
		t.Fatalf("AI pause+price should be rejected as a whole")
	}
	rec, p := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"paused": true}, "reason": "maintenance"})
	if rec.Code != 200 || e.gate.Settings().Paused {
		t.Fatalf("proposal: %d paused=%v", rec.Code, e.gate.Settings().Paused)
	}
	if rec, _ := e.call("POST", "/api/proposals/"+p["id"].(string)+"/approve", aiKey, nil); rec.Code != 403 {
		t.Fatalf("AI approved pause: %d", rec.Code)
	}
	if rec, _ := e.call("POST", "/api/proposals/"+p["id"].(string)+"/approve", adminKey, nil); rec.Code != 200 {
		t.Fatalf("admin approve: %d", rec.Code)
	}
	if !e.gate.Settings().Paused {
		t.Fatal("approved pause not applied")
	}

	e = newEnv(t, "")
	if rec, out := e.call("PUT", "/api/settings", adminKey, map[string]any{"paused": true}); rec.Code != 200 || !e.gate.Settings().Paused || out["paused"] != true {
		t.Fatalf("admin pause: %d %v", rec.Code, out)
	}
	req := httptest.NewRequest(http.MethodGet, "/premium/a", nil)
	wr := httptest.NewRecorder()
	e.gate.ServeHTTP(wr, req)
	if wr.Code != http.StatusNotFound {
		t.Fatalf("paused should be free (origin 404): %d", wr.Code)
	}
	if rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{"paused": false}); rec.Code != 200 || e.gate.Settings().Paused {
		t.Fatal("unpause")
	}
}

func TestSettingsPersistInOverrides(t *testing.T) {
	e := newEnv(t, "")
	before, err := os.ReadFile(e.file)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := e.call("PUT", "/api/settings", adminKey, map[string]any{
		"price_sats":   42,
		"protect":      []string{"/only/**"},
		"paused":       true,
		"bot_policies": map[string]any{"unknown": map[string]any{"action": "free"}},
	})
	if rec.Code != 200 {
		t.Fatalf("apply: %d", rec.Code)
	}
	after, _ := os.ReadFile(e.file)
	if !bytes.Equal(before, after) {
		t.Fatal("config.json was rewritten")
	}
	over := e.srv.cfg.OverridesFile()
	st, err := os.Stat(over)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("overrides mode %o", st.Mode().Perm())
	}
	loaded, err := config.Load(e.file)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PriceSats != 42 || !loaded.Paused || len(loaded.Protect) != 1 || loaded.Protect[0] != "/only/**" || loaded.BotPolicies["unknown"].Action != gate.ActionFree {
		t.Fatalf("reload: %+v policies=%v", loaded, loaded.BotPolicies)
	}
}

func TestSettingsNotPublishedIfSaveFails(t *testing.T) {
	e := newEnv(t, "")
	// Point overrides at a path that cannot be created, so the write fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.StateDir = blocker
	rec, out := e.call("PUT", "/api/settings", adminKey, map[string]any{"price_sats": 99})
	if rec.Code != 500 {
		t.Fatalf("want 500 on save failure, got %d %v", rec.Code, out)
	}
	if e.gate.Settings().PriceSats != 10 {
		t.Fatalf("change was published although it was not saved: price=%d", e.gate.Settings().PriceSats)
	}
}

func TestAICannotWeakenProtection(t *testing.T) {
	e := newEnv(t, `,"ai_can_apply":true`)
	// Lowering the price is weaker: must stay a proposal.
	rec, out := e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 1})
	if rec.Code != 403 || e.gate.Settings().PriceSats != 10 {
		t.Fatalf("AI lowered the price: %d %v gate=%d", rec.Code, out, e.gate.Settings().PriceSats)
	}
	if rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"protect": []string{"/elsewhere/**"}}); rec.Code != 403 {
		t.Fatalf("AI rewrote protect: %d %v", rec.Code, out)
	}
	if rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"bot_policies": map[string]any{"unknown": map[string]any{"action": "free"}}}); rec.Code != 403 {
		t.Fatalf("AI set free: %d %v", rec.Code, out)
	}
	if rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"pow_seconds_per_sat": 1}); rec.Code != 403 {
		t.Fatalf("AI lowered PoW: %d %v", rec.Code, out)
	}
	// Raising the price is stricter: allowed.
	if rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 15}); rec.Code != 200 || e.gate.Settings().PriceSats != 15 {
		t.Fatalf("AI should apply a stricter price: %d %v", rec.Code, out)
	}
	// The human admin can still weaken after a clear choice (API has no confirm).
	if rec, _ = e.call("PUT", "/api/settings", adminKey, map[string]any{"price_sats": 5}); rec.Code != 200 || e.gate.Settings().PriceSats != 5 {
		t.Fatalf("admin should still be able to lower the price: %d", rec.Code)
	}
}

// The takedown from the advisory: each part looks "stricter" on its own.
// The AI must not apply it, even piece by piece, and the dashboard flags it.
func TestAICannotApplyTakedown(t *testing.T) {
	e := newEnv(t, `,"ai_can_apply":true`)
	for name, ch := range map[string]map[string]any{
		"whole site":  {"protect": []string{"/premium/**", "/**"}},
		"max price":   {"price_sats": 1000000},
		"crawlers":    {"bot_policies": map[string]any{"verified": map[string]any{"action": "block"}}},
		"crawler pay": {"bot_policies": map[string]any{"verified-signed": map[string]any{"action": "pay", "price_multiplier": 5}}},
		"one per min": {"challenges_per_minute": 1},
		"all at once": {
			"price_sats": 1000000, "protect": []string{"/premium/**", "/**"}, "challenges_per_minute": 1,
			"bot_policies": map[string]any{"verified": map[string]any{"action": "block"}},
		},
	} {
		rec, out := e.call("PUT", "/api/settings", aiKey, ch)
		if rec.Code != 403 {
			t.Fatalf("%s: AI applied it: %d %v", name, rec.Code, out)
		}
	}
	if s := e.gate.Settings(); s.PriceSats != 10 || len(s.Protect) != 1 {
		t.Fatalf("settings changed: %+v", s)
	}
	// It can still propose it; the dashboard marks it and the human must confirm.
	rec, p := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"protect": []string{"/premium/**", "/**"}}})
	if rec.Code != 200 {
		t.Fatalf("propose: %d %v", rec.Code, p)
	}
	req := httptest.NewRequest("GET", "/api/proposals", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("Authorization", "Bearer "+adminKey)
	lrec := httptest.NewRecorder()
	e.h.ServeHTTP(lrec, req)
	var list []map[string]any
	if err := json.Unmarshal(lrec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["risks"] == nil {
		t.Fatalf("proposal not flagged: %v", list)
	}
	id := p["id"].(string)
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve", adminKey, nil); rec.Code != 409 {
		t.Fatalf("approved without confirmation: %d", rec.Code)
	}
	if rec, _ := e.call("POST", "/api/proposals/"+id+"/approve?confirm=1", adminKey, nil); rec.Code != 200 {
		t.Fatalf("confirmed approve: %d", rec.Code)
	}
	// Small, ordinary tightening is still fine for the AI.
	if rec, out := e.call("PUT", "/api/settings", aiKey, map[string]any{"bot_policies": map[string]any{"unknown": map[string]any{"action": "block"}}}); rec.Code != 200 {
		t.Fatalf("AI could not tighten unknown clients: %d %v", rec.Code, out)
	}
}

// Issue #55: many small AI applies, each under the per-step threshold,
// must not reach the confirmation ceiling. Drift is measured from the
// last settings a person applied, including after a restart.
func TestAICannotRatchetPastConfirmation(t *testing.T) {
	e := newEnv(t, `,"ai_can_apply":true`)

	// 10 -> 20 is a single allowed doubling; 40 would be 4x the baseline.
	rec, out := e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 20})
	if rec.Code != 200 || e.gate.Settings().PriceSats != 20 {
		t.Fatalf("first doubling: %d %v", rec.Code, out)
	}
	for _, p := range []int{40, 80, 160, 320, 640, 1000} {
		rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": p})
		if rec.Code != 403 || e.gate.Settings().PriceSats != 20 {
			t.Fatalf("price ratchet to %d: %d %v gate=%d", p, rec.Code, out, e.gate.Settings().PriceSats)
		}
	}

	// A proposal that would complete the ratchet still needs confirm=1.
	rec, p := e.call("POST", "/api/proposals", aiKey, map[string]any{"changes": map[string]any{"price_sats": 40}})
	if rec.Code != 200 {
		t.Fatalf("propose 40: %d %v", rec.Code, p)
	}
	lrec, _ := e.call("GET", "/api/proposals", adminKey, nil)
	var list []map[string]any
	if err := json.Unmarshal(lrec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["risks"] == nil {
		t.Fatalf("proposal for 40 not flagged against baseline: %v", list)
	}
	id := p["id"].(string)
	if rec, out = e.call("POST", "/api/proposals/"+id+"/approve", adminKey, nil); rec.Code != 409 || e.gate.Settings().PriceSats != 20 {
		t.Fatalf("approve without confirm: %d %v gate=%d", rec.Code, out, e.gate.Settings().PriceSats)
	}
	if rec, _ = e.call("POST", "/api/proposals/"+id+"/reject", adminKey, nil); rec.Code != 200 {
		t.Fatalf("reject: %d", rec.Code)
	}

	// 30 -> 15 is an allowed half-cut; 8 is already more than half off the baseline.
	rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"challenges_per_minute": 15})
	if rec.Code != 200 || e.gate.Settings().ChallengesPerMinute != 15 {
		t.Fatalf("first half-cut: %d %v", rec.Code, out)
	}
	for _, r := range []int{8, 4, 2, 1} {
		rec, out = e.call("PUT", "/api/settings", aiKey, map[string]any{"challenges_per_minute": r})
		if rec.Code != 403 || e.gate.Settings().ChallengesPerMinute != 15 {
			t.Fatalf("challenge ratchet to %d: %d %v gate=%d", r, rec.Code, out, e.gate.Settings().ChallengesPerMinute)
		}
	}

	// A restart must not forget the human baseline (still 10 sats / 30 per minute).
	e2 := reloadEnv(t, e)
	rec, out = e2.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 40})
	if rec.Code != 403 || e2.gate.Settings().PriceSats != 20 {
		t.Fatalf("after restart, price 40: %d %v gate=%d", rec.Code, out, e2.gate.Settings().PriceSats)
	}
	rec, out = e2.call("PUT", "/api/settings", aiKey, map[string]any{"challenges_per_minute": 8})
	if rec.Code != 403 || e2.gate.Settings().ChallengesPerMinute != 15 {
		t.Fatalf("after restart, cpm 8: %d %v gate=%d", rec.Code, out, e2.gate.Settings().ChallengesPerMinute)
	}

	// Once a person applies new settings, those become the baseline.
	rec, out = e2.call("PUT", "/api/settings", adminKey, map[string]any{"price_sats": 40, "challenges_per_minute": 15})
	if rec.Code != 200 {
		t.Fatalf("human apply: %d %v", rec.Code, out)
	}
	rec, out = e2.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 80})
	if rec.Code != 200 || e2.gate.Settings().PriceSats != 80 {
		t.Fatalf("AI doubling from new baseline: %d %v", rec.Code, out)
	}
	rec, out = e2.call("PUT", "/api/settings", aiKey, map[string]any{"price_sats": 160})
	if rec.Code != 403 || e2.gate.Settings().PriceSats != 80 {
		t.Fatalf("AI 4x new baseline: %d %v gate=%d", rec.Code, out, e2.gate.Settings().PriceSats)
	}
}

// reloadEnv starts a new admin server from e's config and overrides,
// as if the process had restarted.
func reloadEnv(t *testing.T, e *env) *env {
	t.Helper()
	cfg, err := config.Load(e.file)
	if err != nil {
		t.Fatal(err)
	}
	n := &env{ln: lightning.NewFake(), now: e.now, file: e.file}
	n.mon = NewMonitor(cfg.Admin.VisitorIPs, n.now)
	n.gate = gate.New(gate.Options{
		PriceSats: cfg.PriceSats, Protect: cfg.Protect, Prices: cfg.Prices, Paused: cfg.Paused, PoW: cfg.PoW, ChallengeTTL: cfg.ChallengeTTL(), PassTTL: cfg.PassTTL(),
		SecretKey: []byte(strings.Repeat("s", 32)), Lightning: n.ln, Next: http.NotFoundHandler(),
		ChallengesPerMinute: cfg.ChallengesPerMinute, MaxInvoicesPerMinute: 1000, MaxPendingInvoices: 1000,
		Observer: n.mon.Observe,
	})
	n.srv = New(Options{Config: cfg, ConfigFile: e.file, Gate: n.gate, Monitor: n.mon, Node: n.ln})
	n.srv.now = func() time.Time { return n.now }
	n.h = n.srv.Handler()
	return n
}
