package admin

// Statistics for the dashboard's Stats page: what visitors do, page by page
// and client by client, hour by hour. Everything is aggregated as events
// arrive (no request log is kept), bounded in memory, and saved to a file
// so it survives restarts. Visitors appear as the Monitor anonymises them
// ("admin.visitor_ips").

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/gate"
)

// Bounds and windows.
const (
	statsKeep    = 30 * 24 * time.Hour // hourly series and idle clients are kept this long
	maxPages     = 2000                // distinct paths tracked; the rest are not
	maxClients   = 5000                // distinct clients; the least recently seen go first
	maxTokens    = 50_000              // open 402 offers remembered to time how long unlocking takes
	maxSessions  = 50_000              // sessions remembered to estimate time on page
	maxSeen      = 1000                // distinct visitors remembered per page
	sessionGap   = 30 * time.Minute    // a longer gap between two pages ends a visit
	tokenWindow  = time.Hour           // an offer unlocked later than this is not timed
	maxUserAgent = 160
	reportPages  = 50
	reportRows   = 200
)

// Kinds of client, from the strongest evidence seen.
const (
	KindVerified = "verified-bot" // a known crawler whose address or signature checks out
	KindImpostor = "impostor"     // claims a known crawler, the check says no
	KindBot      = "bot"          // says it is a bot or a script (User-Agent), or sends none
	KindHuman    = "human"        // a browser that behaves like one: language, HTML, cookies
	KindUnknown  = "unknown"
)

var kindRank = map[string]int{KindUnknown: 0, KindHuman: 1, KindBot: 2, KindImpostor: 3, KindVerified: 4}

// Bucket is one hour of activity.
type Bucket struct {
	Hour       int64   `json:"hour"` // unix seconds at the start of the hour
	Requests   uint64  `json:"requests"`
	PageViews  uint64  `json:"page_views"`
	HumanViews uint64  `json:"human_views"`
	BotViews   uint64  `json:"bot_views"`
	Challenges uint64  `json:"challenges"`
	Paid       uint64  `json:"paid"`
	PoW        uint64  `json:"pow"`
	Free       uint64  `json:"free"`
	Repelled   uint64  `json:"repelled"`
	Sats       int64   `json:"sats"`
	SolveMs    float64 `json:"solve_ms"`
	SolveN     uint64  `json:"solve_n"`
	LatencyMs  float64 `json:"latency_ms"`
	LatencyN   uint64  `json:"latency_n"`
	DwellS     float64 `json:"dwell_s"`
	DwellN     uint64  `json:"dwell_n"`
}

func (b *Bucket) add(o *Bucket) {
	b.Requests += o.Requests
	b.PageViews += o.PageViews
	b.HumanViews += o.HumanViews
	b.BotViews += o.BotViews
	b.Challenges += o.Challenges
	b.Paid += o.Paid
	b.PoW += o.PoW
	b.Free += o.Free
	b.Repelled += o.Repelled
	b.Sats += o.Sats
	b.SolveMs += o.SolveMs
	b.SolveN += o.SolveN
	b.LatencyMs += o.LatencyMs
	b.LatencyN += o.LatencyN
	b.DwellS += o.DwellS
	b.DwellN += o.DwellN
}

// PageStat is one path (no query string).
type PageStat struct {
	Path       string    `json:"path"`
	Views      uint64    `json:"views"` // HTML pages the origin delivered
	HumanViews uint64    `json:"human_views"`
	Challenges uint64    `json:"challenges"` // 402 answers
	Paid       uint64    `json:"paid"`
	PoW        uint64    `json:"pow"`
	Free       uint64    `json:"free"`
	Repelled   uint64    `json:"repelled"`
	Sats       int64     `json:"sats"`
	Visitors   uint64    `json:"visitors"` // distinct visitors (approximate after a restart)
	SolveMs    float64   `json:"solve_ms"`
	SolveN     uint64    `json:"solve_n"`
	DwellS     float64   `json:"dwell_s"`
	DwellN     uint64    `json:"dwell_n"`
	LatencyMs  float64   `json:"latency_ms"`
	LatencyN   uint64    `json:"latency_n"`
	LastSeen   time.Time `json:"last_seen"`
	seen       map[string]struct{}
}

// ClientStat is one client: an anonymised visitor with one User-Agent.
type ClientStat struct {
	Visitor    string    `json:"visitor"` // as admin.visitor_ips shows it: keyed hash, network or address
	Kind       string    `json:"kind"`
	Class      string    `json:"class"`         // the gate's classification: verified-signed, verified, impostor, unknown
	Bot        string    `json:"bot,omitempty"` // a known crawler's name, or a signed bot's key host
	Agent      string    `json:"agent"`         // short form of the User-Agent: "Chrome · Windows", "curl", "GPTBot"
	UserAgent  string    `json:"user_agent"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Requests   uint64    `json:"requests"`
	Pages      uint64    `json:"pages"`
	Challenges uint64    `json:"challenges"`
	Paid       uint64    `json:"paid"`
	PoW        uint64    `json:"pow"`
	Repelled   uint64    `json:"repelled"`
	Sats       int64     `json:"sats"`
	SolveMs    float64   `json:"solve_ms"`
	SolveN     uint64    `json:"solve_n"`
	LastPath   string    `json:"last_path"`
}

type visitState struct {
	at   time.Time
	path string
}

// Stats aggregates gate events. Use it through a Monitor.
type Stats struct {
	mu       sync.Mutex
	since    time.Time
	hours    map[int64]*Bucket
	pages    map[string]*PageStat
	clients  map[string]*ClientStat
	tokens   map[string]time.Time
	sessions map[string]visitState
	dirty    bool
}

func newStats(now time.Time) *Stats {
	return &Stats{since: now, hours: map[int64]*Bucket{}, pages: map[string]*PageStat{}, clients: map[string]*ClientStat{},
		tokens: map[string]time.Time{}, sessions: map[string]visitState{}}
}

var (
	botUA     = regexp.MustCompile(`(?i)bot\b|bot/|crawl|spider|slurp|scrap|fetch|curl/|wget/|python|go-http-client|java/|okhttp|axios|node-fetch|httpclient|libwww|headless|phantom|puppeteer|playwright|spikes-bot`)
	browserUA = regexp.MustCompile(`(?i)^mozilla/5\.0 .*(chrome|firefox|safari|edg|opr)/`)
)

// kindOf classifies one request.
func kindOf(e gate.Event) string {
	switch e.Class.Kind {
	case botid.Signed, botid.Verified:
		return KindVerified
	case botid.Impostor:
		return KindImpostor
	}
	if e.UserAgent == "" || botUA.MatchString(e.UserAgent) {
		return KindBot
	}
	if browserUA.MatchString(e.UserAgent) && e.Lang && (e.HTML || e.Session != "") {
		return KindHuman
	}
	return KindUnknown
}

// agentName shortens a User-Agent to what a person recognises.
func agentName(ua string) string {
	// Lower case ASCII only, byte for byte, so indexes found in l are valid in
	// ua (strings.ToLower can change the length: "Ⱥ" is 2 bytes, "ⱥ" is 3).
	lb := []byte(ua)
	for i, c := range lb {
		if 'A' <= c && c <= 'Z' {
			lb[i] = c + 'a' - 'A'
		}
	}
	l := string(lb)
	switch {
	case ua == "":
		return "(no User-Agent)"
	case browserUA.MatchString(ua) && !botUA.MatchString(ua):
		b := "Browser"
		switch {
		case strings.Contains(l, "edg/"):
			b = "Edge"
		case strings.Contains(l, "opr/"):
			b = "Opera"
		case strings.Contains(l, "firefox/"):
			b = "Firefox"
		case strings.Contains(l, "chrome/"):
			b = "Chrome"
		case strings.Contains(l, "safari/"):
			b = "Safari"
		}
		os := ""
		switch {
		case strings.Contains(l, "android"):
			os = "Android"
		case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
			os = "iOS"
		case strings.Contains(l, "windows"):
			os = "Windows"
		case strings.Contains(l, "mac os x"):
			os = "macOS"
		case strings.Contains(l, "linux"):
			os = "Linux"
		}
		if os != "" {
			return b + " · " + os
		}
		return b
	}
	// A bot or tool: its first product token ("GPTBot/1.2" → "GPTBot"),
	// or the name inside "(compatible; Googlebot/2.1; …)".
	if i := strings.Index(l, "compatible;"); i >= 0 {
		rest := strings.TrimSpace(ua[i+len("compatible;"):])
		name, _, _ := strings.Cut(rest, ";")
		name, _, _ = strings.Cut(name, ")")
		name, _, _ = strings.Cut(strings.TrimSpace(name), "/")
		if name != "" {
			return truncate(name, 40)
		}
	}
	if loc := botUA.FindStringIndex(ua); loc != nil && browserUA.MatchString(ua) { // "Mozilla/5.0 … HeadlessChrome/120" → "HeadlessChrome"
		word := func(b byte) bool {
			return b == '-' || b == '_' || b >= '0' && b <= '9' || b|0x20 >= 'a' && b|0x20 <= 'z'
		}
		i, j := loc[0], loc[0]
		for i > 0 && word(ua[i-1]) {
			i--
		}
		for j < len(ua) && word(ua[j]) {
			j++
		}
		return truncate(ua[i:j], 40)
	}
	name, _, _ := strings.Cut(ua, " ")
	name, _, _ = strings.Cut(name, "/")
	return truncate(name, 40)
}

// uaKey tells clients of one visitor apart; it hashes the stored (truncated) form so saved clients match live ones.
func uaKey(ua string) string {
	h := sha256.Sum256([]byte(truncate(ua, maxUserAgent)))
	return hex.EncodeToString(h[:4])
}

// add records one event; visitor is the anonymised client.
func (s *Stats) add(e gate.Event, visitor string) {
	now := e.Time
	if now.IsZero() {
		now = time.Now()
	}
	kind := kindOf(e)
	path := cleanPath(e.Resource)
	ck := visitor + "|" + uaKey(e.UserAgent) // client key: hashed before taking the lock

	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
	b := s.bucket(now)
	b.Requests++

	c := s.client(ck, visitor, e, now)
	if kindRank[kind] > kindRank[c.Kind] {
		c.Kind = kind
	}
	if e.Class.Kind != "" && e.Class.Kind != botid.Unknown || c.Class == "" {
		c.Class = string(e.Class.Kind)
	}
	if n := botName(e.Class); n != "" {
		c.Bot = n
	}
	c.Requests++
	c.LastSeen = now
	c.LastPath = path

	// Pages: HTML the origin delivered, and every protected path.
	var p *PageStat
	if e.Page || !e.Open {
		p = s.page(path, now)
	}
	if p != nil {
		p.LastSeen = now
		if _, ok := p.seen[visitor]; !ok && len(p.seen) < maxSeen {
			p.seen[visitor] = struct{}{}
			p.Visitors++
		}
	}
	if e.Page {
		b.PageViews++
		p.Views++
		c.Pages++
		switch c.Kind {
		case KindHuman:
			b.HumanViews++
			p.HumanViews++
		case KindVerified, KindImpostor, KindBot:
			b.BotViews++
		}
		if c.Kind == KindHuman { // a crawler's pace says nothing about reading time
			s.visit(e, ck, path, now)
		}
	}
	if e.Status > 0 {
		ms := float64(e.Latency) / float64(time.Millisecond)
		b.LatencyMs += ms
		b.LatencyN++
		if p != nil {
			p.LatencyMs += ms
			p.LatencyN++
		}
	}

	switch e.Outcome {
	case gate.OutcomeChallenged, gate.OutcomeRejected:
		b.Challenges++
		p.Challenges++
		c.Challenges++
		if e.Outcome == gate.OutcomeRejected {
			b.Repelled++
			p.Repelled++
			c.Repelled++
		}
		// Timed per client and page, not per token: a 402 can offer several
		// tokens (invoice, puzzle, lottery, the browser's), and any of them may come back.
		if k := waitKey(ck, path); s.tokens[k].IsZero() {
			s.rememberToken(k, now)
		}
	case gate.OutcomePaid:
		b.Paid++
		b.Sats += e.Price
		p.Paid++
		p.Sats += e.Price
		c.Paid++
		c.Sats += e.Price
		s.unlocked(waitKey(ck, path), now, b, p, c)
	case gate.OutcomePoW:
		b.PoW++
		p.PoW++
		c.PoW++
		s.unlocked(waitKey(ck, path), now, b, p, c)
	case gate.OutcomeFree:
		b.Free++
		p.Free++
	case gate.OutcomeRateLimited, gate.OutcomeBlocked, gate.OutcomeBusy:
		b.Repelled++
		p.Repelled++
		c.Repelled++
	}
}

// waitKey identifies one client waiting at one page (not by session: a
// client gets its session cookie with the 402 itself).
func waitKey(clientKey, path string) string {
	return clientKey + "|" + path
}

// unlocked times how long the client took from its 402 to a valid proof.
func (s *Stats) unlocked(token string, now time.Time, b *Bucket, p *PageStat, c *ClientStat) {
	t0, ok := s.tokens[token]
	if !ok {
		return
	}
	delete(s.tokens, token)
	d := now.Sub(t0)
	if d < 0 || d > tokenWindow {
		return
	}
	ms := float64(d) / float64(time.Millisecond)
	b.SolveMs += ms
	b.SolveN++
	p.SolveMs += ms
	p.SolveN++
	c.SolveMs += ms
	c.SolveN++
}

func (s *Stats) rememberToken(token string, now time.Time) {
	if len(s.tokens) >= maxTokens {
		for k, t := range s.tokens {
			if now.Sub(t) > tokenWindow {
				delete(s.tokens, k)
			}
		}
		if len(s.tokens) >= maxTokens {
			clear(s.tokens) // bounded memory beats timing every unlock
		}
	}
	s.tokens[token] = now
}

// visit estimates time on page: the gap to the same visitor's next page,
// within one visit (sessionGap). The last page of a visit has no estimate.
func (s *Stats) visit(e gate.Event, clientKey, path string, now time.Time) {
	key := e.Session
	if key == "" {
		key = clientKey
	}
	if prev, ok := s.sessions[key]; ok {
		if d := now.Sub(prev.at); d > 0 && d <= sessionGap {
			if pp := s.pages[prev.path]; pp != nil {
				pp.DwellS += d.Seconds()
				pp.DwellN++
			}
			b := s.bucket(now)
			b.DwellS += d.Seconds()
			b.DwellN++
		}
	}
	if len(s.sessions) >= maxSessions {
		for k, v := range s.sessions {
			if now.Sub(v.at) > sessionGap {
				delete(s.sessions, k)
			}
		}
		if len(s.sessions) >= maxSessions {
			clear(s.sessions)
		}
	}
	s.sessions[key] = visitState{at: now, path: path}
}

func (s *Stats) bucket(now time.Time) *Bucket {
	h := now.Truncate(time.Hour).Unix()
	b := s.hours[h]
	if b == nil {
		b = &Bucket{Hour: h}
		s.hours[h] = b
		cut := now.Add(-statsKeep).Unix()
		for k := range s.hours {
			if k < cut {
				delete(s.hours, k)
			}
		}
	}
	return b
}

func (s *Stats) page(path string, now time.Time) *PageStat {
	p := s.pages[path]
	if p == nil {
		if len(s.pages) >= maxPages {
			evictOldest(s.pages, func(p *PageStat) time.Time { return p.LastSeen }) // random paths must not fill it for good
		}
		p = &PageStat{Path: path, seen: map[string]struct{}{}}
		s.pages[path] = p
	}
	if p.seen == nil {
		p.seen = map[string]struct{}{}
	}
	return p
}

func (s *Stats) client(key, visitor string, e gate.Event, now time.Time) *ClientStat {
	c := s.clients[key]
	if c == nil {
		if len(s.clients) >= maxClients {
			evictOldest(s.clients, func(c *ClientStat) time.Time { return c.LastSeen })
		}
		c = &ClientStat{Visitor: visitor, Kind: KindUnknown, Agent: agentName(e.UserAgent), UserAgent: truncate(e.UserAgent, maxUserAgent), FirstSeen: now}
		s.clients[key] = c
	}
	return c
}

// evictOldest drops the tenth of m seen least recently.
func evictOldest[V any](m map[string]V, seen func(V) time.Time) {
	list := make([]string, 0, len(m))
	for k := range m {
		list = append(list, k)
	}
	sort.Slice(list, func(i, j int) bool { return seen(m[list[i]]).Before(seen(m[list[j]])) })
	for _, k := range list[:max(1, len(list)/10)] {
		delete(m, k)
	}
}

// --- report ---

// KindStat sums up one kind of client over the clients table.
type KindStat struct {
	Clients    uint64 `json:"clients"`
	Requests   uint64 `json:"requests"`
	Pages      uint64 `json:"pages"`
	Challenges uint64 `json:"challenges"`
	Unlocks    uint64 `json:"unlocks"`
	Sats       int64  `json:"sats"`
}

// Report is what GET /api/stats returns.
type Report struct {
	Range      string              `json:"range"`
	From       time.Time           `json:"from"`
	To         time.Time           `json:"to"`
	Since      time.Time           `json:"since"` // statistics collected since
	VisitorIPs string              `json:"visitor_ips"`
	Totals     Bucket              `json:"totals"`
	UnlockRate float64             `json:"unlock_rate"` // (paid + pow) / challenges
	Series     []Bucket            `json:"series"`      // hourly, or daily for 30d
	Kinds      map[string]KindStat `json:"kinds"`       // over the clients below, all time
	Pages      []PageStat          `json:"pages"`
	Clients    []ClientStat        `json:"clients"`
	ClientsAll int                 `json:"clients_total"`
}

var ranges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// Report builds the dashboard's view. kind filters the clients table ("" for all).
func (s *Stats) report(rng, kind, mode string, now time.Time) Report {
	span, ok := ranges[rng]
	if !ok {
		rng, span = "24h", ranges["24h"]
	}
	to := now.Truncate(time.Hour)
	from := to.Add(-span + time.Hour)
	step := time.Hour
	if rng == "30d" {
		step = 24 * time.Hour
		from = now.Truncate(24*time.Hour).AddDate(0, 0, -29)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	r := Report{Range: rng, From: from, To: now, Since: s.since, VisitorIPs: mode, Kinds: map[string]KindStat{}}
	for t := from; !t.After(to); t = t.Add(step) {
		agg := Bucket{Hour: t.Unix()}
		for h := t; h.Before(t.Add(step)); h = h.Add(time.Hour) {
			if b := s.hours[h.Unix()]; b != nil {
				agg.add(b)
			}
		}
		r.Series = append(r.Series, agg)
		r.Totals.add(&agg)
	}
	if r.Totals.Challenges > 0 {
		r.UnlockRate = math.Min(1, float64(r.Totals.Paid+r.Totals.PoW)/float64(r.Totals.Challenges))
	}

	for _, p := range s.pages {
		r.Pages = append(r.Pages, *p)
	}
	sort.Slice(r.Pages, func(i, j int) bool {
		a, b := r.Pages[i], r.Pages[j]
		if a.Views+a.Challenges != b.Views+b.Challenges {
			return a.Views+a.Challenges > b.Views+b.Challenges
		}
		return a.Path < b.Path
	})
	if len(r.Pages) > reportPages {
		r.Pages = r.Pages[:reportPages]
	}

	for _, c := range s.clients {
		k := r.Kinds[c.Kind]
		k.Clients++
		k.Requests += c.Requests
		k.Pages += c.Pages
		k.Challenges += c.Challenges
		k.Unlocks += c.Paid + c.PoW
		k.Sats += c.Sats
		r.Kinds[c.Kind] = k
		if kind == "" || c.Kind == kind {
			r.Clients = append(r.Clients, *c)
		}
	}
	r.ClientsAll = len(r.Clients)
	sort.Slice(r.Clients, func(i, j int) bool { return r.Clients[i].LastSeen.After(r.Clients[j].LastSeen) })
	if len(r.Clients) > reportRows {
		r.Clients = r.Clients[:reportRows]
	}
	return r
}

// --- persistence ---

type statsFile struct {
	V       int          `json:"v"`
	Since   time.Time    `json:"since"`
	Hours   []Bucket     `json:"hours"`
	Pages   []PageStat   `json:"pages"`
	Clients []ClientStat `json:"clients"`
}

// StatsPath is the statistics file next to the config: "config.json" →
// "config.stats.json".
func StatsPath(configFile string) string {
	dir, name := filepath.Split(configFile)
	ext := filepath.Ext(name)
	if ext == "" {
		ext = ".json"
	}
	return filepath.Join(dir, strings.TrimSuffix(name, filepath.Ext(name))+".stats"+ext)
}

// load restores saved statistics; a missing file is no error.
func (s *Stats) load(path string, now time.Time) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f statsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !f.Since.IsZero() && f.Since.Before(s.since) {
		s.since = f.Since
	}
	cut := now.Add(-statsKeep)
	for _, b := range f.Hours {
		if b.Hour >= cut.Unix() {
			b := b
			s.hours[b.Hour] = &b
		}
	}
	for _, p := range f.Pages {
		if len(s.pages) < maxPages {
			p := p
			p.seen = map[string]struct{}{}
			s.pages[p.Path] = &p
		}
	}
	for _, c := range f.Clients {
		if c.LastSeen.After(cut) && len(s.clients) < maxClients {
			c := c
			s.clients[c.Visitor+"|"+uaKey(c.UserAgent)] = &c
		}
	}
	return nil
}

// save writes the statistics atomically (mode 0600).
func (s *Stats) save(path string) error {
	s.mu.Lock()
	f := statsFile{V: 1, Since: s.since}
	for _, b := range s.hours {
		f.Hours = append(f.Hours, *b)
	}
	for _, p := range s.pages {
		f.Pages = append(f.Pages, *p)
	}
	for _, c := range s.clients {
		f.Clients = append(f.Clients, *c)
	}
	s.dirty = false
	s.mu.Unlock()
	sort.Slice(f.Hours, func(i, j int) bool { return f.Hours[i].Hour < f.Hours[j].Hour })
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stats-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil { // make the rename durable; not possible on Windows, so best effort
		d.Sync()
		d.Close()
	}
	return nil
}

// run saves the statistics every interval while they change, and once more when ctx ends.
func (s *Stats) run(ctx context.Context, path string, every time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.save(path); err != nil {
				logf("admin: saving statistics: %v", err)
			}
			return
		case <-t.C:
			s.mu.Lock()
			dirty := s.dirty
			s.mu.Unlock()
			if dirty {
				if err := s.save(path); err != nil {
					s.mu.Lock()
					s.dirty = true
					s.mu.Unlock()
					logf("admin: saving statistics to %s: %v", path, err)
				}
			}
		}
	}
}
