package admin

import (
	"fmt"
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
	"github.com/Choffolo/spikes402/internal/gate"
)

const (
	chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
	gbotUA   = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func TestKindOf(t *testing.T) {
	cases := []struct {
		e    gate.Event
		want string
	}{
		{gate.Event{Class: botid.Class{Kind: botid.Verified}, UserAgent: gbotUA}, KindVerified},
		{gate.Event{Class: botid.Class{Kind: botid.Signed}}, KindVerified},
		{gate.Event{Class: botid.Class{Kind: botid.Impostor}, UserAgent: gbotUA}, KindImpostor},
		{gate.Event{UserAgent: ""}, KindBot},
		{gate.Event{UserAgent: "curl/8.5.0", Lang: true, HTML: true}, KindBot},
		{gate.Event{UserAgent: "python-requests/2.32"}, KindBot},
		{gate.Event{UserAgent: "spikes-bot/1.0"}, KindBot},
		{gate.Event{UserAgent: "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0 Safari/537.36", Lang: true, HTML: true}, KindBot},
		{gate.Event{UserAgent: chromeUA, Lang: true, HTML: true}, KindHuman},
		{gate.Event{UserAgent: chromeUA, Lang: true, Session: "s1"}, KindHuman},
		{gate.Event{UserAgent: chromeUA, HTML: true}, KindUnknown}, // no Accept-Language: not like a browser
		{gate.Event{UserAgent: "Mozilla/4.0 something"}, KindUnknown},
	}
	for _, c := range cases {
		if got := kindOf(c.e); got != c.want {
			t.Errorf("%q class %q: %s, want %s", c.e.UserAgent, c.e.Class.Kind, got, c.want)
		}
	}
}

func TestAgentName(t *testing.T) {
	for ua, want := range map[string]string{
		chromeUA: "Chrome · Windows",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1": "Safari · iOS",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0":                                                                  "Firefox · Linux",
		gbotUA:       "Googlebot",
		"curl/8.5.0": "curl",
		"GPTBot/1.2 (+https://openai.com/gptbot)": "GPTBot",
		"": "(no User-Agent)",
		// Letters whose lower case is longer in UTF-8 must not shift the slice (used to panic).
		"ȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺȺ (compatible; EvilBot/1.0)": "EvilBot",
		"Ⱥ compatible;": "Ⱥ",
	} {
		if got := agentName(ua); got != want {
			t.Errorf("%q: %q, want %q", ua, got, want)
		}
	}
}

func TestStatsFlow(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	m := NewMonitor("truncate", t0)
	ip := net.ParseIP("203.0.113.9")
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	// A person: home page, an article (time on home: 40 s), then a protected page unlocked by PoW in 3 s.
	human := gate.Event{IP: ip, UserAgent: chromeUA, Lang: true, HTML: true, Session: "s1", Status: 200, Latency: 20 * time.Millisecond}
	ev := func(base gate.Event, d time.Duration, path string, o gate.Outcome, f func(*gate.Event)) {
		e := base
		e.Time, e.Resource, e.Outcome = at(d), "GET "+path, o
		if f != nil {
			f(&e)
		}
		m.Observe(e)
	}
	page := func(e *gate.Event) { e.Page, e.Open = true, true }
	ev(human, 0, "/", gate.OutcomeOpen, page)
	ev(human, 40*time.Second, "/blog/a?utm=x", gate.OutcomeOpen, page)
	ev(human, 50*time.Second, "/premium/r", gate.OutcomeChallenged, func(e *gate.Event) { e.Token, e.Status, e.Latency = "t1", 0, 0 })
	ev(human, 53*time.Second, "/premium/r", gate.OutcomePoW, func(e *gate.Event) { e.Token, e.Page = "t1", true })
	// A bot pays for the same page; an impostor gets blocked.
	bot := gate.Event{IP: net.ParseIP("198.51.100.4"), UserAgent: "spikes-bot/1.0"}
	ev(bot, time.Minute, "/premium/r", gate.OutcomeChallenged, func(e *gate.Event) { e.Token = "t2" })
	ev(bot, time.Minute+1500*time.Millisecond, "/premium/r", gate.OutcomePaid, func(e *gate.Event) {
		e.Token, e.Price, e.Page, e.Status, e.Latency = "t2", 10, true, 200, 5*time.Millisecond
	})
	ev(gate.Event{IP: net.ParseIP("192.0.2.1"), UserAgent: gbotUA, Class: botid.Class{Kind: botid.Impostor, Name: "googlebot"}}, 2*time.Minute, "/premium/r", gate.OutcomeBlocked, nil)

	// The siege view only sees protected requests.
	if c := m.Counts(); c.Total != 5 {
		t.Fatalf("siege counted %d, want 5 (open requests are for statistics only)", c.Total)
	}

	r := m.Stats("24h", "", at(time.Hour))
	tot := r.Totals
	if tot.Requests != 7 || tot.PageViews != 4 || tot.HumanViews != 3 || tot.BotViews != 1 || tot.Challenges != 2 ||
		tot.PoW != 1 || tot.Paid != 1 || tot.Sats != 10 || tot.Repelled != 1 || len(r.Series) != 24 {
		t.Fatalf("totals %+v, %d hours", tot, len(r.Series))
	}
	if r.UnlockRate != 1 || tot.SolveN != 2 || tot.SolveMs != 4500 {
		t.Fatalf("unlock rate %v, solves %d/%v ms", r.UnlockRate, tot.SolveN, tot.SolveMs)
	}
	if tot.DwellN != 2 || tot.DwellS != 40+13 { // home → blog 40 s, blog → premium 13 s
		t.Fatalf("dwell %d / %v s", tot.DwellN, tot.DwellS)
	}
	pages := map[string]PageStat{}
	for _, p := range r.Pages {
		pages[p.Path] = p
	}
	if p := pages["/"]; p.Views != 1 || p.DwellN != 1 || p.DwellS != 40 {
		t.Fatalf("home %+v", p)
	}
	if _, ok := pages["/blog/a"]; !ok {
		t.Fatalf("query string kept: %v", r.Pages)
	}
	if p := pages["/premium/r"]; p.Challenges != 2 || p.PoW != 1 || p.Paid != 1 || p.Sats != 10 || p.Visitors != 3 || p.Repelled != 1 || p.SolveN != 2 {
		t.Fatalf("premium %+v", p)
	}
	if r.Kinds[KindHuman].Clients != 1 || r.Kinds[KindBot].Clients != 1 || r.Kinds[KindImpostor].Clients != 1 {
		t.Fatalf("kinds %+v", r.Kinds)
	}
	r = m.Stats("7d", KindHuman, at(time.Hour))
	if len(r.Clients) != 1 || len(r.Series) != 7*24 {
		t.Fatalf("filtered clients %+v, %d hours", r.Clients, len(r.Series))
	}
	c := r.Clients[0]
	if c.Visitor != "203.0.113.0/24" || c.Agent != "Chrome · Windows" || c.Pages != 3 || c.PoW != 1 || c.SolveMs != 3000 || c.LastPath != "/premium/r" {
		t.Fatalf("human client %+v", c)
	}
	if r := m.Stats("30d", "", at(time.Hour)); len(r.Series) != 30 || r.Totals.Requests != 7 {
		t.Fatalf("30d: %d days, %d requests", len(r.Series), r.Totals.Requests)
	}
	if r := m.Stats("bogus", "", at(time.Hour)); r.Range != "24h" {
		t.Fatalf("range %q", r.Range)
	}
}

// A late proof (beyond the token window) or one without a 402 seen is not timed.
func TestSolveWindow(t *testing.T) {
	s, t0 := newStats(time.Unix(0, 0)), time.Unix(1_800_000_000, 0)
	s.add(gate.Event{Time: t0, Outcome: gate.OutcomeChallenged, Token: "a", Resource: "GET /p"}, "v")
	s.add(gate.Event{Time: t0.Add(2 * time.Hour), Outcome: gate.OutcomePoW, Token: "a", Resource: "GET /p"}, "v")
	s.add(gate.Event{Time: t0.Add(2 * time.Hour), Outcome: gate.OutcomePaid, Token: "never-seen", Resource: "GET /p"}, "v")
	if b := s.hours[t0.Add(2*time.Hour).Truncate(time.Hour).Unix()]; b.SolveN != 0 || b.PoW != 1 || b.Paid != 1 || len(s.tokens) != 0 {
		t.Fatalf("%+v, %d tokens", b, len(s.tokens))
	}
}

// A flood of random paths cannot fill the page table for good: the pages
// seen least recently make room, and the newest path is counted.
func TestStatsPagesEvictOldest(t *testing.T) {
	s, t0 := newStats(time.Unix(0, 0)), time.Unix(1_800_000_000, 0)
	for i := 0; i < maxPages+10; i++ {
		s.add(gate.Event{Time: t0.Add(time.Duration(i) * time.Second), Resource: fmt.Sprintf("GET /premium/%d", i), Outcome: gate.OutcomeChallenged}, "v")
	}
	if len(s.pages) > maxPages || s.pages[fmt.Sprintf("/premium/%d", maxPages+9)] == nil || s.pages["/premium/0"] != nil {
		t.Fatalf("%d pages; newest kept, oldest evicted?", len(s.pages))
	}
}

func TestStatsCaps(t *testing.T) {
	s, t0 := newStats(time.Unix(0, 0)), time.Unix(1_800_000_000, 0)
	for i := 0; i < maxClients+10; i++ {
		s.add(gate.Event{Time: t0.Add(time.Duration(i) * time.Second), Resource: fmt.Sprintf("GET /x/%d", i), UserAgent: "curl/8", Open: true}, fmt.Sprint("v", i))
	}
	if len(s.clients) > maxClients || s.clients[fmt.Sprintf("v%d|%s", maxClients+9, uaKey("curl/8"))] == nil {
		t.Fatalf("%d clients, newest missing?", len(s.clients))
	}
	if s.clients["v0|"+uaKey("curl/8")] != nil {
		t.Fatal("oldest client not evicted")
	}
	if len(s.pages) != 0 { // open, non-HTML requests are no pages
		t.Fatalf("%d pages", len(s.pages))
	}
	s.add(gate.Event{Time: t0, Resource: "GET /old", Outcome: gate.OutcomeFree}, "v")
	s.add(gate.Event{Time: t0.Add(statsKeep + 2*time.Hour), Resource: "GET /new", Outcome: gate.OutcomeFree}, "v")
	if _, ok := s.hours[t0.Truncate(time.Hour).Unix()]; ok {
		t.Fatal("hour older than 30 days kept")
	}
}

func TestStatsPersistence(t *testing.T) {
	if got := StatsPath(filepath.Join("etc", "spikes", "config.json")); got != filepath.Join("etc", "spikes", "config.stats.json") {
		t.Fatalf("StatsPath: %s", got)
	}
	if got := StatsPath("conf"); got != "conf.stats.json" {
		t.Fatalf("StatsPath: %s", got)
	}
	path := filepath.Join(t.TempDir(), "c.stats.json")
	now := time.Now()
	a := newStats(now.Add(-time.Hour))
	if err := a.load(path, now); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	a.add(gate.Event{Time: now, Resource: "GET /premium/x", Outcome: gate.OutcomePaid, Price: 21, UserAgent: chromeUA, Page: true}, "203.0.113.0/24")
	if err := a.save(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("statistics file: %v %v", fi, err)
	}
	b := newStats(now)
	if err := b.load(path, now); err != nil {
		t.Fatal(err)
	}
	b.add(gate.Event{Time: now, Resource: "GET /premium/x", Outcome: gate.OutcomePaid, Price: 21, UserAgent: chromeUA, Page: true}, "203.0.113.0/24")
	r := b.report("24h", "", "truncate", now)
	if r.Totals.Paid != 2 || r.Totals.Sats != 42 || len(r.Pages) != 1 || r.Pages[0].Paid != 2 || len(r.Clients) != 1 || r.Clients[0].Paid != 2 || !r.Since.Equal(a.since) {
		t.Fatalf("after reload: %+v pages %+v clients %+v since %v", r.Totals, r.Pages, r.Clients, r.Since)
	}
	os.WriteFile(path, []byte("{broken"), 0o600)
	if newStats(now).load(path, now) == nil {
		t.Fatal("broken file loaded")
	}
}

func TestStatsAPI(t *testing.T) {
	e := newEnv(t, `,"visitor_ips":"truncate"`)
	e.now = time.Now() // the gate stamps events with the real clock
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/premium/p%d?email=secret", i), nil)
		req.RemoteAddr = "203.0.113.7:1234"
		req.Header.Set("User-Agent", chromeUA)
		req.Header.Set("Accept-Language", "it-IT")
		req.Header.Set("Accept", "text/html")
		e.gate.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("GET", "/public", nil) // not protected: statistics only
	req.RemoteAddr = "198.51.100.1:1"
	e.gate.ServeHTTP(httptest.NewRecorder(), req)

	rec, out := e.call("GET", "/api/stats?range=7d", aiKey, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	tot := out["totals"].(map[string]any)
	if tot["challenges"].(float64) != 3 || tot["requests"].(float64) != 4 || out["visitor_ips"] != "truncate" || out["range"] != "7d" {
		t.Fatalf("%v", out)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.0/24") || strings.Contains(body, "203.0.113.7") || strings.Contains(body, "secret") {
		t.Fatalf("visitor not truncated or query leaked: %s", body)
	}
	kinds := out["kinds"].(map[string]any)
	if kinds[KindHuman] == nil || kinds[KindBot] == nil { // the /public request had no User-Agent
		t.Fatalf("kinds %v", kinds)
	}
	if rec, _ := e.call("GET", "/api/stats", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d", rec.Code)
	}
}
