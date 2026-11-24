package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
)

func (f *fixture) withSiege() *PublicSiege {
	s := NewPublicSiege()
	s.now = func() time.Time { return f.now }
	f.gate.opt.PublicSiege = s
	return s
}

func (f *fixture) siegeJSON(t *testing.T) (SiegeSnapshot, string) {
	t.Helper()
	rec := f.get(SiegeJSONPath, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("siege.json: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	var s SiegeSnapshot
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return s, body
}

const siegeLinkText = "See the siege in real time"

func TestSiegeOffByDefault(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{SiegePagePath, SiegeJSONPath} {
		if rec := f.get(p, "", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", p, rec.Code)
		}
	}
	if body := f.get("/premium/article", "", "text/html").Body.String(); strings.Contains(body, siegeLinkText) || strings.Contains(body, SiegePagePath) {
		t.Fatal("402 page links to the siege view while it is off")
	}
}

func TestSiegePageAndLink(t *testing.T) {
	f := newFixture(t)
	f.withSiege()
	body := f.get("/premium/article", "", "text/html").Body.String()
	if !strings.Contains(body, `<a href="`+SiegePagePath+`">`+siegeLinkText+`</a>`) {
		t.Fatalf("402 page has no siege link: %s", body)
	}

	rec := f.get(SiegePagePath, "", "")
	page := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("page: %d CSP %q", rec.Code, csp)
	}
	scripts := inlineScripts(page)
	if len(scripts) != 2 {
		t.Fatalf("want 2 inline scripts, got %d", len(scripts))
	}
	for _, js := range append(scripts, siegeCSS) {
		if !strings.Contains(csp, "'sha256-"+b64sha(js)+"'") {
			t.Fatalf("CSP %q does not cover an inline script or style", csp)
		}
	}
	// No external resources, no HTML injection sinks, honest about the delay.
	if regexp.MustCompile(`(?i)<(script|link|img|iframe)[^>]+(src|href)=`).MatchString(strings.Replace(page, `<link rel="icon" href="data:`, "", 1)) ||
		strings.Contains(page, "innerHTML") || !strings.Contains(page, "Delayed a few seconds") || !strings.Contains(page, "anonymised") ||
		!strings.Contains(page, "prefers-reduced-motion") || !strings.Contains(page, "document.hidden") {
		t.Fatalf("unexpected page: %s", page)
	}
	for _, want := range []string{`class="logo-link"`, `aria-label="Back to the site"`, `<h1><a href="/" class="logo-link" aria-label="Back to the site">`} {
		if !strings.Contains(page, want) {
			t.Fatalf("siege heading logo is not a home link, missing %q", want)
		}
	}
	if rec := f.get(SiegePagePath, "", ""); rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("page sets a cookie")
	}
	req := httptest.NewRequest(http.MethodPost, SiegeJSONPath, nil)
	w := httptest.NewRecorder()
	f.gate.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

func TestSiegeJSONHasNoVisitorData(t *testing.T) {
	f := newFixture(t)
	s := f.withSiege()
	// Real requests through the gate: an address, a path with a query and
	// a user agent that must not show up anywhere.
	req := httptest.NewRequest(http.MethodGet, "/premium/secret-article?email=alice%40example.com", nil)
	req.RemoteAddr = "203.0.113.77:4242"
	req.Header.Set("User-Agent", "Mozilla/5.0 UniqueAgent/9.9")
	f.gate.ServeHTTP(httptest.NewRecorder(), req)
	b := f.challenge(t, "/premium/x")
	if rec := f.get("/premium/x", solve(t, b), ""); rec.Code != http.StatusOK {
		t.Fatalf("pow: %d", rec.Code)
	}
	// Classes: only listed crawlers keep a name; signed agents (a URL) do not.
	s.Observe(Event{Time: f.now, Outcome: OutcomeChallenged, Class: botid.Class{Kind: botid.Verified, Name: "GPTBot"}})
	s.Observe(Event{Time: f.now, Outcome: OutcomeRejected, Class: botid.Class{Kind: botid.Impostor, Name: "Googlebot"}})
	s.Observe(Event{Time: f.now, Outcome: OutcomePaid, Class: botid.Class{Kind: botid.Signed, Name: "https://agent.example/keys"}})
	s.Observe(Event{Time: f.now, Outcome: OutcomeBlocked, Class: botid.Class{Kind: botid.Verified, Name: "<script>"}})

	f.now = f.now.Add(SiegeDelay)
	snap, body := f.siegeJSON(t)
	for _, leak := range []string{"203.0.113", "premium", "secret", "email", "alice", "Mozilla", "UniqueAgent", "agent.example", "script", "v-"} {
		if strings.Contains(body, leak) {
			t.Fatalf("JSON leaks %q: %s", leak, body)
		}
	}
	// Exactly the documented fields, nothing else.
	var raw map[string]any
	json.Unmarshal([]byte(body), &raw)
	if keys(raw) != "delay_seconds,last_minute,seconds" {
		t.Fatalf("top-level fields: %s", keys(raw))
	}
	allowed := map[string]bool{"t": true, "paid": true, "pow": true, "held": true, "repelled": true, "bots": true, "name": true, "group": true, "fake": true}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				if !allowed[k] && k != "delay_seconds" && k != "last_minute" && k != "seconds" {
					t.Fatalf("unexpected field %q in %s", k, body)
				}
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(raw)
	if len(snap.Seconds) != 1 {
		t.Fatalf("want one second, got %s", body)
	}
	sec := snap.Seconds[0]
	// 402 for the first request, 402 + PoW for the second, then the four events.
	if sec.Held != 3 || sec.PoW != 1 || sec.Paid != 1 || sec.Repelled != 2 {
		t.Fatalf("counts: %+v", sec.SiegeCounts)
	}
	want := []SiegeBot{{Name: "GPTBot", Group: "held"}, {Name: "Googlebot", Group: "repelled", Fake: true}}
	if len(sec.Bots) != 2 || sec.Bots[0] != want[0] || sec.Bots[1] != want[1] {
		t.Fatalf("bots: %+v", sec.Bots)
	}
	if snap.DelaySeconds != 8 || snap.LastMinute != sec.SiegeCounts {
		t.Fatalf("snapshot: %+v", snap)
	}
}

func keys(m map[string]any) string {
	var out []string
	for _, k := range []string{"delay_seconds", "last_minute", "seconds"} {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	if len(out) != len(m) {
		return "extra fields"
	}
	return strings.Join(out, ",")
}

func TestSiegeDelay(t *testing.T) {
	f := newFixture(t)
	s := f.withSiege()
	t0 := f.now
	s.Observe(Event{Time: t0, Outcome: OutcomePaid})
	for _, d := range []time.Duration{0, time.Second, SiegeDelay - time.Second} {
		f.now = t0.Add(d)
		if snap, body := f.siegeJSON(t); len(snap.Seconds) != 0 || snap.LastMinute.Paid != 0 {
			t.Fatalf("visible after %v: %s", d, body)
		}
	}
	f.now = t0.Add(SiegeDelay)
	if snap, body := f.siegeJSON(t); len(snap.Seconds) != 1 || snap.Seconds[0].T != t0.Unix() || snap.Seconds[0].Paid != 1 {
		t.Fatalf("not visible after the delay: %s", body)
	}
	// Seconds leave the event list after siegeShown, the minute after 60 s.
	f.now = t0.Add(SiegeDelay + siegeShown*time.Second)
	if snap, body := f.siegeJSON(t); len(snap.Seconds) != 0 || snap.LastMinute.Paid != 1 {
		t.Fatalf("after the window: %s", body)
	}
	f.now = t0.Add(SiegeDelay + time.Minute)
	if snap, body := f.siegeJSON(t); snap.LastMinute.Paid != 0 {
		t.Fatalf("after a minute: %s", body)
	}
}

func TestSiegeSnapshotBuiltOncePerSecond(t *testing.T) {
	f := newFixture(t)
	s := f.withSiege()
	invoices := f.gate.Status().Node.InvoicesCreated
	s.Observe(Event{Time: f.now.Add(-SiegeDelay), Outcome: OutcomePoW})
	_, first := f.siegeJSON(t)
	for range 500 {
		// New events in the same second do not trigger a rebuild.
		s.Observe(Event{Time: f.now.Add(-SiegeDelay), Outcome: OutcomePaid})
		if _, body := f.siegeJSON(t); body != first {
			t.Fatal("snapshot changed within the same second")
		}
	}
	if s.builds != 1 {
		t.Fatalf("built %d times, want 1", s.builds)
	}
	f.now = f.now.Add(time.Second)
	f.siegeJSON(t)
	if s.builds != 2 {
		t.Fatalf("built %d times after a second, want 2", s.builds)
	}
	if got := f.gate.Status().Node.InvoicesCreated; got != invoices {
		t.Fatalf("siege view created invoices: %d -> %d", invoices, got)
	}
}

func TestSiegeResponseSizeIsBounded(t *testing.T) {
	f := newFixture(t)
	s := f.withSiege()
	name := strings.Repeat("B", siegeNameLen)
	for sec := range int64(siegeSeconds) {
		for range 1000 {
			s.Observe(Event{Time: f.now.Add(-time.Duration(sec) * time.Second), Outcome: OutcomeRejected, Class: botid.Class{Kind: botid.Impostor, Name: name}})
		}
	}
	if _, body := f.siegeJSON(t); len(body) > 8<<10 {
		t.Fatalf("worst-case body is %d bytes", len(body))
	}
}
