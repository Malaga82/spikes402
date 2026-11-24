package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func (f *fixture) withStats() *PublicStats {
	s := NewPublicStats(f.now)
	s.now = func() time.Time { return f.now }
	f.gate.opt.PublicStats = s
	return s
}

func getStats(t *testing.T, g *Gate, method string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, StatsPath, nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func decodeStats(t *testing.T, rec *httptest.ResponseRecorder) PublicSnapshot {
	t.Helper()
	var s PublicSnapshot
	if err := json.NewDecoder(rec.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return s
}

func TestStatsOffIsNotFound(t *testing.T) {
	f := newFixture(t)
	rec := getStats(t, f.gate, http.MethodGet)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

func TestStatsEmptyAndHeaders(t *testing.T) {
	f := newFixture(t)
	s := f.withStats()
	rec := getStats(t, f.gate, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff")
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=5" {
		t.Fatalf("cache-control %q", rec.Header().Get("Cache-Control"))
	}
	got := decodeStats(t, rec)
	if !got.Since.Equal(s.since) || got.Challenges != 0 || got.UnlocksPoW != 0 || got.UnlocksLightning != 0 || got.SatsReceived != 0 {
		t.Fatalf("empty snapshot: %+v", got)
	}
	if got.Last24h != (PublicWindow{}) {
		t.Fatalf("empty window: %+v", got.Last24h)
	}
	body := rec.Body.String()
	for _, leak := range []string{"visitor", "ip", "path", "user-agent", "user_agent", "balance", "password", "phoenix"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}

	head := getStats(t, f.gate, http.MethodHead)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d body=%q", head.Code, head.Body.String())
	}
	post := getStats(t, f.gate, http.MethodPost)
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", post.Code)
	}
}

func TestStatsCountsChallengePoWAndPayment(t *testing.T) {
	f := newFixture(t)
	f.withStats()

	ch := f.challenge(t, "/premium/a")
	snap := f.gate.opt.PublicStats.Snapshot()
	if snap.Challenges != 1 || snap.UnlocksPoW != 0 || snap.UnlocksLightning != 0 || snap.SatsReceived != 0 {
		t.Fatalf("after 402: %+v", snap)
	}

	rec := f.get("/premium/a", solve(t, ch), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("pow: %d %s", rec.Code, rec.Body.String())
	}
	snap = f.gate.opt.PublicStats.Snapshot()
	if snap.Challenges != 1 || snap.UnlocksPoW != 1 || snap.UnlocksLightning != 0 || snap.SatsReceived != 0 {
		t.Fatalf("after pow: %+v", snap)
	}

	ch2 := f.challenge(t, "/premium/b")
	auth := f.pay(t, ch2)
	rec = f.get("/premium/b", auth, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("pay: %d %s", rec.Code, rec.Body.String())
	}
	snap = f.gate.opt.PublicStats.Snapshot()
	if snap.Challenges != 2 || snap.UnlocksPoW != 1 || snap.UnlocksLightning != 1 || snap.SatsReceived != 10 {
		t.Fatalf("after payment: %+v", snap)
	}
	if snap.Last24h != (PublicWindow{Challenges: 2, UnlocksPoW: 1, UnlocksLightning: 1, SatsReceived: 10}) {
		t.Fatalf("last 24h: %+v", snap.Last24h)
	}
}

func TestStatsRejectedIsAChallengeNotAnUnlock(t *testing.T) {
	f := newFixture(t)
	f.withStats()
	ch := f.challenge(t, "/premium/a")
	rec := f.get("/premium/a", "PoW "+ch.PoW.Challenge+":0", "")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("want 402, got %d", rec.Code)
	}
	snap := f.gate.opt.PublicStats.Snapshot()
	// first request issued a challenge; the bad proof served another 402
	if snap.Challenges != 2 || snap.UnlocksPoW != 0 || snap.UnlocksLightning != 0 {
		t.Fatalf("%+v", snap)
	}
}

func TestStatsPassReuseDoesNotRecount(t *testing.T) {
	f := newFixture(t)
	f.withStats()
	ch := f.challenge(t, "/premium/a")
	req := httptest.NewRequest(http.MethodGet, "/premium/a", nil)
	req.Header.Set("Authorization", f.pay(t, ch))
	req.Header.Set(RedeemHeader, redeemCookie)
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("redeem cookie: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no pass cookie")
	}
	snap := f.gate.opt.PublicStats.Snapshot()
	if snap.UnlocksLightning != 1 || snap.SatsReceived != 10 {
		t.Fatalf("after redeem: %+v", snap)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/premium/a", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	f.gate.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("pass reuse: %d %s", rec2.Code, rec2.Body.String())
	}
	snap2 := f.gate.opt.PublicStats.Snapshot()
	if snap2.UnlocksLightning != 1 || snap2.SatsReceived != 10 || snap2.Challenges != snap.Challenges {
		t.Fatalf("pass reuse recounted: before=%+v after=%+v", snap, snap2)
	}
}

func TestStatsClaimCookieCountsOnce(t *testing.T) {
	f := newFixture(t)
	f.withStats()
	ch := f.challenge(t, "/premium/article")
	if _, err := f.ln.Pay(ch.L402.Invoice); err != nil {
		t.Fatal(err)
	}
	rec := f.claim(ch.L402.Token, redeemCookie)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("claim redeem: %d %s", rec.Code, rec.Body.String())
	}
	snap := f.gate.opt.PublicStats.Snapshot()
	if snap.UnlocksLightning != 1 || snap.SatsReceived != 10 {
		t.Fatalf("claim should count the payment: %+v", snap)
	}
	rec2 := f.claim(ch.L402.Token, redeemCookie)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("replay claim: %d %s", rec2.Code, rec2.Body.String())
	}
	snap2 := f.gate.opt.PublicStats.Snapshot()
	if snap2.UnlocksLightning != 1 || snap2.SatsReceived != 10 {
		t.Fatalf("spent claim recounted: %+v", snap2)
	}
}

func TestStatsLast24hRollsOff(t *testing.T) {
	f := newFixture(t)
	s := f.withStats()
	s.Observe(Event{Time: f.now, Outcome: OutcomePaid, Sats: 7})
	s.Observe(Event{Time: f.now, Outcome: OutcomePoW})
	s.Observe(Event{Time: f.now, Outcome: OutcomeChallenged})
	f.now = f.now.Add(24*time.Hour + time.Minute)
	snap := s.Snapshot()
	if snap.Challenges != 1 || snap.UnlocksPoW != 1 || snap.UnlocksLightning != 1 || snap.SatsReceived != 7 {
		t.Fatalf("totals should remain: %+v", snap)
	}
	if snap.Last24h != (PublicWindow{}) {
		t.Fatalf("window should be empty: %+v", snap.Last24h)
	}
	s.Observe(Event{Time: f.now, Outcome: OutcomePaid, Sats: 3})
	snap = s.Snapshot()
	if snap.SatsReceived != 10 || snap.UnlocksLightning != 2 {
		t.Fatalf("totals: %+v", snap)
	}
	if snap.Last24h != (PublicWindow{UnlocksLightning: 1, SatsReceived: 3}) {
		t.Fatalf("window: %+v", snap.Last24h)
	}
}

func TestStatsCacheReusedUntilExpiry(t *testing.T) {
	f := newFixture(t)
	s := f.withStats()
	first, err := s.cachedJSON()
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second) // still within the cache TTL
	second, err := s.cachedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || &first[0] != &second[0] {
		t.Fatal("expected the same cached body to be reused")
	}

	s.Observe(Event{Time: f.now, Outcome: OutcomePoW})
	rec := getStats(t, f.gate, http.MethodGet)
	got := decodeStats(t, rec)
	if got.UnlocksPoW != 1 {
		t.Fatalf("observe should invalidate the cache: %+v", got)
	}

	body, err := s.cachedJSON()
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(statsCacheFor + time.Millisecond)
	fresh, err := s.cachedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || &body[0] == &fresh[0] {
		t.Fatal("expected a new body after the cache TTL")
	}
}

func TestStatsPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0).UTC()
	s := NewPublicStats(now)
	s.now = func() time.Time { return now }
	s.Observe(Event{Time: now, Outcome: OutcomeChallenged})
	s.Observe(Event{Time: now, Outcome: OutcomePoW})
	s.Observe(Event{Time: now, Outcome: OutcomePaid, Sats: 4})
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	// A second save with no changes must not be required to work, and
	// the file must exist.
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPublicStats(dir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	loaded.now = func() time.Time { return now.Add(time.Hour) }
	got := loaded.Snapshot()
	if !got.Since.Equal(now) {
		t.Fatalf("since %v want %v", got.Since, now)
	}
	want := PublicWindow{Challenges: 1, UnlocksPoW: 1, UnlocksLightning: 1, SatsReceived: 4}
	if got.Challenges != want.Challenges || got.UnlocksPoW != want.UnlocksPoW || got.UnlocksLightning != want.UnlocksLightning || got.SatsReceived != want.SatsReceived {
		t.Fatalf("totals %+v want %+v", got, want)
	}
	if got.Last24h != want {
		t.Fatalf("window %+v want %+v", got.Last24h, want)
	}

	// Missing file is a first run.
	empty, err := LoadPublicStats(filepath.Join(dir, "missing-dir-ok"), now)
	if err != nil {
		// Load does not create the dir; missing file in a missing dir is an error
		// only if we try to read it. LoadPublicStats on a missing dir: ReadFile
		// returns NotExist, which we treat as first run.
		t.Fatalf("missing: %v", err)
	}
	_ = empty

	if err := os.WriteFile(filepath.Join(dir, statsFileName), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicStats(dir, now); err == nil {
		t.Fatal("corrupt file should fail")
	}
}

func TestStatsConcurrentObserveAndRead(t *testing.T) {
	s := NewPublicStats(time.Unix(1_800_000_000, 0))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Observe(Event{Time: s.now(), Outcome: OutcomeChallenged})
				s.Observe(Event{Time: s.now(), Outcome: OutcomePoW})
				s.Observe(Event{Time: s.now(), Outcome: OutcomePaid, Sats: 1})
				_ = s.Snapshot()
				req := httptest.NewRequest(http.MethodGet, StatsPath, nil)
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, req)
			}
		}()
	}
	wg.Wait()
	got := s.Snapshot()
	if got.Challenges != 8*200 || got.UnlocksPoW != 8*200 || got.UnlocksLightning != 8*200 || got.SatsReceived != 8*200 {
		t.Fatalf("%+v", got)
	}
}

func TestStatsIgnoresFreeBlockedAndRateLimits(t *testing.T) {
	s := NewPublicStats(time.Unix(1_800_000_000, 0))
	for _, o := range []Outcome{OutcomeFree, OutcomeBlocked, OutcomeRateLimited, OutcomeBusy} {
		s.Observe(Event{Time: s.now(), Outcome: o, Sats: 99})
	}
	got := s.Snapshot()
	if got.Challenges != 0 || got.UnlocksPoW != 0 || got.UnlocksLightning != 0 || got.SatsReceived != 0 {
		t.Fatalf("%+v", got)
	}
}
