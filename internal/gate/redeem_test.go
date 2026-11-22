package gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/Choffolo/spikes402/internal/lightning"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

// send sends a GET (or method) with extra headers and cookies.
func (f *fixture) send(method, target string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	return rec
}

// payFor gets a challenge for method+target and pays it.
func (f *fixture) payFor(t *testing.T, method, target string) string {
	t.Helper()
	rec := f.send(method, target, nil)
	var b challengeBody
	if rec.Code != http.StatusPaymentRequired || json.NewDecoder(rec.Body).Decode(&b) != nil {
		t.Fatalf("%s %s: got %d, want a 402", method, target, rec.Code)
	}
	return f.pay(t, b)
}

func cookieNamed(rec *httptest.ResponseRecorder, prefix string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	return nil
}

// originCounter replaces the origin with one that counts calls and records
// whether anything of ours leaked to it.
func originCounter(t *testing.T, f *fixture, status func(n int) int) *int {
	t.Helper()
	n := 0
	f.gate.opt.Next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.Header.Get("Authorization") != "" || r.Header.Get(RedeemHeader) != "" || strings.Contains(r.Header.Get("Cookie"), "spikes402") {
			t.Errorf("our headers leaked to the origin: %v", r.Header)
		}
		if st := status(n); st != 0 {
			w.WriteHeader(st)
			return
		}
		w.Write([]byte("content of " + r.URL.Path))
	})
	return &n
}

func TestPageUsesSafeElementIDAndChecksWallet(t *testing.T) {
	f := newFixture(t)
	rec := f.get("/premium/a", "", "text/html")
	body := rec.Body.String()
	if strings.Contains(body, `id="webln"`) || !strings.Contains(body, `id="wallet-box"`) {
		t.Fatal("the page must not use id=webln (it would become window.webln)")
	}
	if !strings.Contains(weblnJS, `typeof w.enable!=="function"`) || strings.Contains(weblnJS, "document.write") {
		t.Fatal("script must check the wallet and navigate instead of document.write")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("CSP changed: %q", csp)
	}
}

func TestPassUnlocksOnePageBriefly(t *testing.T) {
	f := newFixture(t)
	calls := originCounter(t, f, func(int) int { return 0 })
	auth := f.pay(t, f.challenge(t, "/premium/a"))

	rec := f.send("GET", "/premium/a", map[string]string{"Authorization": auth, RedeemHeader: "cookie"})
	if rec.Code != http.StatusNoContent || *calls != 0 {
		t.Fatalf("redeem: got %d, origin calls %d (want 204 and none)", rec.Code, *calls)
	}
	pass := cookieNamed(rec, passPrefix)
	if pass == nil || !pass.HttpOnly || pass.SameSite != http.SameSiteStrictMode || pass.MaxAge != int(f.gate.opt.PassTTL.Seconds()) || pass.Secure {
		t.Fatalf("bad pass cookie: %+v", pass)
	}

	// Navigation and reloads within the lifetime: served, nothing paid again.
	for i := 0; i < 2; i++ {
		if rec := f.send("GET", "/premium/a", nil, pass); rec.Code != http.StatusOK || rec.Body.String() != "content of /premium/a" {
			t.Fatalf("with pass (try %d): %d %q", i, rec.Code, rec.Body.String())
		}
	}

	// It unlocks that page only.
	if rec := f.send("GET", "/premium/b", nil, pass); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("other page: %d", rec.Code)
	}
	renamed := &http.Cookie{Name: passName(hashResource("GET /premium/b")), Value: pass.Value}
	if rec := f.send("GET", "/premium/b", nil, renamed); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("pass presented for another page: %d", rec.Code)
	}
	if rec := f.send("HEAD", "/premium/a", nil, pass); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("another method: %d", rec.Code)
	}
	// The token behind it is spent, and a pass is never accepted as a token.
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("token reused: %d", rec.Code)
	}
	fake := f.pay(t, f.challenge(t, "/premium/a")) // a fresh L402 header, with the pass as its token
	_, preimage, _ := strings.Cut(fake, ":")
	if rec := f.get("/premium/a", "L402 "+pass.Value+":"+preimage, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("pass accepted as a token: %d", rec.Code)
	}

	// It ends.
	f.now = f.now.Add(f.gate.opt.PassTTL + time.Second)
	if rec := f.send("GET", "/premium/a", nil, pass); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expired pass: %d", rec.Code)
	}
}

func TestPassOnlyAfterValidProofAndOnlyForGET(t *testing.T) {
	f := newFixture(t)
	calls := originCounter(t, f, func(int) int { return 0 })
	// no proof, wrong proof: a normal 402, no cookie
	for _, auth := range []string{"", "L402 junk:00"} {
		rec := f.send("GET", "/premium/a", map[string]string{"Authorization": auth, RedeemHeader: "cookie"})
		if rec.Code != http.StatusPaymentRequired || cookieNamed(rec, passPrefix) != nil {
			t.Fatalf("auth %q: %d", auth, rec.Code)
		}
	}
	// the request header alone does nothing
	if rec := f.send("GET", "/premium/a", map[string]string{RedeemHeader: "cookie"}); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("header alone: %d", rec.Code)
	}
	// a valid proof on a POST is delivered, never turned into a pass
	auth := f.payFor(t, "POST", "/premium/a")
	req := httptest.NewRequest("POST", "/premium/a", nil)
	req.Header.Set("Authorization", auth)
	req.Header.Set(RedeemHeader, "cookie")
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || *calls != 1 || cookieNamed(rec, passPrefix) != nil {
		t.Fatalf("POST: %d, origin calls %d", rec.Code, *calls)
	}
}

func TestPassCookieIsSecureOverHTTPS(t *testing.T) {
	f := newFixture(t)
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	req := httptest.NewRequest("GET", "/premium/a", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Authorization", auth)
	req.Header.Set(RedeemHeader, "cookie")
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if c := cookieNamed(rec, passPrefix); rec.Code != 204 || c == nil || !c.Secure {
		t.Fatalf("got %d %+v", rec.Code, c)
	}
}

// Redeeming does not create invoices or offers.

func TestPassTTLIsConfigurable(t *testing.T) {
	f := newFixture(t)
	f.gate.opt.PassTTL = 5 * time.Second
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	rec := f.send("GET", "/premium/a", map[string]string{"Authorization": auth, RedeemHeader: "cookie"})
	pass := cookieNamed(rec, passPrefix)
	if rec.Code != http.StatusNoContent || pass == nil || pass.MaxAge != 5 {
		t.Fatalf("5s pass: %d %+v", rec.Code, pass)
	}
	f.now = f.now.Add(4 * time.Second)
	if rec := f.send("GET", "/premium/a", nil, pass); rec.Code != http.StatusOK {
		t.Fatalf("still valid: %d", rec.Code)
	}
	f.now = f.now.Add(2 * time.Second)
	if rec := f.send("GET", "/premium/a", nil, pass); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expired at 6s: %d", rec.Code)
	}
}

func TestPassTTLZeroIssuesNoCookie(t *testing.T) {
	f := newFixture(t)
	f.gate.opt.PassTTL = 0
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	rec := f.send("GET", "/premium/a", map[string]string{"Authorization": auth, RedeemHeader: "cookie"})
	if rec.Code != http.StatusNoContent || cookieNamed(rec, passPrefix) != nil {
		t.Fatalf("zero ttl should be 204 with no cookie: %d %+v", rec.Code, rec.Result().Cookies())
	}
	if rec := f.get("/premium/a", "", ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("next request must pay again: %d", rec.Code)
	}
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("spent token is still spent: %d", rec.Code)
	}
}

func TestRedeemCreatesNoInvoices(t *testing.T) {
	f := newFixture(t)
	cb := &countingBackend{Backend: f.ln}
	f.gate.node = newNodeGuard(cb, 6000)
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	before := cb.n
	rec := f.send("GET", "/premium/a", map[string]string{"Authorization": auth, RedeemHeader: "cookie"})
	pass := cookieNamed(rec, passPrefix)
	f.send("GET", "/premium/a", nil, pass)
	f.send("GET", "/premium/a", nil, pass)
	if cb.n != before {
		t.Fatalf("%d invoices created while redeeming", cb.n-before)
	}
}

// Origin errors give a GET back its token, a few times and briefly; never twice delivered.
func TestOriginErrorGivesTokenBack(t *testing.T) {
	f := newFixture(t)
	calls := originCounter(t, f, func(n int) int {
		if n == 1 {
			return http.StatusBadGateway
		}
		return 0
	})
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusBadGateway {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusOK {
		t.Fatalf("retry after origin error: %d", rec.Code)
	}
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errReplay.Error()) {
		t.Fatalf("after delivery: %d (origin calls %d)", rec.Code, *calls)
	}
}

func TestOriginErrorRetriesAreBounded(t *testing.T) {
	f := newFixture(t)
	calls := originCounter(t, f, func(int) int { return http.StatusServiceUnavailable })
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	for i := 0; i < 6; i++ {
		f.get("/premium/a", auth, "")
	}
	if *calls != maxRetries+1 {
		t.Fatalf("origin called %d times, want %d", *calls, maxRetries+1)
	}

	// the window
	f2 := newFixture(t)
	calls2 := originCounter(t, f2, func(n int) int {
		if n == 1 {
			return http.StatusBadGateway
		}
		return 0
	})
	auth2 := f2.pay(t, f2.challenge(t, "/premium/a"))
	f2.get("/premium/a", auth2, "")
	f2.now = f2.now.Add(retryWindow + time.Second)
	if rec := f2.get("/premium/a", auth2, ""); rec.Code != http.StatusPaymentRequired || *calls2 != 1 {
		t.Fatalf("after the window: %d, origin calls %d", rec.Code, *calls2)
	}
}

func TestNoSecondTryForPOSTOrWhileInFlight(t *testing.T) {
	f := newFixture(t)
	calls := originCounter(t, f, func(int) int { return http.StatusBadGateway })
	auth := f.payFor(t, "POST", "/premium/a")
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/premium/a", nil)
		req.Header.Set("Authorization", auth)
		f.gate.ServeHTTP(httptest.NewRecorder(), req)
	}
	if *calls != 1 {
		t.Fatalf("a failed POST was retried: origin calls %d", *calls)
	}

	// A request that is still being served keeps the token spent.
	f = newFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	f.gate.opt.Next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Write([]byte("ok"))
	})
	auth = f.pay(t, f.challenge(t, "/premium/a"))
	done := make(chan int)
	go func() { done <- f.get("/premium/a", auth, "").Code }()
	<-started
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("duplicate while redeeming: %d", rec.Code)
	}
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first request: %d", code)
	}
}

// A dead origin (transport error, answered 502 by the proxy) counts too.
func TestDeadOriginGivesTokenBack(t *testing.T) {
	f := newFixture(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(dead.URL)
	dead.Close()
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(u) }, ErrorLog: nil}
	f.gate.opt.Next = proxy
	auth := f.pay(t, f.challenge(t, "/premium/a"))
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusBadGateway {
		t.Fatalf("dead origin: %d", rec.Code)
	}
	f.gate.opt.Next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("back")) })
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusOK {
		t.Fatalf("retry once the origin is back: %d", rec.Code)
	}
}

func TestSpentSetRelease(t *testing.T) {
	s := newSpentSet()
	now := time.Unix(0, 0)
	exp := now.Add(time.Hour)
	s.release("x", now) // unknown id: nothing
	if s.use("x", exp, now) != nil {
		t.Fatal("first use")
	}
	s.release("x", now)
	if s.has("x") {
		t.Fatal("released token still counted as spent")
	}
	if s.use("x", exp, now) != nil || s.use("x", exp, now) != errReplay {
		t.Fatal("after release: one more use, then replay")
	}
	s.release("x", now)
	s.release("x", now) // already released: not counted twice
	if s.use("x", exp, now) != nil {
		t.Fatal("second retry")
	}
}

type countingBackend struct {
	lightning.Backend
	n int
}

func (c *countingBackend) CreateInvoice(ctx context.Context, a int64, m string, e time.Duration) (lightning.Invoice, error) {
	c.n++
	return c.Backend.CreateInvoice(ctx, a, m, e)
}
