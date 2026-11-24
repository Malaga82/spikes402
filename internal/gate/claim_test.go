package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/internal/lightning"
)

type countingLookup struct {
	inner lightning.IncomingLookup
	n     atomic.Int32
	block chan struct{} // if non-nil, each call waits for a receive
}

func (c *countingLookup) LookupIncoming(ctx context.Context, h [32]byte) (lightning.IncomingPayment, error) {
	c.n.Add(1)
	if c.block != nil {
		<-c.block
	}
	return c.inner.LookupIncoming(ctx, h)
}

func (f *fixture) claim(token, redeem string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, ClaimPath, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if redeem != "" {
		req.Header.Set(RedeemHeader, redeem)
		req.Method = http.MethodPost
	}
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	return rec
}

func claimStatus(t *testing.T, rec *httptest.ResponseRecorder) (int, claimBody) {
	t.Helper()
	var b claimBody
	if rec.Body.Len() > 0 && strings.Contains(rec.Header().Get("Content-Type"), "json") {
		if err := json.NewDecoder(rec.Body).Decode(&b); err != nil && err != io.EOF {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, b
}

func TestClaimUnpaidPaidAndCookie(t *testing.T) {
	f := newFixture(t)
	ch := f.challenge(t, "/premium/article?x=1")
	if ch.L402 == nil || ch.L402.Claim != ClaimPath {
		t.Fatalf("402 body should advertise the claim path: %+v", ch.L402)
	}

	rec := f.claim(ch.L402.Token, "")
	code, body := claimStatus(t, rec)
	if code != http.StatusAccepted || body.Status != "unpaid" || body.Preimage != "" {
		t.Fatalf("unpaid: %d %+v", code, body)
	}

	preimage, err := f.ln.Pay(ch.L402.Invoice)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(lookupUnpaidTTL + time.Millisecond) // unpaid lookups are cached briefly
	rec = f.claim(ch.L402.Token, "")
	code, body = claimStatus(t, rec)
	if code != http.StatusOK || body.Status != "paid" || !strings.EqualFold(body.Preimage, preimage) {
		t.Fatalf("paid json: %d %+v, want %s", code, body, preimage)
	}

	// Redeem cookie issues a pass bound to the original page, not to /claim.
	rec = f.claim(ch.L402.Token, redeemCookie)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cookie: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no pass cookie")
	}
	// The pass unlocks the original resource.
	req := httptest.NewRequest(http.MethodGet, "/premium/article?x=1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	got := httptest.NewRecorder()
	f.gate.ServeHTTP(got, req)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "content of /premium/article") {
		t.Fatalf("pass did not unlock the page: %d %s", got.Code, got.Body.String())
	}

	// Replay: the token is spent.
	rec = f.claim(ch.L402.Token, redeemCookie)
	code, body = claimStatus(t, rec)
	if code != http.StatusConflict || body.Status != "spent" {
		t.Fatalf("replay: %d %+v", code, body)
	}
}

func TestClaimWrongTokenExpiredAndNoInvoice(t *testing.T) {
	f := newFixture(t)
	ch := f.challenge(t, "/premium/article")

	if rec := f.claim("", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: %d", rec.Code)
	}
	if rec := f.claim("not-a-token", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: %d", rec.Code)
	}
	// A third party who only has the invoice, not the signed token, cannot claim.
	if rec := f.claim(ch.L402.Invoice, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("invoice as token: %d", rec.Code)
	}

	f.now = f.now.Add(2 * time.Minute) // past ChallengeTTL (1 minute in tests? fixture is time.Minute)
	rec := f.claim(ch.L402.Token, "")
	code, body := claimStatus(t, rec)
	if code != http.StatusGone || body.Status != "expired" {
		t.Fatalf("expired: %d %+v", code, body)
	}

	// PoW-only: no invoice, no claim.
	f2 := newFixture(t)
	f2.gate.node.backend = brokenNode{}
	powCh := f2.challenge(t, "/premium/article")
	if powCh.L402 != nil {
		t.Fatal("expected no invoice")
	}
	rec = f2.claim(powCh.PoW.Challenge, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pow-only claim: %d %s", rec.Code, rec.Body.String())
	}
}

func TestClaimReservedUnderProtectAll(t *testing.T) {
	f := newFixture(t)
	f.gate.opt.Next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("claim request reached the origin") })
	f.gate.live.Store(&Settings{PriceSats: 10, Protect: []string{"/**"}, PoW: f.gate.opt.PoW, ChallengesPerMinute: 100})
	ch := f.challenge(t, "/premium/article")
	rec := f.claim(ch.L402.Token, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPut, ClaimPath, nil)
	rec = httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", rec.Code)
	}
}

func TestClaimLookupCoalescedAndCached(t *testing.T) {
	f := newFixture(t)
	counter := &countingLookup{inner: f.ln, block: make(chan struct{})}
	f.gate.invoices.lookup = counter
	ch := f.challenge(t, "/premium/article")

	const n = 12
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = f.claim(ch.L402.Token, "").Code
		}(i)
	}
	// Release the blocked lookup once; every goroutine should share it.
	time.Sleep(20 * time.Millisecond)
	close(counter.block)
	wg.Wait()
	if got := counter.n.Load(); got != 1 {
		t.Fatalf("concurrent unpaid lookups: %d, want 1", got)
	}
	for i, c := range codes {
		if c != http.StatusAccepted {
			t.Fatalf("claim %d: %d", i, c)
		}
	}

	// Within the unpaid TTL, another poll is served from the cache.
	if rec := f.claim(ch.L402.Token, ""); rec.Code != http.StatusAccepted {
		t.Fatalf("cached: %d", rec.Code)
	}
	if got := counter.n.Load(); got != 1 {
		t.Fatalf("cached lookup must not hit the node again: %d", got)
	}

	f.now = f.now.Add(lookupUnpaidTTL + time.Millisecond)
	if rec := f.claim(ch.L402.Token, ""); rec.Code != http.StatusAccepted {
		t.Fatalf("after ttl: %d", rec.Code)
	}
	if got := counter.n.Load(); got != 2 {
		t.Fatalf("after ttl: lookups %d, want 2", got)
	}

	// Once paid, the result is cached until the token expires (no more node calls).
	if _, err := f.ln.Pay(ch.L402.Invoice); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(lookupUnpaidTTL + time.Millisecond)
	if code, body := claimStatus(t, f.claim(ch.L402.Token, "")); code != http.StatusOK || body.Status != "paid" {
		t.Fatalf("paid: %d %+v", code, body)
	}
	hits := counter.n.Load()
	f.now = f.now.Add(time.Second)
	if code, _ := claimStatus(t, f.claim(ch.L402.Token, "")); code != http.StatusOK {
		t.Fatalf("paid cache: %d", code)
	}
	if counter.n.Load() != hits {
		t.Fatalf("paid result was looked up again")
	}
}

func TestClaimRateLimit(t *testing.T) {
	f := newFixture(t)
	ch := f.challenge(t, "/premium/article")
	var limited int
	for i := 0; i < claimPerMinute+5; i++ {
		if f.claim(ch.L402.Token, "").Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("expected the per-IP claim limiter to fire")
	}
}

func TestClaimPageHasHashedScript(t *testing.T) {
	f := newFixture(t)
	rec := f.get("/premium/article", "", "text/html")
	body := rec.Body.String()
	for _, want := range []string{"Open in wallet", `id="pay-wait"`, `id="open-wallet"`, `id="pay-msg"`, `href="lightning:`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if !strings.Contains(body, invoiceJS) {
		t.Fatal("invoice script not in the page")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	want := "sha256-" + invoiceHash
	if !strings.Contains(csp, want) {
		t.Fatalf("CSP %q, want hash %s", csp, want)
	}
	if strings.Contains(body, "<script src") {
		t.Error("external script")
	}
}

func TestClaimGlobalLookupBudget(t *testing.T) {
	f := newFixture(t)
	counter := &countingLookup{inner: f.ln}
	f.gate.invoices.lookup = counter
	// Many different invoices: the node sees at most lookupPerMin of them
	// in one minute. Use distinct pages so each offer has its own hash.
	// (pending key includes the path.)
	for i := 0; i < 8; i++ {
		ch := f.challenge(t, "/premium/p"+string(rune('a'+i)))
		if ch.L402 == nil {
			t.Fatal("no invoice")
		}
		f.claim(ch.L402.Token, "")
	}
	if n := counter.n.Load(); n < 1 || int(n) > lookupPerMin {
		t.Fatalf("lookups %d", n)
	}
}

// The lookup cache is bounded: distinct payment hashes cannot grow it
// without limit, expired results are dropped, and a full cache still works.
func TestInvoiceCacheIsBounded(t *testing.T) {
	c := newInvoiceCache(lightning.NewFake())
	if c.lookup == nil {
		t.Skip("fake backend has no lookup")
	}
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < lookupCacheMax+500; i++ {
		c.window = time.Time{} // lift the per-minute cap for this test
		h := fmt.Sprintf("%064x", i)
		if _, err := c.get(h, now.Add(time.Hour), now); err != nil && err != lightning.ErrNotFound {
			t.Fatal(err)
		}
		if n := len(c.cache); n > lookupCacheMax {
			t.Fatalf("cache holds %d entries, cap %d", n, lookupCacheMax)
		}
		now = now.Add(time.Millisecond)
	}
	// Far in the future everything has expired; the next insert sweeps.
	now = now.Add(time.Hour)
	c.window = time.Time{}
	if _, err := c.get(fmt.Sprintf("%064x", 1<<40), now.Add(time.Hour), now); err != nil && err != lightning.ErrNotFound {
		t.Fatal(err)
	}
	if n := len(c.cache); n > 1 && n >= lookupCacheMax {
		t.Fatalf("expired entries were not swept: %d left", n)
	}
}

// A payment seen through the claim endpoint is counted on the paid page
// (named by the 402 page's Referer, believed only when it hashes to the
// token's page), with its price.
func TestClaimObservedOnThePaidPage(t *testing.T) {
	for _, c := range []struct{ referer, want string }{
		{"http://example.com/premium/article?x=1", "GET /premium/article?x=1"},
		{"http://example.com/premium/other", "POST " + ClaimPath}, // not the token's page
		{"", "POST " + ClaimPath},
	} {
		f := newFixture(t)
		rec := &recorder{}
		f.gate.opt.Observer = rec.observe
		ch := f.challenge(t, "/premium/article?x=1")
		if _, err := f.ln.Pay(ch.L402.Invoice); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, ClaimPath, nil)
		req.Header.Set("Authorization", "Bearer "+ch.L402.Token)
		req.Header.Set(RedeemHeader, redeemCookie)
		if c.referer != "" {
			req.Header.Set("Referer", c.referer)
		}
		w := httptest.NewRecorder()
		f.gate.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%q: claim %d", c.referer, w.Code)
		}
		e := rec.events[len(rec.events)-1]
		if e.Outcome != OutcomePaid || e.Resource != c.want || e.Price != ch.PriceSats {
			t.Errorf("%q: event %s %q price %d, want %q price %d", c.referer, e.Outcome, e.Resource, e.Price, c.want, ch.PriceSats)
		}
	}
}
