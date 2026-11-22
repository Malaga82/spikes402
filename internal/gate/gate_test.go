package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/internal/lightning"
	"github.com/Choffolo/spikes402/pow"
)

const testDifficulty = 8 // tiny, so tests stay fast

type fixture struct {
	gate *Gate
	ln   *lightning.Fake
	now  time.Time
	pow  pow.Params // puzzle handed out, whatever the price
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{ln: lightning.NewFake(), now: time.Unix(1_800_000_000, 0),
		pow: pow.Params{Algorithm: pow.SHA256d, Difficulty: testDifficulty}}
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization header leaked to the origin")
		}
		w.Write([]byte("content of " + r.URL.Path))
	})
	f.gate = New(Options{
		PriceSats:    10,
		Protect:      []string{"/premium/**", "/*.pdf"},
		PoW:          func(int64) pow.Params { return f.pow },
		ChallengeTTL: time.Minute,
		PassTTL:      DefaultPassTTL,
		SecretKey:    []byte(strings.Repeat("s", 32)),
		Lightning:    f.ln,
		Next:         origin,

		ChallengesPerMinute:  1000,
		MaxInvoicesPerMinute: 6000,
		MaxPendingInvoices:   1000,
	})
	f.gate.now = func() time.Time { return f.now }
	return f
}

// get performs a request and returns the recorder.
func (f *fixture) get(target, auth, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	return rec
}

// challenge requests target without credentials and decodes the 402 body.
func (f *fixture) challenge(t *testing.T, target string) challengeBody {
	t.Helper()
	rec := f.get(target, "", "")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("%s: got %d, want 402", target, rec.Code)
	}
	var b challengeBody
	if err := json.NewDecoder(rec.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) pay(t *testing.T, b challengeBody) string {
	t.Helper()
	preimage, err := f.ln.Pay(b.L402.Invoice)
	if err != nil {
		t.Fatal(err)
	}
	return "L402 " + b.L402.Token + ":" + preimage
}

func solve(t *testing.T, b challengeBody) string {
	t.Helper()
	nonce, err := params(b).Solve(context.Background(), b.PoW.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return "PoW " + b.PoW.Challenge + ":" + strconv.FormatUint(nonce, 10)
}

func params(b challengeBody) pow.Params {
	return pow.Params{Algorithm: b.PoW.Algorithm, Difficulty: b.PoW.Difficulty, MemoryMiB: b.PoW.MemoryMiB}
}

func TestUnprotectedPassthrough(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/", "/blog/post", "/premiumfoo", "/dir/file.pdf"} {
		rec := f.get(p, "", "")
		if rec.Code != http.StatusOK || rec.Body.String() != "content of "+p {
			t.Errorf("%s: got %d %q", p, rec.Code, rec.Body.String())
		}
	}
}

func TestIssues402(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/premium", "/premium/article", "/report.pdf"} {
		rec := f.get(p, "", "")
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("%s: got %d, want 402", p, rec.Code)
		}
		auth := rec.Header().Values("WWW-Authenticate")
		if len(auth) != 2 ||
			!strings.HasPrefix(auth[0], `L402 macaroon="`) || !strings.Contains(auth[0], `, invoice="lnfake`) ||
			!strings.HasPrefix(auth[1], `PoW challenge="`) || !strings.Contains(auth[1], `difficulty="8"`) {
			t.Fatalf("%s: bad WWW-Authenticate: %q", p, auth)
		}
	}
	b := f.challenge(t, "/premium/article?x=1")
	if b.PriceSats != 10 || b.Resource != "GET /premium/article?x=1" || b.L402 == nil || b.PoW.Difficulty != testDifficulty {
		t.Fatalf("unexpected body: %+v", b)
	}
}

func TestHTMLPage(t *testing.T) {
	f := newFixture(t)
	rec := f.get("/premium/article", "", "text/html,application/xhtml+xml")
	body := rec.Body.String()
	if rec.Code != http.StatusPaymentRequired ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(body, "data:image/png;base64,") ||
		!strings.Contains(body, "lnfake10sat1") {
		t.Fatalf("bad HTML page (%d): %s", rec.Code, body)
	}
	invoice, token := weblnAttrs(t, body)
	if !strings.HasPrefix(invoice, "lnfake") || token == "" ||
		!strings.Contains(body, `id="webln-pay"`) ||
		!strings.Contains(body, "Pay with one click") ||
		!strings.Contains(body, "window.webln") ||
		!strings.Contains(body, "w.enable(") ||
		!strings.Contains(body, "w.sendPayment(") ||
		!strings.Contains(body, `Authorization:"L402 "`) {
		t.Fatalf("missing WebLN markup: %s", body)
	}
	// Every script in the page is exactly what the CSP hash covers.
	csp := rec.Header().Get("Content-Security-Policy")
	scripts := inlineScripts(body)
	if len(scripts) != 3 || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("want hashed inline scripts and connect-src 'self', got %d, CSP %q", len(scripts), csp)
	}
	for _, js := range scripts {
		if want := "sha256-" + base64.StdEncoding.EncodeToString(sha256Sum([]byte(js))); !strings.Contains(csp, want) {
			t.Fatalf("CSP %q, want hash %s", csp, want)
		}
	}
	// Same invoice and token as the machine-readable challenge: no new invoice.
	l402 := rec.Header().Values("WWW-Authenticate")[0]
	if !strings.Contains(l402, `macaroon="`+token+`"`) || !strings.Contains(l402, `invoice="`+invoice+`"`) {
		t.Fatalf("button does not match WWW-Authenticate: %s", l402)
	}
	// The credential path the script uses (Authorization: L402 token:preimage)
	// unlocks the page, including when the browser asks for HTML.
	auth := f.pay(t, challengeBody{L402: &l402Offer{Token: token, Invoice: invoice}})
	got := f.get("/premium/article", auth, "text/html")
	if got.Code != http.StatusOK || got.Body.String() != "content of /premium/article" {
		t.Fatalf("redeem via the page credential: %d %q", got.Code, got.Body.String())
	}
}

func weblnAttrs(t *testing.T, body string) (invoice, token string) {
	t.Helper()
	for _, name := range []string{"data-invoice", "data-token"} {
		key := name + `="`
		i := strings.Index(body, key)
		if i < 0 {
			t.Fatalf("%s missing", name)
		}
		i += len(key)
		j := strings.Index(body[i:], `"`)
		if name == "data-invoice" {
			invoice = body[i : i+j]
		} else {
			token = body[i : i+j]
		}
	}
	return
}

func TestValidPayment(t *testing.T) {
	f := newFixture(t)
	auth := f.pay(t, f.challenge(t, "/premium/article"))
	rec := f.get("/premium/article", auth, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "content of /premium/article" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestValidPoW(t *testing.T) {
	f := newFixture(t)
	auth := solve(t, f.challenge(t, "/premium/article"))
	if rec := f.get("/premium/article", auth, ""); rec.Code != http.StatusOK {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestWrongPreimage(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	wrong := "L402 " + b.L402.Token + ":" + strings.Repeat("ab", 32)
	rec := f.get("/premium/article", wrong, "")
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errBadProof.Error()) {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	// A failed attempt must not burn the token: paying properly still works.
	if rec := f.get("/premium/article", f.pay(t, b), ""); rec.Code != http.StatusOK {
		t.Fatalf("after wrong attempt: got %d", rec.Code)
	}
}

func TestWrongPoW(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	var bad uint64
	for params(b).Check(b.PoW.Challenge, bad) {
		bad++
	}
	rec := f.get("/premium/article", "PoW "+b.PoW.Challenge+":"+strconv.FormatUint(bad, 10), "")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestReplay(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	// The same token can be redeemed once, by either route.
	pay, work := f.pay(t, b), solve(t, b)
	if rec := f.get("/premium/article", pay, ""); rec.Code != http.StatusOK {
		t.Fatalf("first use: got %d", rec.Code)
	}
	for _, auth := range []string{pay, work} {
		rec := f.get("/premium/article", auth, "")
		if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errReplay.Error()) {
			t.Fatalf("replay: got %d %q", rec.Code, rec.Body.String())
		}
	}
}

// A paid invoice stays usable once even if the offer's puzzle was used
// first (by the same client, or anyone who saw the token).
func TestPaidInvoiceRedeemableAfterWork(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	pay, work := f.pay(t, b), solve(t, b)
	for i, want := range []int{http.StatusOK, http.StatusPaymentRequired, http.StatusOK, http.StatusPaymentRequired} {
		auth := work
		if i >= 2 {
			auth = pay
		}
		if rec := f.get("/premium/article", auth, ""); rec.Code != want {
			t.Fatalf("step %d: got %d, want %d", i, rec.Code, want)
		}
	}
}

func TestExpiredChallenge(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	pay, work := f.pay(t, b), solve(t, b)
	f.now = f.now.Add(time.Minute) // TTL is one minute
	for _, auth := range []string{pay, work} {
		rec := f.get("/premium/article", auth, "")
		if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errExpired.Error()) {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
	}
}

func TestBoundToResource(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/cheap")
	auth := f.pay(t, b)
	for _, target := range []string{"/premium/expensive", "/premium/cheap?page=2"} {
		rec := f.get(target, auth, "")
		if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errWrongTarget.Error()) {
			t.Fatalf("%s: got %d %q", target, rec.Code, rec.Body.String())
		}
	}
}

func TestForgedToken(t *testing.T) {
	f := newFixture(t)
	b := f.challenge(t, "/premium/article")
	other := newFixture(t) // same code, different secret key
	other.gate.sign = signer{[]byte(strings.Repeat("x", 32))}
	forged := other.challenge(t, "/premium/article")
	for _, auth := range []string{
		"L402 " + b.L402.Token + "x:" + strings.Repeat("00", 32), // tampered
		other.pay(t, forged), // signed with another key
		"Bearer something",   // not our scheme
		"L402 garbage",       // malformed
	} {
		if rec := f.get("/premium/article", auth, ""); rec.Code != http.StatusPaymentRequired {
			t.Fatalf("%q: got %d", auth, rec.Code)
		}
	}
}

func TestRejectsTraversal(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = "/blog/../premium/article"
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

type brokenNode struct{}

func (brokenNode) CreateInvoice(context.Context, int64, string, time.Duration) (lightning.Invoice, error) {
	return lightning.Invoice{}, errors.New("node offline")
}

func TestPoWStillWorksWhenNodeIsDown(t *testing.T) {
	f := newFixture(t)
	f.gate.node.backend = brokenNode{}
	b := f.challenge(t, "/premium/article")
	if b.L402 != nil {
		t.Fatal("no invoice should be offered when the node is down")
	}
	html := f.get("/premium/article", "", "text/html")
	if strings.Contains(html.Body.String(), "webln-pay") || strings.Contains(html.Body.String(), "window.webln") {
		t.Fatalf("WebLN markup without an invoice: %s", html.Body.String())
	}
	if rec := f.get("/premium/article", solve(t, b), ""); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestConcurrentReplay(t *testing.T) {
	f := newFixture(t)
	auth := f.pay(t, f.challenge(t, "/premium/article"))
	ok := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() { ok <- f.get("/premium/article", auth, "").Code == http.StatusOK }()
	}
	granted := 0
	for i := 0; i < 20; i++ {
		if <-ok {
			granted++
		}
	}
	if granted != 1 {
		t.Fatalf("token redeemed %d times, want exactly 1", granted)
	}
}
