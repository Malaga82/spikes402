package gate

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Choffolo/spikes402/pow"
)

var scriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// inlineScripts are the bodies of the executable inline scripts of a page
// (data blocks such as ld+json have a type attribute and do not count).
func inlineScripts(body string) []string {
	var out []string
	for _, m := range scriptRE.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestEnergyWallPage(t *testing.T) {
	f := newFixture(t)
	rec := f.get("/premium/article", "", "text/html")
	body := rec.Body.String()
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d, want 402", rec.Code)
	}
	for _, want := range []string{
		"invisible energy wall built with Bitcoin",
		"Pay a few sats with the",
		"solve a math puzzle with your computer",
		`href="https://github.com/Choffolo/spikes402#browser-wallet-extension-prototype"`,
		`id="pow-go"`, `id="pow-bar"`, `id="pow-stats"`,
		`data-worker="` + workerSrc + `"`,
		`data-difficulty="8"`,
		`<div class="paywall">`,
		`class="ways"`,
		`width="160"`,
		`id="webln-pay"`, // the Lightning invoice flow is still there
		`id="open-wallet"`, `id="pay-wait"`, "Open in wallet",
		"data:image/png;base64,",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The challenge in the page is the one in the headers (one token per offer).
	_, token := weblnAttrs(t, body)
	if !strings.Contains(body, `data-challenge="`+token+`"`) {
		t.Error("puzzle and invoice use different tokens")
	}
	// Nothing from outside, nothing inline beyond the two hashed scripts.
	if strings.Contains(body, "<script src") || strings.Contains(body, "http://") {
		t.Error("page loads or links something external")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "worker-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'unsafe") || strings.Contains(csp, "*") {
		t.Errorf("CSP too loose: %s", csp)
	}
	if got := len(inlineScripts(body)); got != 3 {
		t.Errorf("%d inline scripts, want 3 (wallet, invoice wait, puzzle)", got)
	}
	// Machine-readable parts are unchanged.
	if len(rec.Header().Values("WWW-Authenticate")) != 2 {
		t.Errorf("WWW-Authenticate: %q", rec.Header().Values("WWW-Authenticate"))
	}
}

func TestPaywallMarkup(t *testing.T) {
	f := newFixture(t)
	body := f.get("/premium/article", "", "text/html").Body.String()
	m := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no JSON-LD")
	}
	var ld struct {
		Type    string `json:"@type"`
		Free    bool   `json:"isAccessibleForFree"`
		HasPart struct {
			Type string `json:"@type"`
			Free bool   `json:"isAccessibleForFree"`
			Sel  string `json:"cssSelector"`
		} `json:"hasPart"`
	}
	if err := json.Unmarshal([]byte(m[1]), &ld); err != nil {
		t.Fatal(err)
	}
	if ld.Type != "WebPage" || ld.Free || ld.HasPart.Type != "WebPageElement" || ld.HasPart.Free || ld.HasPart.Sel != ".paywall" {
		t.Errorf("bad markup: %s", m[1])
	}
	// Google only accepts class selectors: the element must exist.
	if !strings.Contains(body, `class="paywall"`) {
		t.Error("no .paywall element")
	}
}

func TestWorkerAsset(t *testing.T) {
	f := newFixture(t)
	f.gate.opt.Next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("worker request reached the origin") })
	f.gate.live.Store(&Settings{PriceSats: 10, Protect: []string{"/**"}, PoW: f.gate.opt.PoW, ChallengesPerMinute: 100})
	for _, target := range []string{WorkerPath, workerSrc} {
		rec := f.get(target, "", "")
		h := rec.Header()
		if rec.Code != http.StatusOK || rec.Body.String() != powWorkerJS ||
			!strings.HasPrefix(h.Get("Content-Type"), "text/javascript") ||
			h.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(h.Get("Cache-Control"), "max-age") ||
			h.Get("Content-Security-Policy") != "default-src 'none'" {
			t.Fatalf("%s: %d %v", target, rec.Code, h)
		}
	}
	req := httptest.NewRequest(http.MethodHead, WorkerPath, nil)
	rec := httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	req = httptest.NewRequest(http.MethodPost, WorkerPath, strings.NewReader("x"))
	rec = httptest.NewRecorder()
	f.gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}

func TestArgon2idHidesThePuzzle(t *testing.T) {
	f := newFixture(t)
	f.pow = pow.Params{Algorithm: pow.Argon2id, Difficulty: 4, MemoryMiB: 1}
	rec := f.get("/premium/article", "", "text/html")
	body := rec.Body.String()
	if rec.Code != http.StatusPaymentRequired || strings.Contains(body, `id="pow-box"`) || len(inlineScripts(body)) != 2 {
		t.Fatalf("Argon2id page offers a puzzle the browser cannot solve: %d", rec.Code)
	}
}

// Known vectors of the browser puzzle: the smallest nonce the JS worker
// finds from the given start, checked by the Go verifier.
func TestBrowserPoWKnownVectors(t *testing.T) {
	for _, v := range []struct {
		challenge string
		bits      int
		nonce     uint64
	}{
		{"abc", 12, 747},
		{strings.Repeat("x", 55), 14, 2828}, // padding crosses a block boundary
		{strings.Repeat("y", 70), 13, 1003501},
		{strings.Repeat("z", 120) + "é", 16, 298690},
	} {
		p := pow.Params{Algorithm: pow.SHA256d, Difficulty: v.bits}
		if !p.Check(v.challenge, v.nonce) {
			t.Errorf("%.12q… bits=%d: Go rejects nonce %d", v.challenge, v.bits, v.nonce)
		}
		if v.nonce > 0 && p.Check(v.challenge, v.nonce-1) {
			t.Errorf("%.12q…: nonce %d is not the first", v.challenge, v.nonce)
		}
	}
}

// The real worker, run by Node, solves a real challenge from the gate and
// the gate redeems it the way the page does: Authorization + redeem header.
func TestBrowserWorkerEndToEnd(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	f := newFixture(t)
	f.pow.Difficulty = 14
	b := f.challenge(t, "/premium/article?x=1")

	dir := t.TempDir()
	worker := dir + "/worker.js"
	if err := os.WriteFile(worker, []byte(powWorkerJS), 0o600); err != nil {
		t.Fatal(err)
	}
	const run = `const vm=require("vm"),fs=require("fs");let out;const self={postMessage:m=>{out=m}};
vm.runInNewContext(fs.readFileSync(process.argv[1],"utf8"),{self,TextEncoder,Date,Int32Array,Uint8Array,String});
self.onmessage({data:{challenge:process.argv[2],difficulty:+process.argv[3],start:+process.argv[4]}});
console.log(JSON.stringify(out))`
	for _, start := range []string{"0", "1099511627776"} { // worker 0 and worker 1
		raw, err := exec.Command(node, "-e", run, worker, b.PoW.Challenge, "14", start).Output()
		if err != nil {
			t.Fatal(err)
		}
		var res struct {
			Attempts uint64
			Nonce    uint64
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if !(pow.Params{Algorithm: pow.SHA256d, Difficulty: 14}).Check(b.PoW.Challenge, res.Nonce) {
			t.Fatalf("start %s: Go rejects the JS nonce %d", start, res.Nonce)
		}
		req := httptest.NewRequest(http.MethodGet, "/premium/article?x=1", nil)
		req.Header.Set("Authorization", "PoW "+b.PoW.Challenge+":"+strconv.FormatUint(res.Nonce, 10))
		req.Header.Set(RedeemHeader, "cookie")
		rec := httptest.NewRecorder()
		f.gate.ServeHTTP(rec, req)
		if start == "0" {
			if rec.Code != http.StatusNoContent || !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), ";"), "HttpOnly") {
				t.Fatalf("redeem: %d %v", rec.Code, rec.Header())
			}
		} else if rec.Code != http.StatusPaymentRequired { // same token: already spent
			t.Fatalf("a token must be spendable once, got %d", rec.Code)
		}
	}
}

// The worker's Bitcoin lottery mode finds the same first nonce as
// pow.HeaderHash, within its range, and reports a range with no solution.
func TestBrowserWorkerLotteryHeader(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	header := make([]byte, 76)
	for i := range header {
		header[i] = byte(i*7 + 3)
	}
	const bits = 12
	first := func(from uint32) uint32 {
		for n := from; ; n++ {
			if pow.HashZeroBits(pow.HeaderHash(header, n)) >= bits {
				return n
			}
		}
	}
	worker := t.TempDir() + "/worker.js"
	if err := os.WriteFile(worker, []byte(powWorkerJS), 0o600); err != nil {
		t.Fatal(err)
	}
	const run = `const vm=require("vm"),fs=require("fs");let out;const self={postMessage:m=>{out=m}};
vm.runInNewContext(fs.readFileSync(process.argv[1],"utf8"),{self,TextEncoder,Date,Int32Array,Uint8Array,String,parseInt});
self.onmessage({data:{header:process.argv[2],difficulty:+process.argv[3],start:+process.argv[4],end:+process.argv[5]}});
console.log(JSON.stringify(out))`
	want := first(0)
	second := first(want + 1)
	for _, c := range []struct {
		start, end uint32
		nonce      uint32
		exhausted  bool
	}{
		{0, 4294967295, want, false},
		{want + 1, 4294967295, second, false},
		{want + 1, second - 1, 0, true},
	} {
		raw, err := exec.Command(node, "-e", run, worker, hex.EncodeToString(header), strconv.Itoa(bits),
			strconv.FormatUint(uint64(c.start), 10), strconv.FormatUint(uint64(c.end), 10)).Output()
		if err != nil {
			t.Fatal(err)
		}
		var res struct {
			Nonce     *uint32
			Exhausted bool
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if c.exhausted {
			if !res.Exhausted || res.Nonce != nil {
				t.Fatalf("range %d-%d: got %s, want exhausted", c.start, c.end, raw)
			}
			continue
		}
		if res.Nonce == nil || *res.Nonce != c.nonce {
			t.Fatalf("range %d-%d: got %s, want nonce %d", c.start, c.end, raw, c.nonce)
		}
	}
}
