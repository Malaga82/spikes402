package gate

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Choffolo/spikes402/pow"
)

// fakeLottery hands out a made-up header per (job, extranonce2).
type fakeLottery struct {
	mu     sync.Mutex
	en2    uint64
	down   bool
	gone   bool
	checks int
	played int
}

func fakeHeader(job uint32, en2 uint64) []byte {
	h := make([]byte, pow.HeaderPrefixLen)
	binary.LittleEndian.PutUint32(h, job)
	binary.LittleEndian.PutUint64(h[4:], en2)
	return h
}

func (f *fakeLottery) Offer(bits int) (uint32, uint64, []byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return 0, 0, nil, false
	}
	f.en2++
	return 7, f.en2, fakeHeader(7, f.en2), true
}

func (f *fakeLottery) Check(job uint32, en2 uint64, nonce uint32, bits int) (func(), error) {
	f.mu.Lock()
	f.checks++
	gone := f.gone
	f.mu.Unlock()
	if gone || job != 7 {
		return nil, pow.ErrJobGone
	}
	if !(pow.BitcoinWork{Header: fakeHeader(job, en2), Bits: bits}).Check(nonce) {
		return nil, errBadProof
	}
	return func() {
		f.mu.Lock()
		f.played++
		f.mu.Unlock()
	}, nil
}

func (f *fakeLottery) Status() any { return "playing" }

func (f *fakeLottery) Has(job uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return job == 7 && !f.gone
}

func newLotteryFixture(t *testing.T) (*fixture, *fakeLottery) {
	f := newFixture(t)
	l := &fakeLottery{}
	f.gate.opt.Lottery = l
	return f, l
}

func solveLottery(t *testing.T, lo *lotteryOffer) string {
	t.Helper()
	h, _ := hex.DecodeString(lo.Header)
	n, err := pow.BitcoinWork{Header: h, Bits: lo.Difficulty}.Solve(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	return "PoW " + lo.Challenge + ":" + strconv.FormatUint(uint64(n), 10)
}

func TestLotteryOffer(t *testing.T) {
	f, l := newLotteryFixture(t)
	rec := f.get("/premium/a", "", "")
	hdrs := rec.Header().Values("WWW-Authenticate")
	if len(hdrs) != 3 || !strings.Contains(hdrs[1], `algorithm="sha256d"`) || !strings.Contains(hdrs[2], `algorithm="bitcoin"`) ||
		!strings.Contains(hdrs[2], `header="`+hex.EncodeToString(fakeHeader(7, 1))+`"`) {
		t.Fatalf("headers %q", hdrs)
	}
	b := f.challenge(t, "/premium/a")
	if b.Lottery == nil || b.Lottery.Difficulty != testDifficulty || b.Lottery.Usage != lotteryUsage || b.PoW.Algorithm != pow.SHA256d {
		t.Fatalf("body %+v", b)
	}
	if rec := f.get("/premium/a", solveLottery(t, b.Lottery), ""); rec.Code != http.StatusOK || rec.Body.String() != "content of /premium/a" {
		t.Fatalf("lottery answer: %d %s", rec.Code, rec.Body)
	}
	if l.checks != 1 {
		t.Fatalf("checks %d", l.checks)
	}
	// The 402 page's puzzle is the lottery header.
	if page := f.get("/premium/c", "", "text/html").Body.String(); !strings.Contains(page, `data-header="`+hex.EncodeToString(fakeHeader(7, 3))+`"`) ||
		!strings.Contains(page, `data-lottery="`) || !strings.Contains(page, "lottery ticket") {
		t.Fatal("the energy wall does not offer the lottery header")
	}
	// The ordinary puzzle still works next to it.
	b = f.challenge(t, "/premium/b")
	n, _ := f.pow.Solve(context.Background(), b.PoW.Challenge)
	if rec := f.get("/premium/b", "PoW "+b.PoW.Challenge+":"+strconv.FormatUint(n, 10), ""); rec.Code != http.StatusOK {
		t.Fatalf("ordinary answer: %d", rec.Code)
	}
}

func TestLotteryAnswers(t *testing.T) {
	f, l := newLotteryFixture(t)
	b := f.challenge(t, "/premium/a")
	auth := solveLottery(t, b.Lottery)
	tok, nonce, _ := strings.Cut(strings.TrimPrefix(auth, "PoW "), ":")
	n, _ := strconv.ParseUint(nonce, 10, 32)
	h, _ := hex.DecodeString(b.Lottery.Header)
	work := pow.BitcoinWork{Header: h, Bits: b.Lottery.Difficulty}
	n++
	for work.Check(uint32(n)) {
		n++
	}
	for _, bad := range []string{
		"PoW " + tok + ":" + strconv.FormatUint(n, 10),
		"PoW " + tok + ":4294967296",
		"PoW " + tok + ":x",
	} {
		if rec := f.get("/premium/a", bad, ""); rec.Code != http.StatusPaymentRequired {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	if rec := f.get("/premium/b", auth, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("token used on another page: %d", rec.Code)
	}
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusOK {
		t.Fatalf("good answer after bad ones: %d", rec.Code)
	}
	if rec := f.get("/premium/a", auth, ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("replay: %d", rec.Code)
	}
	if l.played != 1 {
		t.Fatalf("recorded %d plays for one redemption", l.played)
	}
	l.gone = true
	b = f.challenge(t, "/premium/c")
	if rec := f.get("/premium/c", solveLottery(t, b.Lottery), ""); rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("job gone: %d %s", rec.Code, rec.Body)
	}
}

func TestLotteryRecordsOnePlayAcrossOriginRetry(t *testing.T) {
	f, l := newLotteryFixture(t)
	originCounter(t, f, func(call int) int {
		if call == 1 {
			return http.StatusBadGateway
		}
		return http.StatusOK
	})
	auth := solveLottery(t, f.challenge(t, "/premium/a").Lottery)
	for _, status := range []int{http.StatusBadGateway, http.StatusOK} {
		if rec := f.get("/premium/a", auth, ""); rec.Code != status {
			t.Fatalf("got %d, want %d", rec.Code, status)
		}
	}
	if l.played != 1 {
		t.Fatalf("recorded %d plays for one solution", l.played)
	}
}

func TestLotteryOff(t *testing.T) {
	f, l := newLotteryFixture(t)
	l.down = true // no job yet
	if b := f.challenge(t, "/premium/a"); b.Lottery != nil || len(f.get("/premium/a", "", "").Header().Values("WWW-Authenticate")) != 2 {
		t.Fatal("lottery offered without a job")
	}
	l.down = false
	f.pow = pow.Params{Algorithm: pow.Argon2id, Difficulty: 1, MemoryMiB: 8}
	if b := f.challenge(t, "/premium/a"); b.Lottery != nil {
		t.Fatal("lottery offered next to Argon2id")
	}
	f.pow = pow.Params{Algorithm: pow.SHA256d, Difficulty: 31}
	if b := f.challenge(t, "/premium/a"); b.Lottery != nil {
		t.Fatal("lottery offered beyond the nonce space")
	}
	if st := f.gate.Status(); st.Lottery != "playing" {
		t.Fatalf("status %+v", st)
	}
}

// The lottery challenge belongs to the offer: a reload of the 402 gets the
// same one (no new header, no new token), solving it spends the offer
// (the ordinary puzzle of the same 402 is then a replay) and drops the
// cached invoice, and a new block replaces a stale header.
func TestLotteryChallengeBelongsToTheOffer(t *testing.T) {
	f, l := newLotteryFixture(t)
	const client = "203.0.113.1:1"
	b1, sess := f.offerFor(t, client, "/premium/a", "")
	b2, _ := f.offerFor(t, client, "/premium/a", sess)
	if b1.Lottery == nil || b2.Lottery == nil || b1.Lottery.Challenge != b2.Lottery.Challenge || l.en2 != 1 {
		t.Fatalf("reload: lottery %v / %v, %d headers handed out", b1.Lottery, b2.Lottery, l.en2)
	}
	l.mu.Lock()
	l.gone = true // a new block
	l.mu.Unlock()
	b3, _ := f.offerFor(t, client, "/premium/a", sess)
	if b3.L402 == nil || b3.L402.Token != b1.L402.Token || b3.Lottery == nil || b3.Lottery.Challenge == b1.Lottery.Challenge {
		t.Fatal("a stale header must be replaced in the same offer")
	}
	l.mu.Lock()
	l.gone = false
	l.mu.Unlock()
	if rec := f.get("/premium/a", solveLottery(t, b3.Lottery), ""); rec.Code != http.StatusOK {
		t.Fatalf("lottery answer: %d", rec.Code)
	}
	n, _ := f.pow.Solve(context.Background(), b1.PoW.Challenge)
	if rec := f.get("/premium/a", "PoW "+b1.PoW.Challenge+":"+strconv.FormatUint(n, 10), ""); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("ordinary puzzle of an offer already solved by the lottery: got %d, want 402", rec.Code)
	}
	if b4, _ := f.offerFor(t, client, "/premium/a", sess); b4.L402 == nil || b4.L402.Token == b1.L402.Token {
		t.Fatal("the solved offer is still handed out")
	}
}
