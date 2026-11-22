package btc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/pow"
)

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func mustHex(t testing.TB, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stratumPrev is prevhash as pools send it: the header bytes, each 4-byte word swapped.
func stratumPrev(display string) string {
	b := reverse(mustHexNoT(display))
	for i := 0; i < 32; i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return hex.EncodeToString(b)
}

func mustHexNoT(s string) []byte { b, _ := hex.DecodeString(s); return b }

// vecNotify is the real block as a mining.notify, split around an 8-byte extranonce.
func vecNotify(t testing.TB) (params []any, en1 []byte, en2 uint64) {
	cb := mustHex(t, vecCoinbase)
	const at = 50 // anywhere works: the pool only fixes where the extranonce goes
	en1 = cb[at : at+4]
	en2 = uint64(binary.BigEndian.Uint32(cb[at+4 : at+8]))
	branch := make([]any, len(vecBranch))
	for i, b := range vecBranch {
		branch[i] = b
	}
	params = []any{"job1", stratumPrev(vecPrev), hex.EncodeToString(cb[:at]), hex.EncodeToString(cb[at+8:]), branch,
		fmt.Sprintf("%08x", vecVersion), fmt.Sprintf("%08x", vecBits), fmt.Sprintf("%08x", vecTime), true}
	return params, en1, en2
}

func TestHeaderOfARealBlock(t *testing.T) {
	params, en1, en2 := vecNotify(t)
	j, clean, err := parseNotify(params)
	if err != nil || !clean {
		t.Fatal(err)
	}
	j.en1, j.en2Size = en1, 4
	h := pow.HeaderHash(j.header(en2), vecNonce)
	if got := hex.EncodeToString(reverse(h[:])); got != vecHash {
		t.Fatalf("block hash %s, want %s", got, vecHash)
	}
	if j.height != vecHeight {
		t.Fatalf("height %d, want %d", j.height, vecHeight)
	}
	if v := hashInt(h); v.Cmp(compactTarget(vecBits)) > 0 {
		t.Fatal("a real block must clear its own target")
	}
	if d := networkDifficulty(vecBits); d < 1e14 || d > 1e15 {
		t.Fatalf("network difficulty %g", d)
	}
	if pow.HashZeroBits(h) < 70 {
		t.Fatalf("zero bits %d", pow.HashZeroBits(h))
	}
}

func TestNotifyErrors(t *testing.T) {
	params, _, _ := vecNotify(t)
	for i, f := range []func(p []any){
		func(p []any) { p[1] = "00" },
		func(p []any) { p[4] = []any{"zz"} },
		func(p []any) { p[5] = "123" },
		func(p []any) { p[0] = "" },
		func(p []any) { // more merkle levels than any block needs
			branch := make([]any, maxBranch+1)
			for i := range branch {
				branch[i] = strings.Repeat("00", 32)
			}
			p[4] = branch
		},
		func(p []any) { p[2] = strings.Repeat("00", maxCoinbase) }, // an oversized coinbase
	} {
		p := append([]any(nil), params...)
		f(p)
		if _, _, err := parseNotify(p); err == nil {
			t.Errorf("case %d: accepted", i)
		}
	}
	if _, _, err := parseNotify(params[:5]); err == nil {
		t.Error("short notify accepted")
	}
}

func TestDifficulties(t *testing.T) {
	var h [32]byte
	h[31-4], h[31-5] = 0xFF, 0xFF // 0x0000_0000_FFFF_00..: diff1 itself
	if d := shareDifficulty(hashInt(h)); d < 0.99 || d > 1.01 {
		t.Fatalf("diff1 hash: %g", d)
	}
	if networkDifficulty(0x1d00ffff) != 1 {
		t.Fatal("genesis nBits must be difficulty 1")
	}
	if b := en2Bytes(0x0102030405, 4); hex.EncodeToString(b) != "02030405" {
		t.Fatalf("en2 %x", b)
	}
	if b := en2Bytes(7, 10); hex.EncodeToString(b) != "00000000000000000007" {
		t.Fatalf("en2 %x", b)
	}
}

// fakePool speaks stratum v1 with one job (the real block's) and checks the
// shares it gets by rebuilding the header from what was submitted.
type fakePool struct {
	t      *testing.T
	ln     net.Listener
	diff   float64
	user   string
	mu     sync.Mutex
	shares []string
	bad    int
}

func newFakePool(t *testing.T, diff float64) *fakePool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePool{t: t, ln: ln, diff: diff}
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *fakePool) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *fakePool) handle(c net.Conn) {
	defer c.Close()
	params, en1, _ := vecNotify(p.t)
	cb1, _ := hex.DecodeString(params[2].(string))
	cb2, _ := hex.DecodeString(params[3].(string))
	w := func(v any) { b, _ := json.Marshal(v); c.Write(append(b, '\n')) }
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		var m struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.Method {
		case "mining.subscribe":
			w(map[string]any{"id": m.ID, "error": nil, "result": []any{[]any{[]any{"mining.notify", "x"}}, hex.EncodeToString(en1), 4}})
		case "mining.authorize":
			p.mu.Lock()
			p.user, _ = m.Params[0].(string)
			p.mu.Unlock()
			w(map[string]any{"id": m.ID, "error": nil, "result": true})
			w(map[string]any{"id": nil, "method": "mining.set_difficulty", "params": []any{p.diff}})
			w(map[string]any{"id": nil, "method": "mining.notify", "params": params})
		case "mining.submit":
			en2, _ := hex.DecodeString(m.Params[2].(string))
			ntime, _ := hex.DecodeString(m.Params[3].(string))
			nonce, _ := hex.DecodeString(m.Params[4].(string))
			j, _, _ := parseNotify(params)
			j.coinb1, j.coinb2, j.en1, j.en2Size = cb1, cb2, en1, len(en2)
			j.ntime = binary.BigEndian.Uint32(ntime)
			h := pow.HeaderHash(j.header(uint64(binary.BigEndian.Uint32(en2))), binary.BigEndian.Uint32(nonce))
			ok := shareDifficulty(hashInt(h)) >= p.diff
			p.mu.Lock()
			if ok {
				p.shares = append(p.shares, m.Params[4].(string))
			} else {
				p.bad++
			}
			p.mu.Unlock()
			w(map[string]any{"id": m.ID, "error": nil, "result": ok})
		}
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestLotteryWithPool(t *testing.T) {
	pool := newFakePool(t, 1e-6) // tiny pool difficulty, so test answers are shares
	l := New(Options{Pool: pool.ln.Addr().String(), User: "bc1qtest.spikes402"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)
	waitFor(t, "a job", func() bool { _, _, _, ok := l.Offer(12); return ok })

	id, en2, header, ok := l.Offer(12)
	_, en2b, header2, _ := l.Offer(12)
	if !ok || en2 == en2b || string(header) == string(header2) {
		t.Fatal("two offers must get different headers")
	}
	nonce, err := pow.BitcoinWork{Header: header, Bits: 12}.Solve(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	record, err := l.Check(id, en2, nonce, 12)
	if err != nil {
		t.Fatal(err)
	}
	if st := l.Stats(); st.SharesSubmitted != 0 || st.ProofsValid != 0 {
		t.Fatalf("recorded an unredeemed proof: %+v", st)
	}
	record()
	waitFor(t, "the share", func() bool { return l.Stats().SharesAccepted == 1 })
	if _, err := l.Check(id, en2, nonce+1, 30); err == nil {
		t.Fatal("a wrong answer passed")
	}
	if _, err := l.Check(9999, en2, nonce, 12); err != pow.ErrJobGone {
		t.Fatalf("unknown job: %v", err)
	}
	st := l.Stats()
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.bad != 0 || len(pool.shares) != 1 || pool.user != "bc1qtest.spikes402" {
		t.Fatalf("pool saw %d good, %d bad shares, user %q", len(pool.shares), pool.bad, pool.user)
	}
	if !st.Connected || st.ProofsValid != 1 || st.ProofsInvalid != 1 || st.Hashes != 4096 || st.BestDifficulty <= 0 ||
		st.Height != vecHeight || st.PoolDifficulty != 1e-6 || st.Chance <= 0 || st.Chance > 1e-15 || st.Blocks != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestLotteryOffersOnlyCurrentWork(t *testing.T) {
	l := New(Options{JobTTL: time.Minute})
	now := time.Unix(100, 0)
	l.now = func() time.Time { return now }
	l.en1, l.en2Size = []byte{42}, 1
	params, _, _ := vecNotify(t)
	j, _, err := parseNotify(params)
	if err != nil {
		t.Fatal(err)
	}
	l.addJob(j, true, l.gen)
	if _, _, _, ok := l.Offer(12); ok {
		t.Fatal("offered a job before authorization")
	}
	l.conn = true
	l.jobs[l.order[0]].en2.Store(254)
	if _, en2, _, ok := l.Offer(12); !ok || en2 != 255 {
		t.Fatalf("last extranonce: %d, offered=%t", en2, ok)
	}
	if _, _, _, ok := l.Offer(12); ok {
		t.Fatal("offered a reused extranonce")
	}
	// A new job has extranonces of its own again.
	j2, _, _ := parseNotify(params)
	l.addJob(j2, false, l.gen)
	if _, en2, _, ok := l.Offer(12); !ok || en2 != 1 {
		t.Fatalf("new job: extranonce %d, offered=%t", en2, ok)
	}
	// A difficulty that arrives after the job applies to it.
	if j2.poolDiff != 0 {
		t.Fatalf("pool difficulty %v before any set_difficulty", j2.poolDiff)
	}
	l.notification(rpcMsg{Method: "mining.set_difficulty", Params: []byte("[0.5]")}, l.gen)
	if j2.poolDiff != 0.5 {
		t.Fatalf("pool difficulty %v after set_difficulty", j2.poolDiff)
	}
	now = now.Add(time.Minute)
	if _, _, _, ok := l.Offer(12); ok {
		t.Fatal("offered an expired job")
	}
}

func TestLotteryNoPool(t *testing.T) {
	l := New(Options{Pool: "127.0.0.1:1", User: "x"})
	if _, _, _, ok := l.Offer(10); ok {
		t.Fatal("offer without a job")
	}
	if _, _, _, ok := l.Offer(31); ok {
		t.Fatal("offer beyond the nonce space")
	}
	if s := l.Stats(); s.Connected || s.Jobs != 0 || !strings.Contains(s.Pool, "127.0.0.1") {
		t.Fatalf("%+v", s)
	}
}

// A set_difficulty from the pool while proofs are being recorded must not
// race with the read of the job's pool difficulty (go test -race).
func TestRecordAndSetDifficultyDoNotRace(t *testing.T) {
	l := New(Options{JobTTL: time.Minute})
	l.en1, l.en2Size, l.conn = []byte{42}, 4, true
	params, _, _ := vecNotify(t)
	var jobs []*job
	for i := 0; i < 200; i++ {
		j, _, err := parseNotify(params)
		if err != nil {
			t.Fatal(err)
		}
		l.addJob(j, false, l.gen) // no difficulty yet: poolDiff is 0
		jobs = append(jobs, j)
	}
	var high [32]byte
	for i := range high {
		high[i] = 0xff // not a block, so the pool difficulty is read
	}
	var wg sync.WaitGroup
	wg.Add(len(jobs) + 1)
	for _, j := range jobs { // each proof on its own request goroutine, as in the gate
		go func() {
			defer wg.Done()
			l.record(j, 1, 1, 1, high)
		}()
	}
	go func() {
		defer wg.Done()
		l.notification(rpcMsg{Method: "mining.set_difficulty", Params: []byte("[1e30]")}, l.gen)
	}()
	wg.Wait()
}

// A difficulty no real pool uses is ignored: every proof would become a share.
func TestAbsurdPoolDifficultyIgnored(t *testing.T) {
	l := New(Options{})
	l.notification(rpcMsg{Method: "mining.set_difficulty", Params: []byte("[1e-12]")}, l.gen)
	l.notification(rpcMsg{Method: "mining.set_difficulty", Params: []byte("[-1]")}, l.gen)
	if l.diff != 0 {
		t.Fatalf("pool difficulty %v accepted", l.diff)
	}
	l.notification(rpcMsg{Method: "mining.set_difficulty", Params: []byte("[0.001]")}, l.gen)
	if l.diff != 0.001 {
		t.Fatalf("pool difficulty %v, want 0.001", l.diff)
	}
}
