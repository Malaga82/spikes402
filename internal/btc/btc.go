// Package btc runs the Bitcoin lottery: Spikes402's proof-of-work becomes
// solo mining. It connects to a solo pool (solo.ckpool.org, public-pool.io,
// or one of your own) over stratum as a miner, keeps the pool's recent jobs,
// gives each 402 challenge its own block header (a unique extranonce2), and
// checks the answers. Any answer that also clears the pool's target is sent
// to the pool as a share; one that clears the network's target is a block,
// paid by the pool to the address in the config.
//
// The odds are tiny (a browser does about a million hashes a second; the
// network does about 10^21), so this is a lottery, not income. The gate never
// depends on it: without a usable job it offers its ordinary puzzle, and an
// answer on an old job still unlocks the page (it is only not sent).
package btc

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Choffolo/spikes402/pow"
)

// Options configure a Lottery.
type Options struct {
	Pool     string // stratum address, "host:port" or "tls://host:port"
	User     string // pool user: for solo pools the payout address, optionally ".worker"
	Password string // pool password, usually ignored ("x")
	Agent    string // user agent sent to the pool
	JobTTL   time.Duration
	Logf     func(format string, args ...any)
}

const (
	maxJobs        = 64
	submitQueue    = 256
	staleForSubmit = 10 * time.Minute
)

// diff1 is the target of difficulty 1 (0xFFFF × 2^208), as pools count it.
var diff1 = new(big.Int).Lsh(big.NewInt(0xFFFF), 208)

// job is one mining job from the pool (mining.notify).
type job struct {
	id       uint32 // ours, goes into tokens
	poolID   string
	prevHash []byte // header order
	coinb1   []byte
	coinb2   []byte
	branch   [][]byte
	version  uint32
	nbits    uint32
	ntime    uint32
	en1      []byte // the connection's extranonce1
	en2Size  int
	poolDiff float64
	height   uint64
	received time.Time
	gen      uint64
	en2      atomic.Uint64 // last extranonce2 handed out: unique per job, so a new job starts again from 1
}

// Stats are the lottery's counters.
type Stats struct {
	Pool              string    `json:"pool"`
	User              string    `json:"user"` // the payout address (public)
	Connected         bool      `json:"connected"`
	Height            uint64    `json:"height"`
	Jobs              int       `json:"jobs"`
	PoolDifficulty    float64   `json:"pool_difficulty"`
	NetworkDifficulty float64   `json:"network_difficulty"`
	Offers            uint64    `json:"offers"`
	ProofsValid       uint64    `json:"proofs_valid"`
	ProofsInvalid     uint64    `json:"proofs_invalid"`
	Hashes            float64   `json:"hashes"`          // expected hashes behind the valid proofs (2^bits each): the tickets played
	BestDifficulty    float64   `json:"best_difficulty"` // the best hash so far, as a share difficulty
	Chance            float64   `json:"chance"`          // probability that the hashes so far found a block at today's difficulty
	SharesSubmitted   uint64    `json:"shares_submitted"`
	SharesAccepted    uint64    `json:"shares_accepted"`
	SharesRejected    uint64    `json:"shares_rejected"`
	SharesDropped     uint64    `json:"shares_dropped"`
	Blocks            uint64    `json:"blocks"` // answers that cleared the network target
	LastError         string    `json:"last_error,omitempty"`
	LastErrorAt       time.Time `json:"last_error_at,omitzero"`
}

// Lottery is the pool connection plus the job store. Create it with New and
// start Run in a goroutine.
type Lottery struct {
	opt  Options
	now  func() time.Time
	dial dialer

	mu        sync.Mutex
	jobs      map[uint32]*job
	order     []uint32
	nextID    uint32
	gen       uint64
	en1       []byte
	en2Size   int
	diff      float64
	cleanID   uint32 // older jobs are no longer valid at the pool
	conn      bool
	hashes    float64
	best      float64
	lastErr   string
	lastErrAt time.Time

	submits chan share
	stats   struct {
		offers, valid, invalid, submitted, accepted, rejected, dropped, blocks atomic.Uint64
	}
}

type share struct {
	job               *job
	en2, ntime, nonce string
}

// New returns a Lottery. Run connects it.
func New(opt Options) *Lottery {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Agent == "" {
		opt.Agent = "spikes402"
	}
	if opt.Password == "" {
		opt.Password = "x"
	}
	if opt.JobTTL <= 0 {
		opt.JobTTL = 10 * time.Minute
	}
	return &Lottery{opt: opt, now: time.Now, dial: netDialer, jobs: map[uint32]*job{}, submits: make(chan share, submitQueue)}
}

func sha256d(b []byte) []byte {
	a := sha256.Sum256(b)
	c := sha256.Sum256(a[:])
	return c[:]
}

// en2Bytes writes the counter into the pool's extranonce2 size, big-endian.
func en2Bytes(v uint64, size int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	if size >= 8 {
		return append(make([]byte, size-8), b[:]...)
	}
	return b[8-size:]
}

// header builds the 76-byte header for extranonce2 en2: the coinbase is
// coinb1 + extranonce1 + extranonce2 + coinb2, its hash climbs the merkle
// branch to the root, and the fields go in little-endian.
func (j *job) header(en2 uint64) []byte {
	cb := append(append(append(append([]byte(nil), j.coinb1...), j.en1...), en2Bytes(en2, j.en2Size)...), j.coinb2...)
	root := sha256d(cb)
	for _, b := range j.branch {
		root = sha256d(append(root, b...))
	}
	h := make([]byte, 0, pow.HeaderPrefixLen)
	h = binary.LittleEndian.AppendUint32(h, j.version)
	h = append(h, j.prevHash...)
	h = append(h, root...)
	h = binary.LittleEndian.AppendUint32(h, j.ntime)
	h = binary.LittleEndian.AppendUint32(h, j.nbits)
	return h
}

// Offer gives a challenge the newest job's header with its own extranonce2.
// ok is false without a usable job (not connected yet): offer the ordinary puzzle.
func (l *Lottery) Offer(bits int) (id uint32, en2 uint64, header []byte, ok bool) {
	if bits < 1 || bits > pow.MaxBitcoinBits {
		return 0, 0, nil, false
	}
	l.mu.Lock()
	l.pruneLocked()
	var jb *job
	if n := len(l.order); n > 0 {
		j := l.jobs[l.order[n-1]]
		if l.currentLocked(j) {
			jb = j
		}
	}
	l.mu.Unlock()
	if jb == nil {
		return 0, 0, nil, false
	}
	en2 = jb.en2.Add(1)
	if en2 == 0 || (jb.en2Size < 8 && en2 >= uint64(1)<<(8*jb.en2Size)) {
		return 0, 0, nil, false
	}
	l.stats.offers.Add(1)
	return jb.id, en2, jb.header(en2), true
}

func (l *Lottery) currentLocked(j *job) bool {
	return l.conn && j.gen == l.gen && j.id >= l.cleanID && j.en1 != nil &&
		l.now().Sub(j.received) < min(l.opt.JobTTL, staleForSubmit)
}

// Has reports whether job id is still kept.
func (l *Lottery) Has(id uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.jobs[id]
	return ok
}

// Check verifies an answer: job id's header with extranonce2 en2 and nonce
// must hash to at least bits zero bits. The caller records the result after
// accepting the proof for the first time.
func (l *Lottery) Check(id uint32, en2 uint64, nonce uint32, bits int) (func(), error) {
	l.mu.Lock()
	jb, ok := l.jobs[id]
	l.mu.Unlock()
	if !ok {
		return nil, pow.ErrJobGone
	}
	h := pow.HeaderHash(jb.header(en2), nonce)
	if pow.HashZeroBits(h) < bits {
		l.stats.invalid.Add(1)
		return nil, errors.New("hash does not meet the difficulty")
	}
	return func() { l.record(jb, en2, nonce, bits, h) }, nil
}

func (l *Lottery) record(jb *job, en2 uint64, nonce uint32, bits int, h [32]byte) {
	l.stats.valid.Add(1)
	v := hashInt(h)
	d := shareDifficulty(v)
	l.mu.Lock()
	l.hashes += math.Ldexp(1, bits)
	l.best = max(l.best, d)
	current := l.currentLocked(jb)
	poolDiff := jb.poolDiff // set_difficulty may fill it in, under l.mu
	l.mu.Unlock()
	block := v.Cmp(compactTarget(jb.nbits)) <= 0
	if block {
		l.stats.blocks.Add(1)
		l.opt.Logf("btc: BLOCK! job %s nonce %d clears the network target", jb.poolID, nonce)
	}
	if block || (poolDiff > 0 && d >= poolDiff) {
		if !current {
			l.stats.dropped.Add(1)
			return
		}
		var nb, tb [4]byte
		binary.BigEndian.PutUint32(nb[:], nonce)
		binary.BigEndian.PutUint32(tb[:], jb.ntime)
		s := share{job: jb, en2: hex.EncodeToString(en2Bytes(en2, jb.en2Size)),
			ntime: hex.EncodeToString(tb[:]), nonce: hex.EncodeToString(nb[:])}
		select {
		case l.submits <- s:
		default:
			l.stats.dropped.Add(1)
		}
	}
}

// hashInt reads a hash as Bitcoin does: a little-endian number.
func hashInt(h [32]byte) *big.Int {
	var be [32]byte
	for i := range h {
		be[31-i] = h[i]
	}
	return new(big.Int).SetBytes(be[:])
}

// shareDifficulty is diff1 / hash: how hard a target this hash would clear.
func shareDifficulty(v *big.Int) float64 {
	if v.Sign() == 0 {
		return math.Inf(1)
	}
	d, _ := new(big.Float).Quo(new(big.Float).SetInt(diff1), new(big.Float).SetInt(v)).Float64()
	return d
}

// compactTarget expands nBits.
func compactTarget(nbits uint32) *big.Int {
	exp, mant := nbits>>24, int64(nbits&0x007fffff)
	t := big.NewInt(mant)
	if exp <= 3 {
		return t.Rsh(t, 8*uint(3-exp))
	}
	return t.Lsh(t, 8*uint(exp-3))
}

// networkDifficulty is diff1 / target of nBits.
func networkDifficulty(nbits uint32) float64 {
	t := compactTarget(nbits)
	if t.Sign() == 0 {
		return 0
	}
	d, _ := new(big.Float).Quo(new(big.Float).SetInt(diff1), new(big.Float).SetInt(t)).Float64()
	return d
}

// Stats returns the counters.
func (l *Lottery) Stats() Stats {
	l.mu.Lock()
	st := Stats{Pool: l.opt.Pool, User: l.opt.User, Connected: l.conn, Jobs: len(l.jobs), Hashes: l.hashes, BestDifficulty: l.best,
		PoolDifficulty: l.diff, LastError: l.lastErr, LastErrorAt: l.lastErrAt}
	if n := len(l.order); n > 0 {
		last := l.jobs[l.order[n-1]]
		st.Height, st.NetworkDifficulty = last.height, networkDifficulty(last.nbits)
	}
	l.mu.Unlock()
	if st.NetworkDifficulty > 0 {
		st.Chance = -math.Expm1(-st.Hashes / (st.NetworkDifficulty * 4294967296))
	}
	st.Offers, st.ProofsValid, st.ProofsInvalid = l.stats.offers.Load(), l.stats.valid.Load(), l.stats.invalid.Load()
	st.SharesSubmitted, st.SharesAccepted = l.stats.submitted.Load(), l.stats.accepted.Load()
	st.SharesRejected, st.SharesDropped, st.Blocks = l.stats.rejected.Load(), l.stats.dropped.Load(), l.stats.blocks.Load()
	return st
}

// Status implements the gate's optional status report.
func (l *Lottery) Status() any { return l.Stats() }

// addJob stores a job; a clean job (a new block) makes the older ones stale for the pool.
func (l *Lottery) addJob(j *job, clean bool, gen uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	j.id, j.gen, j.received = l.nextID, gen, l.now()
	if gen == l.gen {
		j.en1, j.en2Size, j.poolDiff = l.en1, l.en2Size, l.diff
	}
	if clean {
		l.cleanID = j.id
	}
	l.jobs[j.id] = j
	l.order = append(l.order, j.id)
	l.pruneLocked()
}

// pruneLocked drops jobs older than JobTTL (always keeping the newest) and beyond maxJobs.
func (l *Lottery) pruneLocked() {
	cut, now := 0, l.now()
	for cut < len(l.order)-1 && (len(l.order)-cut > maxJobs || now.Sub(l.jobs[l.order[cut]].received) > l.opt.JobTTL) {
		delete(l.jobs, l.order[cut])
		cut++
	}
	l.order = l.order[cut:]
}

func (l *Lottery) setErr(msg string) {
	l.mu.Lock()
	l.lastErr, l.lastErrAt = msg, l.now()
	l.mu.Unlock()
	l.opt.Logf("btc: %s", msg)
}

// parseNotify reads mining.notify: job_id, prevhash, coinb1, coinb2,
// merkle_branch, version, nbits, ntime, clean_jobs.
func parseNotify(p []any) (*job, bool, error) {
	if len(p) < 9 {
		return nil, false, errors.New("mining.notify: too few fields")
	}
	str := func(i int) string { s, _ := p[i].(string); return s }
	word := func(i int) (uint32, error) {
		b, err := hex.DecodeString(str(i))
		if err != nil || len(b) != 4 {
			return 0, fmt.Errorf("mining.notify: field %d is not 4 bytes of hex", i)
		}
		return binary.BigEndian.Uint32(b), nil
	}
	prev, err1 := hex.DecodeString(str(1))
	cb1, err2 := hex.DecodeString(str(2))
	cb2, err3 := hex.DecodeString(str(3))
	if err := errors.Join(err1, err2, err3); err != nil || len(prev) != 32 || str(0) == "" {
		return nil, false, errors.New("mining.notify: malformed job")
	}
	// The pool sends prevhash as eight 4-byte words, each byte-swapped.
	for i := 0; i < 32; i += 4 {
		prev[i], prev[i+1], prev[i+2], prev[i+3] = prev[i+3], prev[i+2], prev[i+1], prev[i]
	}
	j := &job{poolID: str(0), prevHash: prev, coinb1: cb1, coinb2: cb2, height: coinbaseHeight(cb1)}
	list, ok := p[4].([]any)
	if !ok {
		return nil, false, errors.New("mining.notify: malformed merkle branch")
	}
	for _, x := range list {
		s, _ := x.(string)
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil, false, errors.New("mining.notify: malformed merkle branch")
		}
		j.branch = append(j.branch, b)
	}
	var err error
	if j.version, err = word(5); err != nil {
		return nil, false, err
	}
	if j.nbits, err = word(6); err != nil {
		return nil, false, err
	}
	if t := compactTarget(j.nbits); j.nbits&0x00800000 != 0 || t.Sign() == 0 || t.BitLen() > 256 {
		return nil, false, errors.New("mining.notify: invalid block target")
	}
	if j.ntime, err = word(7); err != nil {
		return nil, false, err
	}
	clean, ok := p[8].(bool)
	if !ok {
		return nil, false, errors.New("mining.notify: invalid clean flag")
	}
	return j, clean, nil
}

// coinbaseHeight reads the block height that BIP34 puts first in the
// coinbase script (0 if it cannot): version 4, inputs 1, outpoint 36, script length 1.
func coinbaseHeight(cb1 []byte) uint64 {
	if len(cb1) < 43 {
		return 0
	}
	n := int(cb1[42])
	if n < 1 || n > 8 || len(cb1) < 43+n {
		return 0
	}
	var h uint64
	for i := n - 1; i >= 0; i-- {
		h = h<<8 | uint64(cb1[43+i])
	}
	return h
}
