package gate

// The Bitcoin lottery (Options.Lottery, internal/btc): with every sha256d
// challenge the gate also offers the same work on a real block header from
// a solo pool. The answer unlocks the page like any proof of work and is a
// lottery ticket too: the pool gets it if it clears the pool's target.
//
// The ordinary puzzle comes first in WWW-Authenticate, so clients that do
// not know "bitcoin" keep working; the lottery is a second PoW challenge with
// its own token (proof-of-work only, no invoice).

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/Choffolo/spikes402/pow"
)

// Lottery hands out block headers and checks answers on them (internal/btc).
type Lottery interface {
	// Offer gives a header (76 bytes, no nonce) of the newest job with its
	// own extranonce2; ok is false if no job is usable.
	Offer(bits int) (job uint32, en2 uint64, header []byte, ok bool)
	// Check verifies a nonce and returns what to record after the first redemption.
	// It returns pow.ErrJobGone if the job is no longer known.
	Check(job uint32, en2 uint64, nonce uint32, bits int) (record func(), err error)
	// Has reports whether the job can still be used for new challenges.
	Has(job uint32) bool
}

const lotteryUsage = `find a 32-bit nonce so that SHA256(SHA256(header + nonce as 4 little-endian bytes)), read as a 256-bit little-endian number (the way Bitcoin shows block hashes), has "difficulty" leading zero bits, then send "Authorization: PoW <challenge>:<nonce in decimal>". header is a real Bitcoin block header without its nonce: a hash good enough for the network is a block.`

// lotteryOffer is the lottery part of a 402 answer.
type lotteryOffer struct {
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
	Algorithm  string `json:"algorithm"`
	Header     string `json:"header"`
	Usage      string `json:"usage"`
	job        uint32 // the pool job its header comes from
}

func (lo *lotteryOffer) header() string {
	return fmt.Sprintf(`PoW challenge=%q, difficulty="%d", algorithm=%q, header="%s"`, lo.Challenge, lo.Difficulty, pow.Bitcoin, lo.Header)
}

// newLotteryOffer is the lottery challenge of offer o: the same token ID,
// price and expiry, so solving either puzzle (or paying) spends the one
// offer, and the same difficulty (one header hash costs about the same as
// one sha256d attempt). nil when the puzzle is not sha256d, is too hard for
// a 32-bit nonce, or no job is usable.
func (g *Gate) newLotteryOffer(r *http.Request, o offer) *lotteryOffer {
	bits := o.pow.Difficulty
	if g.opt.Lottery == nil || o.pow.Algorithm != pow.SHA256d || bits < 1 || bits > pow.MaxBitcoinBits {
		return nil
	}
	job, en2, h, ok := g.opt.Lottery.Offer(bits)
	if !ok {
		return nil
	}
	tok, err := g.sign.sign(claims{ID: o.id, Resource: hashResource(resource(r)), PriceSats: o.price,
		Expires: o.expires.Unix(), PowBits: bits, PowAlg: pow.Bitcoin, LotJob: job, LotEn2: en2})
	if err != nil {
		return nil
	}
	return &lotteryOffer{Challenge: tok, Difficulty: bits, Algorithm: pow.Bitcoin, Header: hex.EncodeToString(h), Usage: lotteryUsage, job: job}
}

// checkLottery verifies an answer on a lottery token: a few SHA-256 runs, as
// cheap as the ordinary puzzle, so no extra limits.
func (g *Gate) checkLottery(c claims, nonce uint32) (func(), error) {
	if g.opt.Lottery == nil {
		return nil, errJobGone
	}
	record, err := g.opt.Lottery.Check(c.LotJob, c.LotEn2, nonce, c.PowBits)
	switch {
	case err == nil:
		return record, nil
	case errors.Is(err, pow.ErrJobGone):
		return nil, errJobGone
	}
	return nil, errBadProof
}

var errJobGone = errors.New("the mining job of this token has expired, ask again")
