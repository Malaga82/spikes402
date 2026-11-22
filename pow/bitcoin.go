package pow

// The Bitcoin lottery puzzle ("bitcoin"): the same double SHA-256 as
// sha256d, but over a real Bitcoin block header from a solo pool. The client
// searches the header's 4-byte nonce; a hash that clears the gate's
// difficulty unlocks the page, and one that also clears the pool's (or the
// network's) target is a real share (or a real block). See internal/btc.
//
// Difficulty is in bits, counted the way Bitcoin shows hashes: the hash read
// as a 256-bit little-endian number must be below 2^(256-bits).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	Bitcoin = "bitcoin"

	HeaderPrefixLen = 76 // a block header without its nonce
	MaxBitcoinBits  = 30 // the nonce has 2^32 values: past ~30 bits an honest solver could run out
)

// ErrJobGone means the mining job a token refers to is no longer known (too
// old, or the server restarted): ask for a new challenge.
var ErrJobGone = errors.New("pow: mining job expired")

// BitcoinWork is one lottery puzzle: Header is a block header without its
// nonce (76 bytes); find a nonce whose header hash has at least Bits zero bits.
type BitcoinWork struct {
	Header []byte
	Bits   int
}

// Validate checks the work is well formed and within the accepted bounds.
func (w BitcoinWork) Validate() error {
	switch {
	case len(w.Header) != HeaderPrefixLen:
		return errors.New("pow: a Bitcoin header without its nonce is 76 bytes")
	case w.Bits < 1 || w.Bits > MaxBitcoinBits:
		return ErrTooHard
	}
	return nil
}

// HeaderHash is SHA256(SHA256(header || nonce as 4 little-endian bytes)), in
// the order SHA-256 returns it (Bitcoin shows it reversed).
func HeaderHash(header []byte, nonce uint32) [32]byte {
	var full [80]byte
	copy(full[:], header)
	binary.LittleEndian.PutUint32(full[76:], nonce)
	first := sha256.Sum256(full[:])
	return sha256.Sum256(first[:])
}

// HashZeroBits counts zero bits from the most significant end of h read as a
// little-endian number (the leading zeros of the hash as Bitcoin shows it).
func HashZeroBits(h [32]byte) int {
	n := 0
	for i := 31; i >= 0; i-- {
		if h[i] != 0 {
			return n + bits.LeadingZeros8(h[i])
		}
		n += 8
	}
	return n
}

// Check reports whether nonce solves the work.
func (w BitcoinWork) Check(nonce uint32) bool {
	return w.Validate() == nil && HashZeroBits(HeaderHash(w.Header, nonce)) >= w.Bits
}

// Solve searches the nonces with workers goroutines (0: one per CPU).
func (w BitcoinWork) Solve(ctx context.Context, workers int) (uint32, error) {
	if err := w.Validate(); err != nil {
		return 0, err
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var (
		next  atomic.Uint64
		found atomic.Bool
		once  sync.Once
		nonce uint32
		wg    sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var full [80]byte
			copy(full[:], w.Header)
			for !found.Load() && ctx.Err() == nil {
				start := next.Add(4096) - 4096
				if start >= 1<<32 {
					return
				}
				for n := start; n < start+4096 && n < 1<<32; n++ {
					binary.LittleEndian.PutUint32(full[76:], uint32(n))
					first := sha256.Sum256(full[:])
					if HashZeroBits(sha256.Sum256(first[:])) >= w.Bits {
						once.Do(func() { nonce = uint32(n) })
						found.Store(true)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	switch {
	case found.Load():
		return nonce, nil
	case ctx.Err() != nil:
		return 0, ctx.Err()
	}
	return 0, errors.New("pow: no solution among the 2^32 nonces")
}
