package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/persist"
)

// spentSet remembers redeemed token IDs until they expire, so that each
// token can be used only once. When a SpentStore is set, a use is written
// to disk before use returns, so a restart cannot replay a spent token.
// The id is reserved in memory first and the (slow) disk write happens
// without holding mu, so a slow disk never blocks other lookups; if the
// write fails the reservation is undone and the token is not spent.
//
// One exception, for payers: if the origin fails to answer (see release),
// the token can be used again, a few times and only for a short while.
//
// Keys are compact: 1 byte kind + 16-byte id. Expiry is stored as Unix
// seconds. The public methods still take the same string ids as before.
// SpentStore persists spent tokens across restarts.
type SpentStore interface {
	Persist(persist.SpentRecord) error
}

type spentSet struct {
	mu        sync.Mutex
	ids       map[spentID]spentEntry
	max       int
	inserts   int
	lastSweep time.Time
	store     SpentStore
}

// spentID is "pay" or "pow" plus the 16-byte token id.
type spentID [17]byte

type spentEntry struct {
	expires  int64 // Unix seconds
	first    int64 // Unix seconds of first use
	retries  int   // how often it was given back
	released bool  // given back and not used again yet
}

const (
	spentKindPay   byte = 1
	spentKindPoW   byte = 2
	spentKindOther byte = 0 // tests and unexpected ids
)

// A token whose request the origin could not answer can be retried at most
// maxRetries times, within retryWindow of its first use. Whatever happens,
// it is delivered at most once.
const (
	maxRetries  = 3
	retryWindow = 30 * time.Second
)

// maxSpent bounds the memory of the spent set (about 128 MiB, ~134 bytes
// per entry, measured with HeapAlloc at the cap).
const maxSpent = 1_000_000

func newSpentSet() *spentSet {
	return &spentSet{ids: make(map[spentID]spentEntry), max: maxSpent}
}

func (s *spentSet) load(recs []persist.SpentRecord) {
	for _, r := range recs {
		s.ids[compactID(r.ID)] = spentEntry{expires: r.Expires, first: r.First, retries: r.Retries, released: r.Released}
	}
}

func toSpentRecord(id string, e spentEntry) persist.SpentRecord {
	return persist.SpentRecord{ID: id, Expires: e.expires, First: e.first, Retries: e.retries, Released: e.released}
}

// compactID packs a spent-set key. Production keys are "pay:" or "pow:"
// followed by a 32-character hex id (16 bytes). Anything else is hashed,
// so existing tests that use short names keep working.
func compactID(id string) spentID {
	var k spentID
	kind, rest, ok := strings.Cut(id, ":")
	if ok && len(rest) == 32 {
		if raw, err := hex.DecodeString(rest); err == nil && len(raw) == 16 {
			switch kind {
			case "pay":
				k[0] = spentKindPay
			case "pow":
				k[0] = spentKindPoW
			default:
				k[0] = spentKindOther
			}
			if k[0] != spentKindOther {
				copy(k[1:], raw)
				return k
			}
		}
	}
	k[0] = spentKindOther
	sum := sha256.Sum256([]byte(id))
	copy(k[1:], sum[:16])
	return k
}

// errBusy is returned when the spent set is full of unexpired tokens.
var errBusy = errors.New("server busy, try again later")

// use marks id as spent. It returns errReplay if id was already spent,
// or errBusy if the set is full: refusing is safer than forgetting.
func (s *spentSet) use(id string, expires, now time.Time) error {
	_, err := s.useFirst(id, expires, now)
	return err
}

// useFirst is use, and also tells a new redemption (true) from the retry
// of a released proof (false).
func (s *spentSet) useFirst(id string, expires, now time.Time) (bool, error) {
	s.mu.Lock()
	key := compactID(id)
	if e, seen := s.ids[key]; seen {
		if e.released && now.Unix() < e.first+int64(retryWindow.Seconds()) {
			prev := e
			e.released = false
			s.ids[key] = e // reserve
			s.mu.Unlock()
			if err := s.persist(id, e); err != nil {
				s.mu.Lock()
				s.ids[key] = prev
				s.mu.Unlock()
				return false, err
			}
			return false, nil
		}
		s.mu.Unlock()
		return false, errReplay
	}
	s.inserts++
	// Forget entries that can no longer be replayed: every 1024 inserts,
	// or when full (at most once a second, so a full set stays cheap).
	if s.inserts%1024 == 0 || (len(s.ids) >= s.max && now.Sub(s.lastSweep) >= time.Second) {
		unix := now.Unix()
		for k, e := range s.ids {
			if unix > e.expires {
				delete(s.ids, k)
			}
		}
		s.lastSweep = now
	}
	if len(s.ids) >= s.max {
		s.mu.Unlock()
		return false, errBusy
	}
	e := spentEntry{expires: expires.Unix(), first: now.Unix()}
	s.ids[key] = e // reserve: a concurrent use of the same id is a replay
	s.mu.Unlock()
	if err := s.persist(id, e); err != nil {
		s.mu.Lock()
		delete(s.ids, key)
		s.mu.Unlock()
		return false, err
	}
	return true, nil
}

// persist writes a record to disk. It must be called without s.mu held.
func (s *spentSet) persist(id string, e spentEntry) error {
	if s.store == nil {
		return nil
	}
	if err := s.store.Persist(toSpentRecord(id, e)); err != nil {
		return errBusy
	}
	return nil
}

// release gives a token back after the origin failed to answer, so the same
// request can be tried again. It does nothing once the retries or the
// window are used up. The caller only calls it when nothing was delivered.
func (s *spentSet) release(id string, now time.Time) {
	s.mu.Lock()
	key := compactID(id)
	e, ok := s.ids[key]
	if !ok || e.released || e.retries >= maxRetries || now.Unix() >= e.first+int64(retryWindow.Seconds()) {
		s.mu.Unlock()
		return
	}
	e.retries++
	e.released = true
	s.ids[key] = e
	s.mu.Unlock()
	_ = s.persist(id, e) // if disk fails, still release in this process
}

func (s *spentSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ids)
}

// has reports whether id was already spent (and not given back).
func (s *spentSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, seen := s.ids[compactID(id)]
	return seen && !e.released
}
