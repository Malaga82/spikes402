package gate

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/persist"
)

// StatsPath is the opt-in public aggregate counter (GET/HEAD).
const StatsPath = "/.spikes402/stats"

const (
	statsFileName     = "public-stats.json"
	statsCacheFor     = 5 * time.Second
	statsPersistEvery = 30 * time.Second
	statsWindow       = 24 * time.Hour
	statsBuckets      = 24 * 60 // one bucket per minute
)

// PublicSnapshot is the JSON body of GET /.spikes402/stats.
// It holds only site-wide totals: no addresses, paths, or visitor data.
type PublicSnapshot struct {
	Since            time.Time    `json:"since"`
	Challenges       uint64       `json:"challenges"`
	UnlocksPoW       uint64       `json:"unlocks_pow"`
	UnlocksLightning uint64       `json:"unlocks_lightning"`
	SatsReceived     uint64       `json:"sats_received"`
	Last24h          PublicWindow `json:"last_24h"`
}

// PublicWindow is the same counters over a rolling window.
type PublicWindow struct {
	Challenges       uint64 `json:"challenges"`
	UnlocksPoW       uint64 `json:"unlocks_pow"`
	UnlocksLightning uint64 `json:"unlocks_lightning"`
	SatsReceived     uint64 `json:"sats_received"`
}

// PublicStats records aggregate counters for the optional public endpoint.
// Observe is cheap (a short lock and integer adds). Snapshot is served from
// a few-second cache so a flood of GETs does not walk the window every time.
//
// Challenges can be inflated by anyone who requests a 402 (subject to the
// existing per-client rate limit). Unlocks and sats_received only move when
// a token is successfully spent, which already costs proof-of-work or sats.
type PublicStats struct {
	now func() time.Time

	mu    sync.Mutex
	since time.Time
	all   PublicWindow
	// buckets[unixMinute%statsBuckets] holds that minute, or a stale one
	// which is zeroed before reuse.
	buckets [statsBuckets]minuteBucket
	dirty   bool

	cache      []byte
	cacheUntil time.Time
}

type minuteBucket struct {
	start int64 // unix minute, 0 means empty
	PublicWindow
}

// NewPublicStats starts empty, counting from now.
func NewPublicStats(now time.Time) *PublicStats {
	if now.IsZero() {
		now = time.Now()
	}
	return &PublicStats{now: time.Now, since: now.UTC()}
}

// LoadPublicStats restores a snapshot from dir if one is present.
// A missing file is a first run. A corrupt file is an error: the caller
// may start fresh.
func LoadPublicStats(dir string, now time.Time) (*PublicStats, error) {
	s := NewPublicStats(now)
	if dir == "" {
		return s, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, statsFileName))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.restore(data, now); err != nil {
		return nil, err
	}
	return s, nil
}

// StartPersisting writes a snapshot to dir every interval while ctx is
// live, and once more when ctx is cancelled. A zero interval uses the
// default (30s). No-ops if dir is empty or nothing has changed.
func (s *PublicStats) StartPersisting(ctx context.Context, dir string, every time.Duration) {
	if s == nil || dir == "" {
		return
	}
	if every <= 0 {
		every = statsPersistEvery
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				if err := s.Save(dir); err != nil {
					log.Printf("public stats: saving: %v", err)
				}
				return
			case <-t.C:
				if err := s.Save(dir); err != nil {
					log.Printf("public stats: saving: %v", err)
				}
			}
		}
	}()
}

// Observe records one gate event. It ignores visitor identity, path, and
// class. Only successful unlocks increase unlock counters; sats_received
// counts the token price of a Lightning unlock only.
func (s *PublicStats) Observe(e Event) {
	if s == nil {
		return
	}
	t := e.Time
	if t.IsZero() {
		t = s.now()
	}
	var inc PublicWindow
	switch e.Outcome {
	case OutcomeChallenged, OutcomeRejected:
		inc.Challenges = 1
	case OutcomePoW:
		inc.UnlocksPoW = 1
	case OutcomePaid:
		inc.UnlocksLightning = 1
		if e.Sats > 0 {
			inc.SatsReceived = uint64(e.Sats)
		}
	default:
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all.add(inc)
	s.addBucket(t, inc)
	s.dirty = true
	s.cache = nil
}

// Snapshot returns the current totals. last_24h uses event times.
func (s *PublicStats) Snapshot() PublicSnapshot {
	if s == nil {
		return PublicSnapshot{}
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(now)
}

func (s *PublicStats) snapshotLocked(now time.Time) PublicSnapshot {
	return PublicSnapshot{
		Since:            s.since,
		Challenges:       s.all.Challenges,
		UnlocksPoW:       s.all.UnlocksPoW,
		UnlocksLightning: s.all.UnlocksLightning,
		SatsReceived:     s.all.SatsReceived,
		Last24h:          s.sumWindow(now),
	}
}

// ServeHTTP answers GET/HEAD /.spikes402/stats with a cached JSON body.
func (s *PublicStats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := s.cachedJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=5")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (s *PublicStats) cachedJSON() ([]byte, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil && now.Before(s.cacheUntil) {
		return s.cache, nil
	}
	body, err := json.Marshal(s.snapshotLocked(now))
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	s.cache = body
	s.cacheUntil = now.Add(statsCacheFor)
	return body, nil
}

// Save writes the snapshot to dir if anything changed since the last save.
func (s *PublicStats) Save(dir string) error {
	if s == nil || dir == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := s.marshalState(s.now())
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.dirty = false
	s.mu.Unlock()
	if err := persist.WriteFile(dir, statsFileName, data); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

type statsState struct {
	Since            time.Time      `json:"since"`
	Challenges       uint64         `json:"challenges"`
	UnlocksPoW       uint64         `json:"unlocks_pow"`
	UnlocksLightning uint64         `json:"unlocks_lightning"`
	SatsReceived     uint64         `json:"sats_received"`
	Minutes          []persistedMin `json:"minutes,omitempty"`
}

type persistedMin struct {
	T int64 `json:"t"` // unix minute
	PublicWindow
}

func (s *PublicStats) marshalState(now time.Time) ([]byte, error) {
	st := statsState{
		Since:            s.since,
		Challenges:       s.all.Challenges,
		UnlocksPoW:       s.all.UnlocksPoW,
		UnlocksLightning: s.all.UnlocksLightning,
		SatsReceived:     s.all.SatsReceived,
	}
	cutoff := now.Add(-statsWindow).Unix() / 60
	for i := range s.buckets {
		b := s.buckets[i]
		if b.start > cutoff {
			st.Minutes = append(st.Minutes, persistedMin{T: b.start, PublicWindow: b.PublicWindow})
		}
	}
	return json.Marshal(st)
}

func (s *PublicStats) restore(data []byte, now time.Time) error {
	var st statsState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Since.IsZero() {
		return errors.New("public stats: missing since")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.since = st.Since.UTC()
	s.all = PublicWindow{
		Challenges:       st.Challenges,
		UnlocksPoW:       st.UnlocksPoW,
		UnlocksLightning: st.UnlocksLightning,
		SatsReceived:     st.SatsReceived,
	}
	s.buckets = [statsBuckets]minuteBucket{}
	cutoff := now.Add(-statsWindow).Unix() / 60
	for _, m := range st.Minutes {
		if m.T <= cutoff {
			continue
		}
		s.buckets[m.T%statsBuckets] = minuteBucket{start: m.T, PublicWindow: m.PublicWindow}
	}
	s.dirty = false
	s.cache = nil
	return nil
}

func (s *PublicStats) addBucket(t time.Time, inc PublicWindow) {
	min := t.Unix() / 60
	if min <= 0 {
		return
	}
	i := min % statsBuckets
	if s.buckets[i].start != min {
		s.buckets[i] = minuteBucket{start: min}
	}
	s.buckets[i].add(inc)
}

func (s *PublicStats) sumWindow(now time.Time) PublicWindow {
	cutoff := now.Add(-statsWindow).Unix() / 60
	nowMin := now.Unix() / 60
	var sum PublicWindow
	for i := range s.buckets {
		b := s.buckets[i]
		if b.start > cutoff && b.start <= nowMin {
			sum.add(b.PublicWindow)
		}
	}
	return sum
}

func (w *PublicWindow) add(inc PublicWindow) {
	w.Challenges += inc.Challenges
	w.UnlocksPoW += inc.UnlocksPoW
	w.UnlocksLightning += inc.UnlocksLightning
	w.SatsReceived += inc.SatsReceived
}
