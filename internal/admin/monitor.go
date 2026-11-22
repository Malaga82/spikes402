// Package admin is the admin API and dashboard of Spikes402: statistics,
// the live "siege" monitor, safe settings, change proposals (for an AI
// admin) and, if enabled, withdrawals to a fixed destination.
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/gate"
)

// Bounds of the monitor's memory.
const (
	ringSize   = 1000 // recent visits kept for the siege feed
	maxPerPoll = 200  // visits returned by one poll
	maxBotKeys = 200  // distinct bot names counted; the rest go to "other"
	maxPathLen = 80
)

// Visit is one request to a protected path, as the dashboard shows it.
type Visit struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Visitor string    `json:"visitor"` // anonymised client, see Monitor
	Class   string    `json:"class"`   // verified-signed, verified, impostor, unknown
	Bot     string    `json:"bot,omitempty"`
	Path    string    `json:"path"` // without query string
	Outcome string    `json:"outcome"`
}

// Counts are totals since start.
type Counts struct {
	Since     time.Time         `json:"since"`
	Total     uint64            `json:"total"`
	ByOutcome map[string]uint64 `json:"by_outcome"`
	ByClass   map[string]uint64 `json:"by_class"`
	ByBot     map[string]uint64 `json:"by_bot"`
}

// Monitor records gate events in a fixed-size ring buffer plus counters.
// Visitor addresses are anonymised before they are stored:
//
//	"hash"     (default) a keyed hash, stable until restart: "v-3fa2c1d9e07b"
//	"truncate" the network only: "203.0.113.0/24", "2001:db8:1::/48"
//	"full"     the address (IPv6 as its /64)
type Monitor struct {
	mode string
	salt []byte

	mu     sync.Mutex
	ring   [ringSize]Visit
	next   uint64 // sequence number of the next visit (first is 1)
	counts Counts

	stats *Stats
}

// NewMonitor returns an empty monitor.
func NewMonitor(visitorIPs string, now time.Time) *Monitor {
	salt := make([]byte, 32)
	rand.Read(salt)
	return &Monitor{mode: visitorIPs, salt: salt, next: 1, stats: newStats(now), counts: Counts{
		Since: now, ByOutcome: map[string]uint64{}, ByClass: map[string]uint64{}, ByBot: map[string]uint64{},
	}}
}

// Observe is a gate.Options.Observer.
func (m *Monitor) Observe(e gate.Event) {
	visitor := m.anonymise(e.IP, e.Client)
	m.stats.add(e, visitor)
	if e.Open { // unprotected paths feed the statistics only, not the siege view
		return
	}
	v := Visit{
		Time:    e.Time.UTC(),
		Visitor: visitor,
		Class:   string(e.Class.Kind),
		Bot:     botName(e.Class),
		Path:    cleanPath(e.Resource),
		Outcome: string(e.Outcome),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Seq = m.next
	m.ring[m.next%ringSize] = v
	m.next++
	c := &m.counts
	c.Total++
	c.ByOutcome[v.Outcome]++
	c.ByClass[v.Class]++
	if v.Bot != "" {
		key := v.Bot
		if v.Class == string(botid.Impostor) {
			key = "fake " + key
		}
		if _, ok := c.ByBot[key]; !ok && len(c.ByBot) >= maxBotKeys {
			key = "other"
		}
		c.ByBot[key]++
	}
}

// Since returns the visits after seq (at most the newest maxPerPoll) and
// the sequence number to ask for next time.
func (m *Monitor) Since(seq uint64) ([]Visit, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	last := m.next - 1
	first := seq + 1
	if last >= ringSize && first < last-ringSize+1 {
		first = last - ringSize + 1
	}
	if last >= maxPerPoll && first < last-maxPerPoll+1 {
		first = last - maxPerPoll + 1
	}
	out := []Visit{}
	for s := first; s <= last && s >= 1; s++ {
		out = append(out, m.ring[s%ringSize])
	}
	return out, last
}

// Counts returns a copy of the counters.
func (m *Monitor) Counts() Counts {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.counts
	c.ByOutcome = clone(c.ByOutcome)
	c.ByClass = clone(c.ByClass)
	c.ByBot = clone(c.ByBot)
	return c
}

func clone(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (m *Monitor) anonymise(ip net.IP, client string) string {
	switch m.mode {
	case "full":
		return client
	case "truncate":
		if ip == nil {
			return "?"
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		}
		return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
	default:
		mac := hmac.New(sha256.New, m.salt)
		mac.Write([]byte(client))
		return "v-" + hex.EncodeToString(mac.Sum(nil)[:6])
	}
}

// botName is the bot's name, or for Web Bot Auth the host of its key
// directory (shorter than the full URL).
func botName(c botid.Class) string {
	if c.Name == "" {
		return ""
	}
	if c.Kind == botid.Signed {
		if u, err := url.Parse(c.Name); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return truncate(c.Name, 64)
}

// cleanPath turns "GET /a/b?x=1" into "/a/b" (no query: it may hold personal data).
func cleanPath(resource string) string {
	_, p, _ := strings.Cut(resource, " ")
	p, _, _ = strings.Cut(p, "?")
	return truncate(p, maxPathLen)
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Stats returns the statistics report for rng ("24h", "7d", "30d"), with the
// clients table filtered to kind ("" for all).
func (m *Monitor) Stats(rng, kind string, now time.Time) Report {
	return m.stats.report(rng, kind, m.mode, now)
}

// PersistStats loads the statistics saved at path and keeps saving them
// there every 30 seconds while they change.
// shortcut: no save on shutdown (the process exits through log.Fatal), so up to 30 s are lost; add one if graceful shutdown arrives.
func (m *Monitor) PersistStats(path, legacyPath string, logf func(string, ...any)) {
	source := path
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		source = legacyPath
	}
	if err := m.stats.load(source, time.Now()); err != nil {
		logf("admin: statistics in %s not loaded: %v", source, err)
	}
	go m.stats.run(context.Background(), path, 30*time.Second, logf)
}
