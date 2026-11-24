package gate

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/pow"
)

// Settings are the options an admin may change while the gate runs.
// Changes are swapped in atomically and apply to new 402 offers.
type Settings struct {
	PriceSats           int64
	Prices              []PriceRule // first match wins; empty means use PriceSats only
	Protect             []string    // path patterns that require payment
	Paused              bool        // protected paths are free; no invoices
	ObserveOnly         bool        // dry-run: serve free, record URLs & prices that would get 402
	PoW                 func(priceSats int64) pow.Params
	Policies            map[string]Policy
	ChallengesPerMinute int
	Surge               SurgeConfig
}

// Settings returns the settings in force. Do not modify the Policies map.
func (g *Gate) Settings() Settings { return *g.live.Load() }

// UpdateSettings replaces the live settings. Validate user input with the
// config package first; this only rejects values that would break the gate.
func (g *Gate) UpdateSettings(s Settings) error {
	if s.PriceSats < 1 || s.PoW == nil || s.ChallengesPerMinute < 1 || len(s.Protect) < 1 {
		return errors.New("gate: invalid settings")
	}
	for _, p := range s.Policies {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	g.limiter.setPerMinute(s.ChallengesPerMinute)
	s.Prices = append([]PriceRule(nil), s.Prices...)
	s.Protect = append([]string(nil), s.Protect...)
	s.Surge = cloneSurge(s.Surge)
	if g.surge != nil {
		g.surge.setConfig(s.Surge, surgePatterns(s.Protect, s.Prices))
	}
	g.live.Store(&s)
	return nil
}

// Outcome is what happened to one request to a protected path.
type Outcome string

// Outcomes, from the visitor's point of view.
const (
	OutcomePaid        Outcome = "paid"         // valid Lightning payment proof
	OutcomePoW         Outcome = "pow-solved"   // valid proof-of-work
	OutcomeRetry       Outcome = "retry"        // retry of a previously accepted proof
	OutcomeChallenged  Outcome = "challenged"   // got a 402 offer
	OutcomeRejected    Outcome = "rejected"     // sent a wrong, expired or reused proof (got a new 402)
	OutcomeRateLimited Outcome = "rate-limited" // 429
	OutcomeBusy        Outcome = "busy"         // 503, proof-of-work checks full
	OutcomeBlocked     Outcome = "blocked"      // 403 by a bot policy
	OutcomeFree        Outcome = "free"         // let through by a bot policy (or while paused)
	OutcomeObserved    Outcome = "observed"     // observe_only dry-run: would have been challenged/blocked, served free
	OutcomePass        Outcome = "pass"         // let through with a pass cookie (a payment made a moment ago)
	OutcomeOpen        Outcome = "open"         // an unprotected path, forwarded as is (statistics only)
)

// Event describes one request to a protected path, for monitoring. It
// holds the raw client address: observers must anonymise it before
// storing or showing it.
type Event struct {
	Time     time.Time
	Client   string // rate-limit key: IPv4 address or IPv6 /64
	IP       net.IP
	Class    botid.Class
	Resource string
	Outcome  Outcome
	Sats     int64 // token price; counted as received only for OutcomePaid

	// Details for statistics; zero when not known. Like IP, they come from
	// the visitor: observers must not trust or show them unescaped.
	Open      bool          // an unprotected path (Outcome is OutcomeOpen); bot checks did not run
	UserAgent string        // the User-Agent header
	Session   string        // our session cookie, if the client sent one back
	Lang      bool          // the request had Accept-Language (browsers send it, most bots do not)
	HTML      bool          // the client accepts text/html
	Token     string        // ID of the token offered (402) or redeemed (paid, solved)
	Price     int64         // sats asked (402) or paid
	Algorithm string        // proof-of-work algorithm offered with a 402
	Status    int           // the origin's status, when the request reached it
	Latency   time.Duration // the origin's response time, when it was reached
	Page      bool          // the origin answered 2xx with an HTML page
}

// reqInfo collects a request's details for its Event as it goes through the gate.
type reqInfo struct {
	session, token, alg, ctype string
	price                      int64
	status                     int
	latency                    time.Duration
}

type infoKey struct{}

// info returns the request's details, or nil without an Observer.
func info(r *http.Request) *reqInfo {
	ri, _ := r.Context().Value(infoKey{}).(*reqInfo)
	return ri
}

func (g *Gate) observe(r *http.Request, class botid.Class, o Outcome) {
	if g.opt.Observer == nil && g.opt.PublicStats == nil && g.opt.PublicSiege == nil {
		return
	}
	e := Event{Time: g.now(), Client: g.client(r), IP: g.clientIP(r), Class: class, Resource: resource(r), Outcome: o,
		Open: o == OutcomeOpen, UserAgent: r.UserAgent(), Lang: r.Header.Get("Accept-Language") != "",
		HTML: strings.Contains(r.Header.Get("Accept"), "text/html")}
	if ri := info(r); ri != nil {
		e.Session, e.Token, e.Price, e.Algorithm, e.Status, e.Latency = ri.session, ri.token, ri.price, ri.alg, ri.status, ri.latency
		if o == OutcomePaid {
			e.Sats = ri.price
		}
		e.Page = ri.status >= 200 && ri.status < 300 && strings.Contains(ri.ctype, "text/html")
	}
	if o != OutcomeOpen {
		if g.opt.PublicStats != nil {
			g.opt.PublicStats.Observe(e)
		}
		if g.opt.PublicSiege != nil {
			g.opt.PublicSiege.Observe(e)
		}
	}
	if g.opt.Observer != nil {
		g.opt.Observer(e)
	}
}

// Status is a snapshot of the gate's internal state for the dashboard.
type Status struct {
	OpenInvoices int                `json:"open_invoices"`
	SpentTokens  int                `json:"spent_tokens"`
	Node         NodeStatus         `json:"node"`
	Surge        []SurgeGroupStatus `json:"surge,omitempty"`
	Lottery      any                `json:"lottery,omitempty"` // the Bitcoin lottery, if it reports its state
}

// NodeStatus describes the guard in front of the Lightning node.
type NodeStatus struct {
	BreakerOpen         bool      `json:"breaker_open"`
	BreakerOpenUntil    time.Time `json:"breaker_open_until,omitzero"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	InFlight            int       `json:"in_flight"`
	InvoiceBudget       float64   `json:"invoice_budget"` // invoices that may be created right now
	InvoicesCreated     uint64    `json:"invoices_created"`
	InvoiceFailures     uint64    `json:"invoice_failures"`
	LastError           string    `json:"last_error,omitempty"`
	LastErrorAt         time.Time `json:"last_error_at,omitzero"`
}

// Status returns a snapshot of the gate's state.
func (g *Gate) Status() Status {
	st := Status{OpenInvoices: g.pending.len(), SpentTokens: g.spent.len(), Node: g.node.status(g.now())}
	if g.surge != nil && g.live.Load().Surge.Active() {
		st.Surge = g.surgeStatus(g.live.Load(), g.now(), g.underPressure())
	}
	if l, ok := g.opt.Lottery.(interface{ Status() any }); ok {
		st.Lottery = l.Status()
	}
	return st
}
