// Package gate is the heart of Spikes402: an http.Handler that sits in
// front of a website and asks for "pay or PoW" on protected paths.
package gate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/lightning"
	"github.com/Choffolo/spikes402/internal/persist"
	"github.com/Choffolo/spikes402/pow"
)

// Options configure a Gate.
type Options struct {
	PriceSats    int64                            // default price of one request, in satoshis
	Protect      []string                         // path patterns that require payment
	Prices       []PriceRule                      // optional per-path prices; first match wins
	Paused       bool                             // serve protected paths free; create no invoices
	PoW          func(priceSats int64) pow.Params // the puzzle for a price
	ChallengeTTL time.Duration                    // how long a 402 challenge stays valid
	SecretKey    []byte                           // signs tokens; keep it secret
	Lightning    lightning.Backend
	Next         http.Handler // where paid/free requests go (the origin)

	// Abuse protection for unpaid requests.
	ChallengesPerMinute  int          // 402 answers per client per minute
	MaxInvoicesPerMinute int          // invoices created per minute, all clients together
	MaxPendingInvoices   int          // open invoices at once; beyond this, PoW only
	ClientIPHeader       string       // header with the client IP set by a trusted proxy, or ""
	TrustedProxies       []*net.IPNet // ClientIPHeader is only believed from these addresses

	// CaseSensitive makes Protect patterns match letter case exactly. Off
	// by default, because many websites serve /Premium and /premium alike.
	CaseSensitive bool

	// Bot identification (optional). Classifier nil: everyone is "unknown".
	// Policies empty (the default): everyone pays the same.
	Classifier *botid.Classifier
	Policies   map[string]Policy
	Surge      SurgeConfig

	// Observer, if set, is told about every request to a protected path.
	// It is called synchronously and must be fast.
	Observer func(Event)

	// Argon2MaxMemoryMiB is the most memory concurrent Argon2id checks may
	// use together. 0 means DefaultArgonMaxMemoryMiB (256). A single check
	// that needs more than this is refused (see config).
	Argon2MaxMemoryMiB int

	// Previews show a teaser of the protected page on the 402 page. The
	// first matching rule wins; no match (or mode "none") shows no teaser.
	Previews []PreviewRule

	// SpentStore, if set, records spent tokens on disk. SpentRecords is
	// the already-loaded contents (so New does not fail on a bad store).
	SpentStore   SpentStore
	SpentRecords []persist.SpentRecord

	// Lottery, if set, offers sha256d work on real Bitcoin block headers from a
	// solo pool, so every proof is also a lottery ticket (see lottery.go).
	Lottery Lottery
}

// PriceRule maps a path pattern (same syntax as Protect) to a price.
// Patterns are matched against the canonical path, like Protect.
type PriceRule struct {
	Pattern   string `json:"pattern"`
	PriceSats int64  `json:"price_sats"`
}

// ClassHeader is the response header that tells the client how it was
// classified, e.g. `verified; name="Googlebot"; method=ip-list`.
const ClassHeader = "Spikes402-Class"

// Gate is the pay-or-PoW http.Handler.
type Gate struct {
	opt     Options
	sign    signer
	spent   *spentSet
	limiter *rateLimiter
	pending *pendingOffers
	node    *nodeGuard
	now     func() time.Time // replaceable in tests
	live    atomic.Pointer[Settings]

	// argon limits memory used by concurrent Argon2id checks.
	argon *argonBudget

	preview *previewer // nil: no teasers

	invoices *invoiceCache // looks up whether a 402 invoice has been paid
	claimLim *rateLimiter  // polls of /.spikes402/claim, per client
	surge    *surger       // optional per-group demand / price multiplier

	nodeLog  rateLog // why no invoice was offered
	classLog rateLog // bot classifications
}

// New returns a Gate. It panics on programmer errors; validate user
// input with the config package first.
func New(opt Options) *Gate {
	if len(opt.SecretKey) < 32 || opt.Lightning == nil || opt.Next == nil || opt.PriceSats < 1 ||
		opt.ChallengeTTL <= 0 || opt.PoW == nil || opt.ChallengesPerMinute < 1 || opt.MaxPendingInvoices < 1 || opt.MaxInvoicesPerMinute < 1 {
		panic("gate: invalid options")
	}
	spent := newSpentSet()
	spent.store = opt.SpentStore
	spent.load(opt.SpentRecords)
	g := &Gate{
		opt:     opt,
		sign:    signer{opt.SecretKey},
		spent:   spent,
		limiter: newRateLimiter(opt.ChallengesPerMinute),
		pending: newPendingOffers(opt.MaxPendingInvoices),
		node:    newNodeGuard(opt.Lightning, opt.MaxInvoicesPerMinute),
		now:     time.Now,

		preview:  newPreviewer(opt),
		argon:    newArgonBudget(opt.Argon2MaxMemoryMiB),
		invoices: newInvoiceCache(opt.Lightning),
		claimLim: newRateLimiter(claimPerMinute),
		nodeLog:  rateLog{perMinute: 1},
		classLog: rateLog{perMinute: 60},
		surge:    newSurger(opt.Surge),
	}
	g.invoices.now = func() time.Time { return g.now() }
	g.live.Store(&Settings{
		PriceSats: opt.PriceSats, Prices: append([]PriceRule(nil), opt.Prices...),
		Protect: append([]string(nil), opt.Protect...), Paused: opt.Paused,
		PoW: opt.PoW, Policies: opt.Policies, ChallengesPerMinute: opt.ChallengesPerMinute,
		Surge: cloneSurge(opt.Surge),
	})
	return g
}

// ServeHTTP implements http.Handler.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RequestURI()) > MaxURIBytes {
		http.Error(w, "URI too long", http.StatusRequestURITooLong)
		return
	}
	if strings.HasPrefix(r.URL.Path, ReservedPrefix) {
		g.serveReserved(w, r)
		return
	}
	passes := takePassCookies(r) // read before session() removes them
	session := g.session(r)      // our cookies: not the origin's business
	set := g.live.Load()         // one consistent snapshot for this request
	// Refuse paths like "/free/../paid" or "/free%2f..%2fpaid": the origin
	// could normalise them into a protected path we did not recognise.
	if why := checkPath(r.URL, func(p string) bool { return g.protected(p, set) }); why != "" {
		http.Error(w, "bad path: "+why, http.StatusBadRequest)
		return
	}
	if g.opt.Observer != nil { // details for the statistics, filled in as the request goes
		r = r.WithContext(context.WithValue(r.Context(), infoKey{}, &reqInfo{session: session}))
	}
	if !g.protected(r.URL.Path, set) {
		if g.opt.Observer == nil {
			g.opt.Next.ServeHTTP(w, r)
			return
		}
		g.forward(w, r)
		g.observe(r, botid.Class{Kind: botid.Unknown}, OutcomeOpen)
		return
	}
	// A shared cache or CDN must not store a 402, a paid page, or a
	// protected answer served while paused or on a free policy.
	w = noStore(w)

	class := g.classify(r)
	w.Header().Set(ClassHeader, class.String())
	if set.Paused {
		r.Header.Del("Authorization")
		g.forward(w, r)
		g.observe(r, class, OutcomeFree)
		return
	}
	pol := g.policyFor(set, class)
	switch pol.Action {
	case ActionBlock:
		g.observe(r, class, OutcomeBlocked)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	case ActionFree:
		r.Header.Del("Authorization")
		g.forward(w, r)
		g.observe(r, class, OutcomeFree)
		return
	}
	// A pass (see pass.go) is a payment already made for this very page.
	if resHash := hashResource(resource(r)); r.Header.Get("Authorization") == "" && g.validPass(passes[passName(resHash)], resHash) {
		g.forward(w, r)
		g.observe(r, class, OutcomePass)
		return
	}
	price := pol.price(g.offerPrice(r.URL.Path, set))
	if session == "" {
		session = newSession(w, g.scheme(r) == "https")
	}
	key := g.pendingKey(r, price, pol.Action, session)

	var problem string
	if auth := r.Header.Get("Authorization"); auth != "" {
		c, first, err := g.redeem(r, auth, price)
		if err == nil {
			outcome := OutcomePaid
			scheme, _, _ := strings.Cut(auth, " ")
			if strings.EqualFold(scheme, "PoW") {
				outcome = OutcomePoW
			}
			if !first {
				outcome = OutcomeRetry
			}
			if ri := info(r); ri != nil {
				ri.token, ri.price = c.ID, c.PriceSats
			}
			g.pending.drop(c.ID)
			r.Header.Del("Authorization") // our credential, not the origin's business
			redeem := r.Header.Get(RedeemHeader)
			r.Header.Del(RedeemHeader)
			if redeem == redeemCookie && r.Method == http.MethodGet {
				g.issuePass(w, r, c.ID) // the page navigates next; the origin is not called yet
				g.observe(r, class, outcome)
				return
			}
			g.deliver(w, r, c.ID, scheme)
			g.observe(r, class, outcome)
			return
		}
		var busy *busyError
		if errors.As(err, &busy) {
			if busy.status == http.StatusTooManyRequests {
				g.observe(r, class, OutcomeRateLimited)
			} else {
				g.observe(r, class, OutcomeBusy)
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(busy.wait.Seconds()))))
			http.Error(w, busy.msg, busy.status)
			return
		}
		problem = err.Error()
	}
	g.challenge(w, r, set, class, problem, key, price, pol.Action == ActionPoWOnly)
}

// deliver sends a redeemed request to the origin. If the origin cannot answer
// (a transport error or a 5xx status, so nothing was delivered) a GET or HEAD
// gives the token back for a few more tries (see spentSet.release): a payer
// should not lose a payment to a hiccup of the site. Other methods may have
// changed something at the origin, so they never get a second try.
func (g *Gate) deliver(w http.ResponseWriter, r *http.Request, id, scheme string) {
	status := g.forward(w, r)
	if status >= 500 && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		g.spent.release(spentKey(scheme, id), g.now())
	}
}

// forward sends r to the origin and returns its status (200 if it wrote a
// body without one). With an Observer it also notes the response time and
// content type for the statistics.
func (g *Gate) forward(w http.ResponseWriter, r *http.Request) int {
	rec := &statusRecorder{ResponseWriter: w}
	start := time.Now()
	g.opt.Next.ServeHTTP(rec, r)
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	if ri := info(r); ri != nil {
		ri.status, ri.latency, ri.ctype = status, time.Since(start), w.Header().Get("Content-Type")
	}
	return status
}

// protectedCacheControl is set on every response for a protected path.
const protectedCacheControl = "private, no-store"

// noStore wraps w so the response is sent with Cache-Control:
// private, no-store. Unprotected paths are not wrapped, so the origin
// can still be cached as it asks.
func noStore(w http.ResponseWriter) http.ResponseWriter {
	return &cacheControlWriter{ResponseWriter: w, value: protectedCacheControl}
}

type cacheControlWriter struct {
	http.ResponseWriter
	value string
	wrote bool
}

func (w *cacheControlWriter) WriteHeader(code int) {
	if code >= 200 && !w.wrote {
		w.Header().Set("Cache-Control", w.value)
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheControlWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the real writer (flushing).
func (w *cacheControlWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// statusRecorder remembers the status code the origin answered with.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 && code >= 200 { // ignore 1xx
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the real writer (flushing).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// classify identifies the client and logs anything noteworthy.
func (g *Gate) classify(r *http.Request) botid.Class {
	if g.opt.Classifier == nil {
		return botid.Class{Kind: botid.Unknown}
	}
	c := g.opt.Classifier.Classify(r, g.clientIP(r), g.scheme(r))
	if c.Kind != botid.Unknown || c.Note != "" {
		g.classLog.printf(g.now(), "spikes402: %s; client=%s; resource=%q; user-agent=%q",
			sanitize(c.String()), g.client(r), sanitize(resource(r)), sanitize(r.UserAgent()))
	}
	return c
}

// scheme is "https" if the client reached us over TLS: directly, or via a
// trusted proxy that says so in X-Forwarded-Proto.
func (g *Gate) scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if ip := remoteIP(r); ip != nil && isTrusted(ip, g.opt.TrustedProxies) {
		first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
		if strings.EqualFold(strings.TrimSpace(first), "https") {
			return "https"
		}
	}
	return "http"
}

// protected reports whether p matches one of the configured patterns.
// Patterns use path.Match syntax ("/a/*.html"); a pattern ending in "/**"
// matches everything below that prefix ("/premium/**").
func (g *Gate) protected(p string, set *Settings) bool {
	p = matchKey(p, g.opt.CaseSensitive)
	for _, pat := range set.Protect {
		if !g.opt.CaseSensitive {
			pat = strings.ToLower(pat)
		}
		if matchPattern(pat, p) {
			return true
		}
	}
	return false
}

// pathPrice is the sats price for a request path: the first matching
// rule in set.Prices, or set.PriceSats if none match. Matching uses the
// same canonical path as protected().
func (g *Gate) pathPrice(p string, set *Settings) int64 {
	key := matchKey(p, g.opt.CaseSensitive)
	for _, r := range set.Prices {
		pat := r.Pattern
		if !g.opt.CaseSensitive {
			pat = strings.ToLower(pat)
		}
		if matchPattern(pat, key) {
			return r.PriceSats
		}
	}
	return set.PriceSats
}

// resource is what a token is bound to (as a hash): the method and the
// full path with query string. A token for one page cannot unlock another.
// The request Host is not part of the binding: a client can set Host to
// anything, so binding to it would let them mint or redeem a token for a
// host they chose. Use a configured public host if a site ever needs
// host-specific tokens.
func resource(r *http.Request) string {
	return r.Method + " " + r.URL.RequestURI()
}

var (
	errExpired     = errors.New("token expired")
	errWrongTarget = errors.New("token is for a different resource")
	errWrongPrice  = errors.New("token was issued for a lower price")
	errBadProof    = errors.New("wrong preimage or proof-of-work solution")
	errReplay      = errors.New("token already used")
	errScheme      = errors.New("unsupported Authorization scheme (use L402 or PoW)")
)

// busyError asks the client to retry later instead of getting a new 402.
type busyError struct {
	status int
	wait   time.Duration
	msg    string
}

func (e *busyError) Error() string { return e.msg }

// redeem checks an "L402 <token>:<preimage>" or "PoW <token>:<nonce>"
// credential and marks the token as spent if it is valid. It returns the
// token ID.
//
// A token is redeemed once. The one exception protects payers: whoever
// paid the invoice can still use it once even if the puzzle of the same
// offer was already solved (or burned by a wrong Argon2id answer), so a
// paid invoice is never worthless. Work after payment is refused.
func (g *Gate) redeem(r *http.Request, auth string, price int64) (claims, bool, error) {
	c, record, err := g.check(r, auth, price)
	if err != nil {
		return claims{}, false, err
	}
	scheme, _, _ := strings.Cut(auth, " ")
	if strings.EqualFold(scheme, "PoW") && g.spent.has(spentKey("L402", c.ID)) {
		return claims{}, false, errReplay
	}
	// Checked last, so a bad attempt does not burn a good token.
	first, err := g.spent.useFirst(spentKey(scheme, c.ID), time.Unix(c.Expires, 0), g.now())
	if err != nil {
		return claims{}, false, err
	}
	if first && record != nil {
		record()
	}
	return c, first, nil
}

// spentKey is the entry in the spent set for one way of redeeming a token.
func spentKey(scheme, id string) string {
	if strings.EqualFold(scheme, "PoW") {
		return "pow:" + id
	}
	return "pay:" + id
}

// check verifies a credential without spending it.
func (g *Gate) check(r *http.Request, auth string, price int64) (claims, func(), error) {
	scheme, cred, _ := strings.Cut(auth, " ")
	token, proof, ok := strings.Cut(strings.TrimSpace(cred), ":")
	if !ok {
		return claims{}, nil, errBadToken
	}
	c, err := g.sign.verify(token)
	if err != nil {
		return claims{}, nil, err
	}
	if g.now().Unix() >= c.Expires {
		return claims{}, nil, errExpired
	}
	if c.Resource != hashResource(resource(r)) {
		return claims{}, nil, errWrongTarget
	}
	if c.Kind != "" { // a pass is not a token
		return claims{}, nil, errBadToken
	}

	switch strings.ToUpper(scheme) {
	case "L402", "LSAT": // LSAT is the older name of L402
		preimage, err := hex.DecodeString(proof)
		want, err2 := hex.DecodeString(c.PaymentHash)
		if err != nil || err2 != nil || len(preimage) != 32 || len(want) != 32 {
			return claims{}, nil, errBadProof
		}
		got := sha256.Sum256(preimage)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return claims{}, nil, errBadProof
		}
	case "POW":
		// The work was priced when the token was issued; it must still cover
		// today's price. (A token without a price, from an older version, never does.)
		if c.PriceSats < price {
			return claims{}, nil, errWrongPrice
		}
		nonce, err := strconv.ParseUint(proof, 10, 64)
		if c.PowAlg == pow.Bitcoin {
			if err != nil || nonce > 0xFFFFFFFF {
				return claims{}, nil, errBadProof
			}
			record, err := g.checkLottery(c, uint32(nonce))
			return c, record, err
		}
		p := c.powParams()
		if err != nil || p.Validate() != nil {
			return claims{}, nil, errBadProof
		}
		if p.Algorithm == pow.Argon2id {
			return c, nil, g.checkArgon(r, p, token, nonce, c)
		}
		if !p.Check(token, nonce) {
			return claims{}, nil, errBadProof
		}
	default:
		return claims{}, nil, errScheme
	}
	return c, nil, nil
}

// checkArgon verifies an Argon2id solution. A check costs the server tens
// of MiB and milliseconds, so it is only done for a genuine, unexpired,
// unused token of ours (checked above and here), counts against the
// client's rate limit, runs only if the memory budget has room, and a
// wrong answer burns the token: one check per token, ever.
func (g *Gate) checkArgon(r *http.Request, p pow.Params, token string, nonce uint64, c claims) error {
	now := g.now()
	if g.spent.has(spentKey("PoW", c.ID)) {
		return errReplay
	}
	if ok, wait := g.limiter.allow(g.client(r), now); !ok {
		return &busyError{http.StatusTooManyRequests, wait, "too many requests"}
	}
	if !g.argon.acquire(p.MemoryMiB, argonAcquireWait) {
		return &busyError{http.StatusServiceUnavailable, time.Second, "busy checking proofs of work, retry shortly"}
	}
	defer g.argon.release(p.MemoryMiB)
	if !p.Check(token, nonce) {
		if err := g.spent.use(spentKey("PoW", c.ID), time.Unix(c.Expires, 0), now); err != nil {
			return err
		}
		return errBadProof
	}
	return nil
}

// challengeBody is the JSON answer to an unpaid request.
type challengeBody struct {
	Error     string        `json:"error"`
	Problem   string        `json:"problem,omitempty"`
	Resource  string        `json:"resource"`
	PriceSats int64         `json:"price_sats"`
	ExpiresAt time.Time     `json:"expires_at"`
	L402      *l402Offer    `json:"l402,omitempty"`
	PoW       powOffer      `json:"pow"`
	Preview   *Preview      `json:"preview,omitempty"` // teaser, if the site configured one
	Lottery   *lotteryOffer `json:"lottery,omitempty"`
}

type l402Offer struct {
	Token   string `json:"token"`
	Invoice string `json:"invoice"`
	Usage   string `json:"usage"`
	Claim   string `json:"claim,omitempty"` // GET /.spikes402/claim with Authorization: Bearer <token>
}

type powOffer struct {
	Challenge       string  `json:"challenge"`
	Difficulty      int     `json:"difficulty"`
	Algorithm       string  `json:"algorithm"`
	MemoryMiB       int     `json:"memory_mib,omitempty"`
	ExpectedSeconds float64 `json:"expected_seconds_one_cpu_core"`
	Usage           string  `json:"usage"`
}

// pendingKey identifies one client's offer for one page. It includes the
// session cookie, so two clients behind the same IP never share an offer;
// a client without the cookie gets a new session, hence its own offer, on
// every request (still bounded by the per-IP limit and the invoice caps).
func (g *Gate) pendingKey(r *http.Request, price int64, a Action, session string) string {
	return g.client(r) + " " + strconv.FormatInt(price, 10) + " " + string(a) + " " + hashResource(resource(r)) + " " + session
}

func (g *Gate) client(r *http.Request) string {
	return clientKey(r, g.opt.ClientIPHeader, g.opt.TrustedProxies)
}

func (g *Gate) clientIP(r *http.Request) net.IP {
	return clientIP(r, g.opt.ClientIPHeader, g.opt.TrustedProxies)
}

// challenge answers 402 Payment Required with both ways in, or 429 Too
// Many Requests if this client asked for too many challenges.
func (g *Gate) challenge(w http.ResponseWriter, r *http.Request, set *Settings, class botid.Class, problem, key string, price int64, powOnly bool) {
	now := g.now()
	if ok, wait := g.limiter.allow(g.client(r), now); !ok {
		g.observe(r, class, OutcomeRateLimited)
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if g.surge != nil && set.Surge.Active() {
		g.surge.hit(g.groupOf(r.URL.Path, set), now, g.underPressure())
	}

	// Same client, same page, offer still fresh: hand it out again rather
	// than creating another invoice.
	o, ok := g.pending.get(key, now, g.opt.ChallengeTTL/2)
	if !ok || g.spent.has(spentKey("PoW", o.id)) || g.spent.has(spentKey("L402", o.id)) {
		var err error
		if o, err = g.newOffer(r, now, key, set.PoW(price), price, powOnly); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if ri := info(r); ri != nil {
		ri.token, ri.price, ri.alg = o.id, o.price, o.pow.Algorithm
	}
	if problem != "" {
		g.observe(r, class, OutcomeRejected)
	} else {
		g.observe(r, class, OutcomeChallenged)
	}
	g.writeChallenge(w, r, o, problem, g.newLotteryOffer(r, now, o.pow, price))
}

// newOffer creates a token and, if there is room, an invoice.
func (g *Gate) newOffer(r *http.Request, now time.Time, key string, p pow.Params, price int64, powOnly bool) (offer, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return offer{}, err
	}
	c := claims{
		ID:        hex.EncodeToString(id),
		Resource:  hashResource(resource(r)),
		PriceSats: price,
		Expires:   now.Add(g.opt.ChallengeTTL).Unix(),
	}
	c.PowBits = p.Difficulty
	if p.Algorithm == pow.Argon2id {
		c.PowAlg, c.PowMem = p.Algorithm, p.MemoryMiB
	}

	// Proof-of-work is always offered. An invoice only if the node may be
	// called: not too many open invoices, within the global rate, node
	// healthy, and the policy for this client allows it.
	var invoice string
	gotSlot := !powOnly && g.pending.reserve(now)
	if gotSlot {
		inv, err := g.node.createInvoice(now, price, memo(resource(r)), g.opt.ChallengeTTL)
		if err != nil {
			g.pending.cancelReserve()
			gotSlot = false
			g.nodeLog.printf(now, "spikes402: no invoice, offering proof-of-work only: %v", err)
		} else {
			c.PaymentHash = hex.EncodeToString(inv.PaymentHash[:])
			invoice = inv.PaymentRequest
		}
	}

	token, err := g.sign.sign(c)
	if err != nil {
		if gotSlot {
			g.pending.cancelReserve()
		}
		return offer{}, err
	}
	o := offer{id: c.ID, token: token, invoice: invoice, expires: time.Unix(c.Expires, 0), price: price, pow: p}
	if invoice != "" {
		o.qr = string(invoiceQR(invoice))
		g.pending.put(key, o)
	} else if gotSlot {
		g.pending.cancelReserve()
	}
	return o, nil
}

func (g *Gate) writeChallenge(w http.ResponseWriter, r *http.Request, o offer, problem string, lo *lotteryOffer) {
	body := challengeBody{
		Error:     "payment required",
		Problem:   problem,
		Resource:  resource(r),
		PriceSats: o.price,
		ExpiresAt: o.expires.UTC(),
		PoW: powOffer{
			Challenge:       o.token,
			Difficulty:      o.pow.Difficulty,
			Algorithm:       o.pow.Algorithm,
			ExpectedSeconds: math.Round(o.pow.ExpectedSeconds()*10) / 10,
			Usage:           `find nonce so that SHA256(SHA256(challenge + ":" + nonce)) has "difficulty" leading zero bits, then send "Authorization: PoW <challenge>:<nonce>"`,
		},
	}
	powHeader := fmt.Sprintf(`PoW challenge=%q, difficulty="%d", algorithm="sha256d"`, o.token, o.pow.Difficulty)
	if o.pow.Algorithm == pow.Argon2id {
		body.PoW.MemoryMiB = o.pow.MemoryMiB
		body.PoW.Usage = `find nonce so that Argon2id(password = challenge + ":" + nonce, salt = "spikes402-pow-v1", time = 1, memory = memory_mib MiB, threads = 1, 32 bytes) has "difficulty" leading zero bits, then send "Authorization: PoW <challenge>:<nonce>"`
		powHeader = fmt.Sprintf(`PoW challenge=%q, difficulty="%d", algorithm="argon2id", memory-mib="%d"`, o.token, o.pow.Difficulty, o.pow.MemoryMiB)
	}

	body.Preview = g.preview.get(r)
	h := w.Header()
	if o.invoice != "" {
		h.Add("WWW-Authenticate", fmt.Sprintf(`L402 macaroon=%q, invoice=%q`, o.token, o.invoice))
		body.L402 = &l402Offer{
			Token:   o.token,
			Invoice: o.invoice,
			Usage:   `pay the invoice, then send "Authorization: L402 <token>:<preimage hex>". To learn that an external wallet paid, GET ` + ClaimPath + ` with "Authorization: Bearer <token>"; when paid, the body contains the preimage.`,
			Claim:   ClaimPath,
		}
	}
	h.Add("WWW-Authenticate", powHeader)
	if lo != nil { // after the ordinary puzzle, so older clients keep solving that
		body.Lottery = lo
		h.Add("WWW-Authenticate", lo.header())
	}
	h.Set("Cache-Control", protectedCacheControl)

	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", pageCSP)
		w.WriteHeader(http.StatusPaymentRequired)
		writeHTML(w, body, template.URL(o.qr))
		return
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(body)
}
