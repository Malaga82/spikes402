package gate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/lightning"
)

// ClaimPath is the reserved endpoint a browser (or a bot) polls to learn
// whether the 402 page's Lightning invoice has been paid, without already
// knowing the preimage. It is answered before any protect rule is applied
// and never reaches the origin.
const ClaimPath = "/.spikes402/claim"

// Polling and node-lookup limits. Many tabs watching the same invoice
// share one lookup (see invoiceCache); these caps bound what is left.
const (
	claimPerMinute  = 60 // claim requests per client per minute
	lookupUnpaidTTL = 1500 * time.Millisecond
	lookupFailTTL   = 1500 * time.Millisecond
	lookupBurst     = 4           // node lookups in flight
	lookupPerMin    = 120         // node lookups per minute, all invoices
	lookupTimeout   = nodeTimeout // same 3s bound as invoice creation
	lookupCacheMax  = 10_000      // cached results (a few MiB at most)
)

// invoiceCache looks up invoice status, coalescing concurrent calls for
// the same payment hash and caching the result briefly so a page that
// polls every 1–2s does not turn into a node call every time.
type invoiceCache struct {
	lookup lightning.IncomingLookup // nil: this backend cannot be asked
	now    func() time.Time
	sem    chan struct{}

	mu       sync.Mutex
	cache    map[string]invoiceEntry
	inflight map[string]*invoiceCall
	window   time.Time
	fetched  int
	swept    time.Time
}

type invoiceEntry struct {
	pay     lightning.IncomingPayment
	err     error
	expires time.Time
}

type invoiceCall struct {
	done chan struct{}
	pay  lightning.IncomingPayment
	err  error
}

func newInvoiceCache(b lightning.Backend) *invoiceCache {
	lu, _ := b.(lightning.IncomingLookup)
	return &invoiceCache{
		lookup:   lu,
		now:      time.Now,
		sem:      make(chan struct{}, lookupBurst),
		cache:    map[string]invoiceEntry{},
		inflight: map[string]*invoiceCall{},
	}
}

// get returns the status of paymentHash. paidUntil is when a paid result
// may be forgotten (the token's expiry). A backend miss or a busy node
// is returned as a non-error unpaid/busy result to the caller; only
// unexpected node errors are returned as err.
func (c *invoiceCache) get(paymentHash string, paidUntil, now time.Time) (lightning.IncomingPayment, error) {
	if c == nil || c.lookup == nil || paymentHash == "" {
		return lightning.IncomingPayment{}, errNoLookup
	}
	c.mu.Lock()
	if e, ok := c.cache[paymentHash]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.pay, e.err
	}
	if call, ok := c.inflight[paymentHash]; ok {
		c.mu.Unlock()
		<-call.done
		return call.pay, call.err
	}
	select {
	case c.sem <- struct{}{}:
	default:
		c.mu.Unlock()
		return lightning.IncomingPayment{}, errLookupBusy
	}
	if now.Sub(c.window) >= time.Minute {
		c.window, c.fetched = now, 0
	}
	if c.fetched >= lookupPerMin {
		<-c.sem
		c.mu.Unlock()
		return lightning.IncomingPayment{}, errLookupBusy
	}
	c.fetched++
	call := &invoiceCall{done: make(chan struct{})}
	c.inflight[paymentHash] = call
	c.mu.Unlock()

	pay, err := c.fetch(paymentHash)
	<-c.sem

	ttl := lookupUnpaidTTL
	switch {
	case err != nil && err != lightning.ErrNotFound:
		ttl = lookupFailTTL
	case pay.Paid:
		ttl = paidUntil.Sub(now)
		if ttl < lookupUnpaidTTL {
			ttl = lookupUnpaidTTL
		}
	}

	c.mu.Lock()
	delete(c.inflight, paymentHash)
	c.makeRoomLocked(now)
	c.cache[paymentHash] = invoiceEntry{pay: pay, err: err, expires: now.Add(ttl)}
	c.mu.Unlock()
	call.pay, call.err = pay, err
	close(call.done)
	return pay, err
}

// makeRoomLocked keeps the cache below lookupCacheMax: at the cap it
// forgets expired results (at most once a second, so a full cache stays
// cheap), then, if still full, arbitrary ones. Forgetting a result only
// costs a repeat lookup, which the lookup limits already bound.
func (c *invoiceCache) makeRoomLocked(now time.Time) {
	if len(c.cache) < lookupCacheMax {
		return
	}
	if now.Sub(c.swept) >= time.Second {
		c.swept = now
		for k, e := range c.cache {
			if !now.Before(e.expires) {
				delete(c.cache, k)
			}
		}
	}
	for k := range c.cache {
		if len(c.cache) < lookupCacheMax {
			return
		}
		delete(c.cache, k)
	}
}

func (c *invoiceCache) fetch(paymentHash string) (lightning.IncomingPayment, error) {
	var hash [32]byte
	raw, err := hex.DecodeString(paymentHash)
	if err != nil || len(raw) != 32 {
		return lightning.IncomingPayment{}, lightning.ErrNotFound
	}
	copy(hash[:], raw)
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return c.lookup.LookupIncoming(ctx, hash)
}

var (
	errNoLookup   = errString("invoice lookup is not available")
	errLookupBusy = errString("invoice lookup busy")
	errNoInvoice  = errString("token has no invoice")
	errClaimAuth  = errString("missing or invalid token")
)

type errString string

func (e errString) Error() string { return string(e) }

// serveClaim answers GET/POST /.spikes402/claim. The caller must present
// the HMAC-signed token from the 402 response (Authorization: Bearer).
func (g *Gate) serveClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", protectedCacheControl)
	h.Set("X-Content-Type-Options", "nosniff")

	now := g.now()
	if ok, wait := g.claimLim.allow(g.client(r), now); !ok {
		h.Set("Retry-After", itoaWait(wait))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	token := bearerToken(r)
	c, err := g.sign.verify(token)
	if err != nil || c.Kind != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if now.Unix() >= c.Expires {
		g.writeClaim(w, r, http.StatusGone, claimBody{Status: "expired"})
		return
	}
	if c.PaymentHash == "" {
		http.Error(w, errNoInvoice.Error(), http.StatusBadRequest)
		return
	}
	if g.spent.has(spentKey("L402", c.ID)) {
		g.writeClaim(w, r, http.StatusConflict, claimBody{Status: "spent"})
		return
	}

	pay, err := g.invoices.get(c.PaymentHash, time.Unix(c.Expires, 0), now)
	if err == errLookupBusy || err == errNoLookup {
		h.Set("Retry-After", "2")
		g.writeClaim(w, r, http.StatusAccepted, claimBody{Status: "unpaid"})
		return
	}
	if err != nil && err != lightning.ErrNotFound {
		h.Set("Retry-After", "2")
		g.writeClaim(w, r, http.StatusAccepted, claimBody{Status: "unpaid"})
		return
	}
	if err == lightning.ErrNotFound || !pay.Paid {
		status := "unpaid"
		code := http.StatusAccepted
		if pay.Expired {
			status, code = "expired", http.StatusGone
		}
		h.Set("Retry-After", "2")
		g.writeClaim(w, r, code, claimBody{Status: status})
		return
	}

	preimage := hex.EncodeToString(pay.Preimage[:])
	if r.Header.Get(RedeemHeader) == redeemCookie {
		if err := g.spent.use(spentKey("L402", c.ID), time.Unix(c.Expires, 0), now); err != nil {
			g.writeClaim(w, r, http.StatusConflict, claimBody{Status: "spent"})
			return
		}
		if g.opt.Observer != nil { // the statistics count the paid price
			r = r.WithContext(context.WithValue(r.Context(), infoKey{}, &reqInfo{token: c.ID, price: c.PriceSats}))
		}
		g.observe(r, g.classify(r), OutcomePaid)
		g.pending.drop(c.ID)
		g.issuePassFor(w, r, c.ID, c.Resource)
		return
	}
	g.writeClaim(w, r, http.StatusOK, claimBody{Status: "paid", Preimage: preimage})
}

type claimBody struct {
	Status   string `json:"status"`
	Preimage string `json:"preimage,omitempty"`
}

func (g *Gate) writeClaim(w http.ResponseWriter, r *http.Request, code int, body claimBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(body)
}

// bearerToken reads the 402 token from Authorization: Bearer … (the
// form documented for this endpoint).
func bearerToken(r *http.Request) string {
	scheme, rest, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

func itoaWait(d time.Duration) string {
	n := int(d.Seconds() + 0.999)
	if n < 1 {
		n = 1
	}
	return strconv.Itoa(n)
}
