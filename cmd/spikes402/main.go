// Command spikes402 is the Spikes402 reverse proxy: put it in front of a
// website and protected paths will ask bots to pay sats or do work.
//
//	spikes402 -config config.json
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Choffolo/spikes402/client"
	"github.com/Choffolo/spikes402/internal/admin"
	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/btc"
	"github.com/Choffolo/spikes402/internal/config"
	"github.com/Choffolo/spikes402/internal/gate"
	"github.com/Choffolo/spikes402/internal/lightning"
	"github.com/Choffolo/spikes402/internal/netlimit"
	"github.com/Choffolo/spikes402/internal/persist"
	"github.com/Choffolo/spikes402/webbotauth"
)

func main() {
	configFile := flag.String("config", "config.json", "path to the JSON configuration file")
	flag.Parse()

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	origin, _ := url.Parse(cfg.Origin)   // validated by config.Load
	trusted, _ := cfg.TrustedProxyNets() // validated by config.Load
	proxy := newOriginProxy(origin, originOpt{
		Trusted:        trusted,
		PreserveHost:   cfg.PreserveHost,
		PublicHosts:    cfg.PublicHosts,
		ClientIPHeader: cfg.ClientIPHeader,
	})

	secretConfigured := cfg.SecretKey != ""
	secret := []byte(cfg.SecretKey)
	if len(secret) == 0 { // only allowed with the fake backend
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			log.Fatal(err)
		}
		log.Print("no secret_key set: using a random one (tokens will not survive a restart)")
	}

	if err := persist.Prepare(cfg.StateDir); err != nil {
		log.Fatal(err)
	}
	log.Printf("state directory %s", cfg.StateDir)

	var spentStore gate.SpentStore
	var spentRecords []persist.SpentRecord
	var intentStore admin.IntentStore
	if secretConfigured {
		st, err := persist.OpenSpent(cfg.StateDir, secret)
		if err != nil {
			log.Fatal(err)
		}
		spentRecords, err = st.Load(time.Now())
		if err != nil {
			log.Fatalf("spent tokens: %v", err)
		}
		spentStore = st
		intents, err := persist.OpenIntents(cfg.StateDir, secret)
		if err != nil {
			log.Fatal(err)
		}
		intentStore = intents
		if n := len(spentRecords); n > 0 {
			log.Printf("loaded %d spent token(s) from disk", n)
		}
	} else {
		log.Print("no secret_key set: spent tokens and withdrawal intents are not saved to disk")
	}

	mux := http.NewServeMux()
	var backend lightning.Backend
	switch cfg.Lightning.Backend {
	case "fake":
		fake := lightning.NewFake()
		backend = fake
		mux.Handle(client.FakePayPath, fake.PayHandler())
		log.Print("WARNING: fake Lightning backend: for development only, invoices are not real")
	case "phoenixd":
		backend = &lightning.Phoenixd{URL: cfg.Lightning.PhoenixdURL, Password: cfg.Lightning.PhoenixdPassword}
	}

	// Bot identification: Web Bot Auth signatures first, then the IP
	// lists and reverse DNS published by the crawler operators.
	var classifier *botid.Classifier
	if cfg.IdentifyBotsOn() {
		if cfg.WebBotAuthDevMode {
			log.Print("WARNING: web_bot_auth_dev_mode: accepting key directories on http and local addresses, for development only")
		}
		verifier := webbotauth.NewVerifier(webbotauth.NewDirectories(cfg.WebBotAuthDevMode))
		verifier.Hosts = cfg.PublicHosts
		classifier = botid.New(cfg.Bots(), verifier)
		classifier.TrustedAgents = cfg.WebBotAuthTrustedAgents
		go classifier.Run(context.Background(), log.Printf)
	}

	// The admin dashboard, if enabled, watches every protected request.
	var monitor *admin.Monitor
	var observer func(gate.Event)
	if cfg.AdminEnabled() {
		monitor = admin.NewMonitor(cfg.Admin.VisitorIPs, time.Now())
		observer = monitor.Observe
		legacyStats := admin.StatsPath(*configFile)
		monitor.PersistStats(filepath.Join(cfg.StateDir, filepath.Base(legacyStats)), legacyStats, log.Printf)
	}

	g := gate.New(gate.Options{
		PriceSats:    cfg.PriceSats,
		Protect:      cfg.Protect,
		Prices:       cfg.Prices,
		Previews:     cfg.Previews,
		Paused:       cfg.Paused,
		PoW:          cfg.PoW,
		ChallengeTTL: cfg.ChallengeTTL(),
		SecretKey:    secret,
		Lightning:    backend,
		Next:         proxy,

		ChallengesPerMinute:  cfg.ChallengesPerMinute,
		MaxInvoicesPerMinute: cfg.MaxInvoicesPerMinute,
		MaxPendingInvoices:   cfg.MaxPendingInvoices,
		ClientIPHeader:       cfg.ClientIPHeader,
		TrustedProxies:       trusted,
		CaseSensitive:        cfg.ProtectCaseSensitive,

		Classifier:         classifier,
		Policies:           cfg.BotPolicies,
		Surge:              cfg.Surge,
		Observer:           observer,
		Argon2MaxMemoryMiB: cfg.Argon2MaxMemoryMiB,
		Lottery:            startLottery(cfg),
		BrowserPoW:         cfg.BrowserPoW.Mode,

		SpentStore:   spentStore,
		SpentRecords: spentRecords,
	})
	mux.Handle("/", g)

	if cfg.AdminEnabled() {
		startAdmin(cfg, *configFile, g, monitor, backend, intentStore)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.ReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(cfg.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	p := cfg.PoW(cfg.PriceSats)
	log.Printf("spikes402 listening on %s, protecting %v of %s at %d sats or %s PoW difficulty %d (~%.1f s on one CPU core)",
		cfg.Listen, cfg.Protect, cfg.Origin, cfg.PriceSats, p.Algorithm, p.Difficulty, p.ExpectedSeconds())
	if p.Algorithm == "argon2id" {
		log.Printf("Argon2id checks: %d MiB each, at most %d at once (budget %d MiB)",
			p.MemoryMiB, cfg.Argon2MaxMemoryMiB/p.MemoryMiB, cfg.Argon2MaxMemoryMiB)
	}
	if len(cfg.Previews) > 0 {
		log.Printf("teasers on the 402 page (first matching rule wins): %v", cfg.Previews)
	}
	if len(cfg.Prices) > 0 {
		log.Printf("path prices (first matching rule wins; unmatched protected paths use %d sats): %v", cfg.PriceSats, cfg.Prices)
	}
	if len(cfg.BotPolicies) > 0 {
		log.Printf("bot policies: %v", cfg.BotPolicies)
	}
	if cfg.Surge.Active() {
		log.Printf("surge pricing on: up to %.2g× when 402s/min are ≥ %.2g× the 24h baseline and at least %.0f/min (step +%.2g every %.3g min)",
			cfg.Surge.MaxMultiplier, cfg.Surge.SurgeRatio, cfg.Surge.MinPerMinute, cfg.Surge.Step, cfg.Surge.StepIntervalMinutes)
	}
	if cfg.Paused {
		log.Print("protection is paused: protected paths are served free and no invoices will be created")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(netlimit.Listener(ln, cfg.MaxConnections)))
}

// maxHeaderBytes bounds the request line plus headers (Go's default is
// 1 MiB). URIs beyond gate.MaxURIBytes are refused anyway.
const maxHeaderBytes = 32 << 10

// startLottery connects to the solo pool when "lottery" is set, so that
// proofs of work are Bitcoin lottery tickets. It returns nil otherwise (a
// typed nil would not compare equal to nil inside the gate).
func startLottery(cfg *config.Config) gate.Lottery {
	if !cfg.Lottery.On() {
		return nil
	}
	l := btc.New(btc.Options{Pool: cfg.Lottery.Pool, User: cfg.Lottery.User(), Password: cfg.Lottery.Password,
		Agent: "spikes402", JobTTL: cfg.ChallengeTTL(), Logf: log.Printf})
	go l.Run(context.Background())
	log.Printf("lottery: solo mining through %s for %s; until a job arrives, proofs of work are ordinary sha256d", cfg.Lottery.Pool, cfg.Lottery.Address)
	return l
}

// startAdmin serves the admin API and dashboard on their own address
// (localhost by default), separate from the public proxy.
func startAdmin(cfg *config.Config, configFile string, g *gate.Gate, monitor *admin.Monitor, backend lightning.Backend, intent admin.IntentStore) {
	opt := admin.Options{Config: cfg, ConfigFile: configFile, Gate: g, Monitor: monitor, IntentStore: intent}
	if insp, ok := backend.(lightning.Inspector); ok {
		opt.Node = insp
	}
	if cfg.Withdraw.Enabled {
		switch b := backend.(type) {
		case *lightning.Fake:
			opt.Withdrawer = b
		case *lightning.Phoenixd:
			opt.Withdrawer = &lightning.PhoenixdWithdrawer{URL: b.URL, FullPassword: cfg.Withdraw.PhoenixdFullPassword, FeerateSatByte: cfg.Withdraw.FeerateSatByte}
		}
		log.Printf("withdrawals ENABLED to %s (admin dashboard, withdraw password, two confirmations)", cfg.Withdraw.Destination)
		if cfg.Lightning.Backend == "phoenixd" && !config.IsLoopback(cfg.Listen) {
			log.Print("WARNING: withdrawals are enabled, so phoenixd's FULL-ACCESS password (it can spend everything) is loaded in this internet-facing process. Turn withdrawals off when you are not withdrawing (see SECURITY.md)")
		}
		if !config.IsLoopback(cfg.Admin.Listen) {
			log.Printf("WARNING: withdrawals are enabled and the admin dashboard listens beyond localhost (%s): anyone who gets the admin key and the withdraw password on that network can move your sats", cfg.Admin.Listen)
		}
	}
	adm := admin.New(opt)
	adm.ReconcileWithdrawals(context.Background())
	srv := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           adm.Handler(),
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() { log.Fatal(srv.ListenAndServe()) }()
	ai := "no AI key"
	if cfg.Admin.AIKey != "" {
		ai = "AI may propose changes"
		if cfg.Admin.AICanApply {
			ai = "AI may apply changes"
		}
	}
	log.Printf("admin dashboard on http://%s (%s)", cfg.Admin.Listen, ai)
}

// originProxy forwards requests to the website. Idle connections are kept
// so a burst does not open a new TCP connection for every request. Timeouts
// stop a slow or hanging origin from holding a client (and a paid token)
// indefinitely: the proxy answers 502, and a GET/HEAD can retry the token
// (see gate.deliver).
func originProxy(origin *url.URL) *httputil.ReverseProxy {
	return newOriginProxy(origin, originOpt{})
}

// originOpt is how the origin proxy treats forwarding headers and Host.
type originOpt struct {
	Transport      http.RoundTripper
	Trusted        []*net.IPNet
	PreserveHost   bool
	PublicHosts    []string
	ClientIPHeader string
}

func newOriginProxy(origin *url.URL, opt originOpt) *httputil.ReverseProxy {
	tr := opt.Transport
	if tr == nil {
		tr = originTransport()
	}
	return &httputil.ReverseProxy{
		Rewrite:   rewriteToOrigin(origin, opt),
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("origin error: %v", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// hop and client-IP headers a direct client must not be allowed to set.
var forwardingHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Forwarded-Port", "X-Forwarded-By", "X-Forwarded-Server",
	"X-Forwarded-Scheme", "X-Real-IP", "X-Client-IP",
	"X-Cluster-Client-IP", "CF-Connecting-IP", "True-Client-IP",
	"Forwarded",
}

// rewriteToOrigin sends the request to origin. X-Forwarded-* and the
// configured client-IP header are trusted only when the direct peer is
// in trusted_proxies; otherwise they are stripped and rebuilt from the
// socket address. The Host sent to the origin is the origin URL's host,
// unless preserve_host is set, the peer is trusted, and (when public_hosts
// is set) the inbound host is one of those names. The inbound Host is
// never used as X-Forwarded-Host for an untrusted peer.
func rewriteToOrigin(origin *url.URL, opt originOpt) func(*httputil.ProxyRequest) {
	return func(r *httputil.ProxyRequest) {
		inHost := r.In.Host
		inXFH := firstHeader(r.In.Header, "X-Forwarded-Host")
		inXFP := firstHeader(r.In.Header, "X-Forwarded-Proto")
		inXFF := r.In.Header.Values("X-Forwarded-For")
		peer := requestIP(r.In)
		trusted := ipInNets(peer, opt.Trusted)

		r.SetURL(origin)
		if !trusted {
			stripForwarding(r.Out.Header, opt.ClientIPHeader)
			if peer != nil {
				r.Out.Header.Set("X-Forwarded-For", peer.String())
			}
			if r.In.TLS != nil {
				r.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Out.Header.Set("X-Forwarded-Proto", "http")
			}
			// Never the attacker's Host.
			r.Out.Header.Set("X-Forwarded-Host", origin.Host)
			return
		}

		setTrustedForwarded(r, peer, inXFF, inXFP, firstNonEmpty(inXFH, inHost))
		if opt.PreserveHost {
			host := firstNonEmpty(inXFH, inHost)
			if hostAllowed(host, opt.PublicHosts) {
				r.Out.Host = host
			}
		}
	}
}

func setTrustedForwarded(r *httputil.ProxyRequest, peer net.IP, inXFF []string, proto, host string) {
	var parts []string
	for _, v := range inXFF {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				parts = append(parts, p)
			}
		}
	}
	if peer != nil {
		parts = append(parts, peer.String())
	}
	if len(parts) > 0 {
		r.Out.Header.Set("X-Forwarded-For", strings.Join(parts, ", "))
	}
	if proto == "" {
		if r.In.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	r.Out.Header.Set("X-Forwarded-Proto", proto)
	if host != "" {
		r.Out.Header.Set("X-Forwarded-Host", host)
	}
}

func stripForwarding(h http.Header, clientIPHeader string) {
	for _, name := range forwardingHeaders {
		h.Del(name)
	}
	if clientIPHeader != "" {
		h.Del(clientIPHeader)
	}
}

func firstHeader(h http.Header, name string) string {
	if v := h.Values(name); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func requestIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostAllowed reports whether host may be sent to the origin when
// preserve_host is on. With no public_hosts list, a trusted proxy's
// Host is accepted; otherwise the hostname must match a listed name
// (letter case and a trailing dot are ignored; a port is stripped).
func hostAllowed(host string, public []string) bool {
	name := hostName(host)
	if name == "" {
		return false
	}
	if len(public) == 0 {
		return true
	}
	for _, p := range public {
		if hostName(p) == name {
			return true
		}
	}
	return false
}

func hostName(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func originTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
