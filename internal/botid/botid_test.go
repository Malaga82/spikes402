package botid

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Choffolo/spikes402/webbotauth"
)

// fakeDNS answers from tables and counts lookups.
type fakeDNS struct {
	ptr   map[string][]string
	a     map[string][]string
	aErr  map[string]error // forward lookup errors by name
	fail  bool
	gate  chan struct{} // if set, PTR lookups wait for it
	calls atomic.Int64
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	if f.fail {
		return nil, errors.New("timeout")
	}
	if names, ok := f.ptr[addr]; ok {
		return names, nil
	}
	return nil, &net.DNSError{Err: "not found", IsNotFound: true}
}

func (f *fakeDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err := f.aErr[host]; err != nil {
		return nil, err
	}
	var out []net.IPAddr
	for _, s := range f.a[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

var bots = []Bot{
	{Name: "Googlebot", UserAgent: "Googlebot", IPRangesURL: "x", ReverseDNS: []string{"googlebot.com"}},
	{Name: "GPTBot", UserAgent: "GPTBot", IPRangesURL: "x"},
}

func req(ua string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/premium/a", nil)
	r.Header.Set("User-Agent", ua)
	return r
}

const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestGoogleCrawlersUseTheirOwnPublishedRanges(t *testing.T) {
	c := New(DefaultBots, nil)
	c.resolver = &fakeDNS{}
	c.SetRanges("Googlebot", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	c.SetRanges("AdsBot-Google", []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	got := c.Classify(req("AdsBot-Google-Mobile"), net.ParseIP("198.51.100.10"), "https")
	if got.Kind != Verified || got.Name != "AdsBot-Google" || got.Method != "ip-list" {
		t.Fatalf("special crawler: %+v", got)
	}
	got = c.Classify(req(googleUA), net.ParseIP("192.0.2.10"), "https")
	if got.Kind != Verified || got.Name != "Googlebot" || got.Method != "ip-list" {
		t.Fatalf("common crawler: %+v", got)
	}
}

func TestIPListClassification(t *testing.T) {
	c := New(bots, nil)
	c.SetRanges("GPTBot", []netip.Prefix{netip.MustParsePrefix("20.0.0.0/24"), netip.MustParsePrefix("2001:db8::/32")})
	cases := []struct {
		ua, ip string
		want   Kind
	}{
		{"Mozilla/5.0; compatible; GPTBot/1.2", "20.0.0.7", Verified},
		{"Mozilla/5.0; compatible; gptbot/1.2", "2001:db8::5", Verified}, // case-insensitive
		{"Mozilla/5.0; compatible; GPTBot/1.2", "::ffff:20.0.0.7", Verified},
		{"Mozilla/5.0; compatible; GPTBot/1.2", "6.6.6.6", Impostor},
		{"Mozilla/5.0 Firefox", "6.6.6.6", Unknown},
		{"", "6.6.6.6", Unknown},
	}
	for _, tc := range cases {
		got := c.Classify(req(tc.ua), net.ParseIP(tc.ip), "https")
		if got.Kind != tc.want {
			t.Errorf("%q from %s: got %v, want %s", tc.ua, tc.ip, got, tc.want)
		}
		if got.Kind == Verified && (got.Name != "GPTBot" || got.Method != "ip-list") {
			t.Errorf("got %v", got)
		}
	}
}

func TestReverseDNSWhenNoList(t *testing.T) {
	c := New(bots, nil)
	dns := &fakeDNS{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"6.6.6.6":     {"crawl.googlebot.com.evil.test."},
			"7.7.7.7":     {"fake.googlebot.com."}, // PTR set by the attacker, forward does not confirm
			"34.1.1.1":    {"crawl-34-1-1-1.googlebot.com."},
		},
		a: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"fake.googlebot.com":              {"66.249.66.99"},
			"crawl-34-1-1-1.googlebot.com":    {"34.1.1.1"},
		},
	}
	c.resolver = dns
	for ip, want := range map[string]Kind{"66.249.66.1": Verified, "6.6.6.6": Impostor, "7.7.7.7": Impostor, "8.8.8.8": Impostor} {
		if got := c.Classify(req(googleUA), net.ParseIP(ip), "https"); got.Kind != want {
			t.Errorf("%s: got %v, want %s", ip, got, want)
		}
	}
	// Results are cached.
	before := dns.calls.Load()
	c.Classify(req(googleUA), net.ParseIP("66.249.66.1"), "https")
	if dns.calls.Load() != before {
		t.Fatal("DNS result not cached")
	}
	// Once the list is loaded it is used instead of DNS.
	c.SetRanges("Googlebot", []netip.Prefix{netip.MustParsePrefix("66.249.64.0/19")})
	if got := c.Classify(req(googleUA), net.ParseIP("66.249.66.2"), "https"); got.Kind != Verified || got.Method != "ip-list" {
		t.Fatalf("got %v", got)
	}
	// Outside the list, reverse DNS can still confirm a common crawler.
	if got := c.Classify(req(googleUA), net.ParseIP("34.1.1.1"), "https"); got.Kind != Verified || got.Method != "reverse-dns" {
		t.Fatalf("outside the list, good PTR: got %v", got)
	}
	if got := c.Classify(req(googleUA), net.ParseIP("6.6.6.6"), "https"); got.Kind != Impostor {
		t.Fatalf("outside the list, bad PTR: got %v", got)
	}
}

func TestUncheckableClaimIsUnknown(t *testing.T) {
	c := New(bots, nil)
	c.resolver = &fakeDNS{fail: true}
	if got := c.Classify(req(googleUA), net.ParseIP("66.249.66.1"), "https"); got.Kind != Unknown || !strings.Contains(got.Note, "not checked") {
		t.Fatalf("DNS failure: got %v", got)
	}
	if got := c.Classify(req("GPTBot"), net.ParseIP("20.0.0.1"), "https"); got.Kind != Unknown {
		t.Fatalf("list not loaded: got %v", got)
	}
}

func TestDNSConcurrencyCap(t *testing.T) {
	c := New(bots, nil)
	c.resolver = &fakeDNS{}
	for i := 0; i < maxDNSInFlight; i++ {
		c.dnsSem <- struct{}{}
	}
	if got := c.Classify(req(googleUA), net.ParseIP("66.249.66.1"), "https"); got.Kind != Unknown {
		t.Fatalf("got %v", got)
	}
}

func TestDNSCacheBounded(t *testing.T) {
	c := New(bots, nil)
	c.resolver = &fakeDNS{}
	for i := 0; i < maxDNSCache+100; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		c.Classify(req(googleUA), ip, "https")
	}
	if n := len(c.dnsCache); n > maxDNSCache {
		t.Fatalf("cache has %d entries", n)
	}
}

func TestParseRanges(t *testing.T) {
	p, err := parseRanges([]byte(`{"creationTime":"x","prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv6Prefix":"2001:db8::/32"},{"ipv4Prefix":"bad"}]}`))
	if err != nil || len(p) != 2 {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := parseRanges([]byte(`{"prefixes":[]}`)); err == nil {
		t.Fatal("empty list accepted")
	}
}

func TestFetchRangesLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write([]byte(`{"prefixes":[],"pad":"` + strings.Repeat("x", maxRangesBytes) + `"}`))
			return
		}
		w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"}]}`))
	}))
	defer srv.Close()
	c := New(nil, nil)
	if p, err := c.fetchRanges(context.Background(), srv.URL+"/ok"); err != nil || len(p) != 1 {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := c.fetchRanges(context.Background(), srv.URL+"/big"); err == nil {
		t.Fatal("oversized list accepted")
	}
}

func TestSignedBeatsUserAgent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := httptest.NewServer(webbotauth.DirectoryHandler(key))
	defer dir.Close()
	v := webbotauth.NewVerifier(webbotauth.NewDirectories(true))
	v.Hosts = []string{"origin.test"}
	c := New(bots, v)
	c.resolver = &fakeDNS{}                 // no network: missing PTR is a definite "no" (Impostor)
	c.TrustedAgents = []string{"127.0.0.1"} // where the test directory is served
	signed := func(target string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("User-Agent", googleUA)
		(&webbotauth.Signer{Key: key, AgentURL: dir.URL + webbotauth.DirectoryPath}).Sign(r)
		return r
	}
	if got := c.Classify(signed("https://origin.test/premium/a"), net.ParseIP("6.6.6.6"), "https"); got.Kind != Signed || got.Method != "web-bot-auth" {
		t.Fatalf("got %v", got)
	}
	// A signature made for another site (relayed here) does not count.
	if got := c.Classify(signed("https://other.test/premium/a"), net.ParseIP("6.6.6.6"), "https"); got.Kind == Signed || !strings.Contains(got.Note, "not this site") {
		t.Fatalf("relayed: got %v", got)
	}
	// A valid signature from an untrusted directory falls back to the other checks.
	c.TrustedAgents = []string{"bots.example"}
	if got := c.Classify(signed("https://origin.test/premium/b"), net.ParseIP("6.6.6.6"), "https"); got.Kind != Impostor || !strings.Contains(got.Note, "not on a trusted domain") {
		t.Fatalf("untrusted: got %v", got)
	}
	for agent, want := range map[string]bool{
		"https://bots.example/.well-known/x": true, "https://crawler.bots.example/x": true,
		"https://evilbots.example/x": false, "https://bots.example.evil.test/x": false,
	} {
		if c.trusted(agent) != want {
			t.Errorf("trusted(%s) != %v", agent, want)
		}
	}
	// A broken signature falls back to the other checks, with a note.
	r := httptest.NewRequest(http.MethodGet, "https://origin.test/premium/a", nil)
	r.Header.Set("User-Agent", "curl")
	r.Header.Set("Signature-Input", `sig1=("@authority");created=1;expires=2;keyid="k";tag="web-bot-auth"`)
	r.Header.Set("Signature", "sig1=:AAAA:")
	if got := c.Classify(r, net.ParseIP("6.6.6.6"), "https"); got.Kind != Unknown || !strings.Contains(got.Note, "signature invalid") {
		t.Fatalf("got %v", got)
	}
}

func TestClassString(t *testing.T) {
	got := Class{Kind: Verified, Name: "GPTBot", Method: "ip-list"}.String()
	if got != `verified; name="GPTBot"; method=ip-list` {
		t.Fatalf("got %s", got)
	}
}

// A PTR name that does not exist (NXDOMAIN) confirms nothing: alone it makes
// an impostor, not an unknown. A confirmed name is not undone by a later
// name whose lookup fails.
func TestForwardDNSNotFoundAndBreak(t *testing.T) {
	c := New(bots, nil)
	c.resolver = &fakeDNS{
		ptr: map[string][]string{
			"7.7.7.7":    {"nx.googlebot.com."},
			"66.249.1.1": {"crawl-1.googlebot.com.", "broken.googlebot.com."},
			"66.249.1.2": {"nx.googlebot.com.", "crawl-2.googlebot.com."},
		},
		a: map[string][]string{
			"crawl-1.googlebot.com": {"66.249.1.1"},
			"crawl-2.googlebot.com": {"66.249.1.2"},
		},
		aErr: map[string]error{
			"nx.googlebot.com":     &net.DNSError{Err: "no such host", IsNotFound: true},
			"broken.googlebot.com": &net.DNSError{Err: "timeout", IsTimeout: true},
		},
	}
	for ip, want := range map[string]Kind{"7.7.7.7": Impostor, "66.249.1.1": Verified, "66.249.1.2": Verified} {
		if got := c.Classify(req(googleUA), net.ParseIP(ip), "https"); got.Kind != want {
			t.Errorf("%s: got %v, want %s", ip, got, want)
		}
	}
}

// A failing DNS is asked once a minute per address, not on every request,
// and requests that arrive together share one lookup.
func TestReverseDNSFailureCacheAndSharedLookup(t *testing.T) {
	c := New(bots, nil)
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	dns := &fakeDNS{fail: true}
	c.resolver = dns
	for i := 0; i < 5; i++ {
		if got := c.Classify(req(googleUA), net.ParseIP("7.7.7.7"), "https"); got.Kind != Unknown {
			t.Fatalf("got %v", got)
		}
	}
	if n := dns.calls.Load(); n != 1 {
		t.Fatalf("%d PTR lookups for one failing address, want 1", n)
	}
	now = now.Add(dnsErrorTTL + time.Second)
	c.Classify(req(googleUA), net.ParseIP("7.7.7.7"), "https")
	if n := dns.calls.Load(); n != 2 {
		t.Fatalf("%d PTR lookups after the failure expired, want 2", n)
	}

	dns2 := &fakeDNS{gate: make(chan struct{})}
	c.resolver = dns2
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Classify(req(googleUA), net.ParseIP("8.8.4.4"), "https")
		}()
	}
	for dns2.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the others queue behind the first lookup
	close(dns2.gate)
	wg.Wait()
	if n := dns2.calls.Load(); n != 1 {
		t.Fatalf("%d PTR lookups for 8 concurrent requests, want 1", n)
	}
}
