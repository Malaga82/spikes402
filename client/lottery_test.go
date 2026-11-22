package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Choffolo/spikes402/pow"
)

func TestLotteryPreferred(t *testing.T) {
	header := make([]byte, pow.HeaderPrefixLen)
	header[0] = 0x20
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			got = auth
			w.Write([]byte("ok"))
			return
		}
		w.Header().Add("WWW-Authenticate", `PoW challenge="classic", difficulty="8", algorithm="sha256d"`)
		w.Header().Add("WWW-Authenticate", fmt.Sprintf(`PoW challenge="lotto", difficulty="10", algorithm="bitcoin", header="%x"`, header))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	c := &Client{Mode: ModePoW}
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	tok, n, _ := strings.Cut(strings.TrimPrefix(got, "PoW "), ":")
	nonce, _ := strconv.ParseUint(n, 10, 32)
	if tok != "lotto" || !(pow.BitcoinWork{Header: header, Bits: 10}).Check(uint32(nonce)) {
		t.Fatalf("answer %q", got)
	}

	// Too hard, or malformed: the ordinary puzzle.
	for _, hdr := range []string{
		fmt.Sprintf(`PoW challenge="lotto", difficulty="29", algorithm="bitcoin", header="%x"`, header),
		`PoW challenge="lotto", difficulty="10", algorithm="bitcoin", header="00"`,
	} {
		h := http.Header{}
		h.Add("WWW-Authenticate", hdr)
		if _, _, ok := c.lottery(ParseChallenges(h)); ok {
			t.Errorf("%s: accepted", hdr)
		}
	}
}

func TestLotteryFallsBackToFreshOrdinaryPuzzle(t *testing.T) {
	header := make([]byte, pow.HeaderPrefixLen)
	p := pow.Params{Algorithm: pow.SHA256d, Difficulty: 5}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "":
			w.Header().Add("WWW-Authenticate", `PoW challenge="initial", difficulty="5", algorithm="sha256d"`)
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`PoW challenge="lotto", difficulty="5", algorithm="bitcoin", header="%x"`, header))
		case strings.HasPrefix(auth, "PoW lotto:"):
			w.Header().Add("WWW-Authenticate", `PoW challenge="renewed", difficulty="5", algorithm="sha256d"`)
		default:
			token, n, _ := strings.Cut(strings.TrimPrefix(auth, "PoW "), ":")
			nonce, err := strconv.ParseUint(n, 10, 64)
			if err != nil || token != "renewed" || !p.Check(token, nonce) {
				http.Error(w, "wrong fallback proof", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	c := &Client{Mode: ModePoW}
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("fallback returned %d", resp.StatusCode)
	}
}
