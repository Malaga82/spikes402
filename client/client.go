// Package client is a small library for bots that meet a Spikes402 gate.
//
// It sends a request; if the answer is 402 Payment Required it either
// solves the proof-of-work puzzle or pays the Lightning invoice through a
// Payer, then repeats the request with the proof.
package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Choffolo/spikes402/pow"
	"github.com/Choffolo/spikes402/webbotauth"
)

// Payer pays a BOLT11 invoice and returns the payment preimage in hex.
//
// TODO: add a real wallet (for example the bot's own phoenixd node via
// POST /payinvoice). A real Payer MUST decode the invoice and refuse to
// pay more than the bot's budget before paying.
type Payer interface {
	Pay(ctx context.Context, invoice string) (preimageHex string, err error)
}

// Mode chooses how the client answers a 402.
type Mode string

const (
	ModePoW Mode = "pow" // do the work
	ModePay Mode = "pay" // pay the invoice
)

// Client fetches URLs protected by Spikes402.
type Client struct {
	HTTP          *http.Client // defaults to http.DefaultClient
	Mode          Mode
	Payer         Payer // needed for ModePay
	MaxDifficulty int   // refuse harder sha256d puzzles; 0 means 28 (about 2 min on one CPU core)

	// Argon2id puzzles: refuse harder ones, or ones needing more memory per
	// attempt. 0 means 14 (about 3 min at 16 MiB) and 64 MiB. The solver
	// runs at most 4 attempts at once, so it needs up to 4 x the memory.
	MaxArgonDifficulty int
	MaxArgonMemoryMiB  int

	// Signer, if set, signs every request with Web Bot Auth (HTTP Message
	// Signatures) so the site can recognise this bot.
	Signer    *webbotauth.Signer
	UserAgent string

	Logf func(format string, args ...any)
}

// Challenge is one parsed WWW-Authenticate challenge.
type Challenge struct {
	Scheme string
	Params map[string]string
}

// ParseChallenges reads WWW-Authenticate headers such as
// `L402 macaroon="...", invoice="..."`. Values must be quoted and must
// not contain quotes, which holds for everything Spikes402 sends.
func ParseChallenges(h http.Header) []Challenge {
	var out []Challenge
	for _, v := range h.Values("WWW-Authenticate") {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
		c := Challenge{Scheme: scheme, Params: map[string]string{}}
		for _, part := range strings.Split(rest, ",") {
			k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok {
				c.Params[k] = strings.Trim(val, `"`)
			}
		}
		out = append(out, c)
	}
	return out
}

func find(cs []Challenge, scheme string) (Challenge, bool) {
	for _, c := range cs {
		if strings.EqualFold(c.Scheme, scheme) {
			return c, true
		}
	}
	return Challenge{}, false
}

// Get fetches url, answering a 402 challenge if needed.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	resp, err := c.do(ctx, url, "")
	if err != nil || resp.StatusCode != http.StatusPaymentRequired {
		return resp, err
	}
	challenges := ParseChallenges(resp.Header)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Retry the URL we actually landed on (after redirects). A cross-host
	// redirect on the first request would otherwise send the proof back
	// to the original host, which would bounce us again without the header.
	retry := url
	if resp.Request != nil && resp.Request.URL != nil {
		retry = resp.Request.URL.String()
	}
	if c.Mode == ModePoW {
		if token, lot, ok := c.lottery(challenges); ok {
			auth, err := c.answerLottery(ctx, token, lot)
			if err == nil {
				resp, err = c.do(ctx, retry, auth)
				if err != nil || resp.StatusCode != http.StatusPaymentRequired {
					return resp, err
				}
				// The job can expire while we work. Use the ordinary puzzle from the new offer.
				challenges = ParseChallenges(resp.Header)
				if _, ok := ordinaryPoW(challenges); !ok {
					return resp, nil
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.Request != nil && resp.Request.URL != nil {
					retry = resp.Request.URL.String()
				}
			} else if ctx.Err() != nil {
				return nil, err
			}
		}
	}
	auth, err := c.answer(ctx, challenges)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, retry, auth)
}

func ordinaryPoW(challenges []Challenge) (Challenge, bool) {
	for _, ch := range challenges {
		if strings.EqualFold(ch.Scheme, "PoW") && ch.Params["algorithm"] != pow.Bitcoin {
			return ch, true
		}
	}
	return Challenge{}, false
}

// answer turns a 402 challenge into an Authorization header value.
func (c *Client) answer(ctx context.Context, challenges []Challenge) (string, error) {
	switch c.Mode {
	case ModePoW:
		ch, ok := ordinaryPoW(challenges)
		if !ok {
			return "", errors.New("server offered no proof-of-work challenge")
		}
		p, err := c.puzzle(ch)
		if err != nil {
			return "", err
		}
		c.logf("402: solving %s proof-of-work (difficulty %d, ~%.1f s on one CPU core)...", p.Algorithm, p.Difficulty, p.ExpectedSeconds())
		nonce, err := p.Solve(ctx, ch.Params["challenge"])
		if err != nil {
			return "", err
		}
		c.logf("402: solved, nonce=%d", nonce)
		return "PoW " + ch.Params["challenge"] + ":" + strconv.FormatUint(nonce, 10), nil

	case ModePay:
		ch, ok := find(challenges, "L402")
		if !ok {
			return "", errors.New("server offered no Lightning invoice")
		}
		if c.Payer == nil {
			return "", errors.New("no Payer configured")
		}
		c.logf("402: paying invoice %s", ch.Params["invoice"])
		preimage, err := c.Payer.Pay(ctx, ch.Params["invoice"])
		if err != nil {
			return "", fmt.Errorf("payment failed: %w", err)
		}
		c.logf("402: paid")
		return "L402 " + ch.Params["macaroon"] + ":" + preimage, nil
	}
	return "", fmt.Errorf("unknown mode %q", c.Mode)
}

// lottery finds a Bitcoin lottery challenge (see the README's "Bitcoin
// lottery") that is within MaxDifficulty.
func (c *Client) lottery(challenges []Challenge) (string, pow.BitcoinWork, bool) {
	limit := c.MaxDifficulty
	if limit == 0 {
		limit = 28
	}
	for _, ch := range challenges {
		if !strings.EqualFold(ch.Scheme, "PoW") || ch.Params["algorithm"] != pow.Bitcoin {
			continue
		}
		bits, err1 := strconv.Atoi(ch.Params["difficulty"])
		header, err2 := hex.DecodeString(ch.Params["header"])
		w := pow.BitcoinWork{Header: header, Bits: bits}
		if err1 == nil && err2 == nil && w.Validate() == nil && bits <= limit && ch.Params["challenge"] != "" {
			return ch.Params["challenge"], w, true
		}
	}
	return "", pow.BitcoinWork{}, false
}

// answerLottery solves a Bitcoin lottery challenge.
func (c *Client) answerLottery(ctx context.Context, token string, w pow.BitcoinWork) (string, error) {
	c.logf("402: solving the Bitcoin lottery puzzle (difficulty %d, ~%.1f s on one CPU core): a real block header...",
		w.Bits, pow.Params{Algorithm: pow.SHA256d, Difficulty: w.Bits}.ExpectedSeconds())
	nonce, err := w.Solve(ctx, 0)
	if err != nil {
		return "", err
	}
	c.logf("402: solved, nonce=%d, block hash %x...", nonce, reversedPrefix(pow.HeaderHash(w.Header, nonce), 8))
	return "PoW " + token + ":" + strconv.FormatUint(uint64(nonce), 10), nil
}

// reversedPrefix is the start of a hash as Bitcoin shows it.
func reversedPrefix(h [32]byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = h[31-i]
	}
	return out
}

// puzzle reads the PoW challenge and checks it is within our limits.
func (c *Client) puzzle(ch Challenge) (pow.Params, error) {
	difficulty, err := strconv.Atoi(ch.Params["difficulty"])
	if err != nil {
		return pow.Params{}, errors.New("bad proof-of-work difficulty")
	}
	p := pow.Params{Algorithm: ch.Params["algorithm"], Difficulty: difficulty}
	limit, memLimit := c.MaxDifficulty, 0
	switch p.Algorithm {
	case pow.SHA256d:
		if limit == 0 {
			limit = 28
		}
	case pow.Argon2id:
		if p.MemoryMiB, err = strconv.Atoi(ch.Params["memory-mib"]); err != nil {
			return pow.Params{}, errors.New("bad argon2id memory")
		}
		limit, memLimit = c.MaxArgonDifficulty, c.MaxArgonMemoryMiB
		if limit == 0 {
			limit = 14
		}
		if memLimit == 0 {
			memLimit = 64
		}
		if p.MemoryMiB > memLimit {
			return pow.Params{}, fmt.Errorf("puzzle needs too much memory: %d MiB > limit %d MiB", p.MemoryMiB, memLimit)
		}
	default:
		return pow.Params{}, fmt.Errorf("unsupported proof-of-work algorithm %q", p.Algorithm)
	}
	if difficulty > limit {
		return pow.Params{}, fmt.Errorf("puzzle too hard: difficulty %d > limit %d", difficulty, limit)
	}
	if err := p.Validate(); err != nil {
		return pow.Params{}, err
	}
	return p, nil
}

func (c *Client) do(ctx context.Context, url, auth string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Signer != nil {
		if err := c.Signer.Sign(req); err != nil {
			return nil, err
		}
	}
	return c.httpClient(auth).Do(req)
}

// httpClient returns c.HTTP (or the default). When a payment proof is
// attached, cross-host redirects are refused so the token is not sent
// to another site and so we do not pay twice after the header is stripped.
func (c *Client) httpClient(auth string) *http.Client {
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	if auth == "" {
		return h
	}
	clone := *h
	orig := h.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && !sameHost(via[0].URL, req.URL) {
			return fmt.Errorf("refusing to follow a redirect to a different host (%s → %s) with a payment proof", via[0].URL.Host, req.URL.Host)
		}
		if orig != nil {
			return orig(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &clone
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host)
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}
