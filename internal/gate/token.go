package gate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Choffolo/spikes402/pow"
)

// claims is what a Spikes402 token says. One token is issued per 402
// answer and can be redeemed exactly once, either with the preimage of
// its invoice (L402) or with a proof-of-work solution.
type claims struct {
	ID          string `json:"id"`            // random, used to stop replays
	PaymentHash string `json:"ph"`            // hex sha256 of the invoice preimage ("" if no invoice)
	Resource    string `json:"res"`           // hash of "METHOD /path?query", the resource the token unlocks
	PriceSats   int64  `json:"sats"`          // price at issue; PoW must still cover today's price (see check)
	Expires     int64  `json:"exp"`           // unix seconds
	PowBits     int    `json:"pow"`           // proof-of-work difficulty
	PowAlg      string `json:"alg,omitempty"` // "" (sha256d), "argon2id" or "bitcoin"
	PowMem      int    `json:"mem,omitempty"` // Argon2id memory in MiB
	Kind        string `json:"k,omitempty"`   // "" for a challenge token, "pass" for the access cookie (see pass.go)
	LotJob      uint32 `json:"lj,omitempty"`  // Bitcoin lottery: the pool job (see lottery.go)
	LotEn2      uint64 `json:"le,omitempty"`  // Bitcoin lottery: the extranonce2 that makes this token's header
}

func (c claims) powParams() pow.Params {
	if c.PowAlg == "" {
		return pow.Params{Algorithm: pow.SHA256d, Difficulty: c.PowBits}
	}
	return pow.Params{Algorithm: c.PowAlg, Difficulty: c.PowBits, MemoryMiB: c.PowMem}
}

// Token format: base64url(JSON claims) "." base64url(HMAC-SHA256(secret, first part)).
//
// This is a deliberately simple stand-in for a macaroon (see README): it
// carries the same essential facts (payment hash + what it unlocks +
// expiry) and is just as unforgeable, but has no caveat chaining.

var errBadToken = errors.New("invalid token")

type signer struct{ key []byte }

func (s signer) sign(c claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(body)), nil
}

func (s signer) verify(token string) (claims, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return claims{}, errBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(body)) {
		return claims{}, errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return claims{}, errBadToken
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, errBadToken
	}
	return c, nil
}

func (s signer) mac(body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}
