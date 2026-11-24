package config

import (
	"fmt"
	"strings"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/gate"
)

// WeakensProtection lists ways next is easier on visitors than cur.
// An empty list means protection is stricter or equal.
func WeakensProtection(cur, next *Config) []string {
	if cur == nil || next == nil {
		return nil
	}
	var why []string
	if next.Paused && !cur.Paused {
		why = append(why, "pause would serve protected paths free")
	}
	if next.ObserveOnly && !cur.ObserveOnly {
		why = append(why, "observe_only would serve protected paths free")
	}
	if next.PriceSats < cur.PriceSats {
		why = append(why, fmt.Sprintf("price_sats would fall from %d to %d", cur.PriceSats, next.PriceSats))
	}
	if next.PowSecondsPerSat < cur.PowSecondsPerSat {
		why = append(why, "pow_seconds_per_sat would be lowered")
	}
	if next.ChallengesPerMinute > cur.ChallengesPerMinute {
		why = append(why, "challenges_per_minute would be raised")
	}
	if dcur, dnext := cur.PoW(cur.PriceSats).Difficulty, next.PoW(next.PriceSats).Difficulty; dnext < dcur {
		why = append(why, fmt.Sprintf("proof-of-work difficulty would fall from %d to %d", dcur, dnext))
	}

	curPat := map[string]struct{}{}
	for _, p := range cur.Protect {
		curPat[p] = struct{}{}
	}
	nextPat := map[string]struct{}{}
	for _, p := range next.Protect {
		nextPat[p] = struct{}{}
	}
	for p := range curPat {
		if _, ok := nextPat[p]; !ok {
			why = append(why, "a protect pattern would be removed or narrowed ("+p+")")
			break
		}
	}

	caseSens := cur.ProtectCaseSensitive || next.ProtectCaseSensitive
	for _, r := range cur.Prices {
		old := r.PriceSats
		newP := gate.PriceFor(samplePath(r.Pattern), next.Prices, next.PriceSats, caseSens)
		if newP < old {
			why = append(why, fmt.Sprintf("price for %s would fall from %d to %d", r.Pattern, old, newP))
		}
	}
	seen := map[string]struct{}{}
	for _, r := range cur.Prices {
		seen[r.Pattern] = struct{}{}
	}
	for _, r := range next.Prices {
		if _, ok := seen[r.Pattern]; ok {
			continue
		}
		was := gate.PriceFor(samplePath(r.Pattern), cur.Prices, cur.PriceSats, caseSens)
		if r.PriceSats < was {
			why = append(why, fmt.Sprintf("new price rule for %s (%d sats) is below the current %d", r.Pattern, r.PriceSats, was))
		}
	}

	keys := map[string]struct{}{}
	for k := range cur.BotPolicies {
		keys[k] = struct{}{}
	}
	for k := range next.BotPolicies {
		keys[k] = struct{}{}
	}
	for k := range keys {
		a, b := cur.BotPolicies[k], next.BotPolicies[k]
		if policyRank(b) < policyRank(a) {
			why = append(why, fmt.Sprintf("bot policy %s would be weaker (%s → %s)", k, policyAction(a), policyAction(b)))
		}
		if policyMultiplier(b) < policyMultiplier(a) {
			why = append(why, fmt.Sprintf("bot policy %s price_multiplier would be lowered", k))
		}
	}
	return why
}

// Limits for what the AI may apply on its own (see NeedsConfirmation).
const (
	aiPriceFactor = 2    // a price may at most double...
	aiPriceFloor  = 10   // ...unless it stays at or below this many sats,
	aiPriceCeil   = 1000 // and never go above this many sats.
)

// NeedsConfirmation lists changes that make protection stricter or equal on
// paper but can still take a site down: a whole-site paywall, known
// crawlers (search engines, signed agents) made to pay or blocked where
// they were not, a big price jump, or a sharp cut in challenges. The AI
// may not apply these, and the dashboard asks the human to confirm them,
// even when ai_can_apply is on. An empty list means no extra confirmation.
// When the AI applies a change, cur should be the last settings a person
// applied, not the previous AI step, so many small changes cannot add up
// to these limits.
func NeedsConfirmation(cur, next *Config) []string {
	if cur == nil || next == nil {
		return nil
	}
	var why []string

	had := map[string]struct{}{}
	for _, p := range cur.Protect {
		had[p] = struct{}{}
	}
	for _, p := range next.Protect {
		if _, ok := had[p]; !ok && strings.Trim(p, "/*") == "" {
			why = append(why, "protect pattern "+p+" would put the whole site behind payment")
		}
	}

	if bigRise(cur.PriceSats, next.PriceSats) {
		why = append(why, fmt.Sprintf("price_sats would rise from %d to %d", cur.PriceSats, next.PriceSats))
	}
	caseSens := cur.ProtectCaseSensitive || next.ProtectCaseSensitive
	for _, r := range next.Prices {
		was := gate.PriceFor(samplePath(r.Pattern), cur.Prices, cur.PriceSats, caseSens)
		if bigRise(was, r.PriceSats) {
			why = append(why, fmt.Sprintf("price for %s would rise from %d to %d", r.Pattern, was, r.PriceSats))
		}
	}

	if next.ChallengesPerMinute*2 < cur.ChallengesPerMinute {
		why = append(why, fmt.Sprintf("challenges_per_minute would fall from %d to %d", cur.ChallengesPerMinute, next.ChallengesPerMinute))
	}

	// Stricter policies are fine for unknown clients and impostors. For
	// anything else (verified crawlers, signed agents, named bots, URL
	// policies) being made to pay or blocked needs a human.
	for k, b := range next.BotPolicies {
		a := cur.BotPolicies[k]
		if k == string(botid.Unknown) || k == string(botid.Impostor) {
			if policyMultiplier(b) > aiPriceFactor*policyMultiplier(a) {
				why = append(why, fmt.Sprintf("bot policy %s price_multiplier would more than double", k))
			}
			continue
		}
		if policyRank(b) > policyRank(a) || policyMultiplier(b) > policyMultiplier(a) {
			why = append(why, fmt.Sprintf("bot policy %s would make it pay more or be blocked (%s → %s)", k, policyAction(a), policyAction(b)))
		}
	}
	return why
}

// bigRise reports whether a price going from old to next is more than the
// AI may apply on its own.
func bigRise(old, next int64) bool {
	return next > old && (next > aiPriceCeil || (next > aiPriceFloor && next > aiPriceFactor*old))
}

func policyAction(p gate.Policy) string {
	if p.Action == "" {
		return string(gate.ActionPay)
	}
	return string(p.Action)
}

func policyRank(p gate.Policy) int {
	switch p.Action {
	case gate.ActionFree:
		return 0
	case gate.ActionBlock:
		return 2
	default:
		return 1 // pay, pow-only, or empty (default pay)
	}
}

func policyMultiplier(p gate.Policy) float64 {
	if p.PriceMultiplier == 0 {
		return 1
	}
	return p.PriceMultiplier
}

// samplePath is one path that pattern matches, used to compare prices.
func samplePath(pattern string) string {
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		if prefix == "" {
			return "/x"
		}
		return prefix + "/x"
	}
	return strings.ReplaceAll(pattern, "*", "x")
}
