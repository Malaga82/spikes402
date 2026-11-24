package config

import (
	"strings"
	"testing"

	"github.com/Choffolo/spikes402/internal/gate"
)

func testCfg(t *testing.T) *Config {
	t.Helper()
	c, err := load(t, `{`+base+`,"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPowSecondsFloor(t *testing.T) {
	if _, err := load(t, `{`+base+`,"pow_seconds_per_sat":0.000001,"lightning":{"backend":"fake"}}`); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("tiny pow_seconds_per_sat accepted: %v", err)
	}
	c, err := load(t, `{`+base+`,"pow_seconds_per_sat":0.000001,"unsafe_allow_dangerous_config":true,"lightning":{"backend":"fake"}}`)
	if err != nil || c.PowSecondsPerSat != 0.000001 {
		t.Fatalf("unsafe should allow a lower value: %v %+v", err, c)
	}
	if _, err := load(t, `{`+base+`,"pow_seconds_per_sat":1,"lightning":{"backend":"fake"}}`); err != nil {
		t.Fatalf("1 second per sat should be accepted: %v", err)
	}
}

func TestWeakensProtection(t *testing.T) {
	cur := testCfg(t) // price 5, protect from base, sps default 10
	price := int64(3)
	n, err := cur.Apply(Changes{PriceSats: &price})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) == 0 {
		t.Fatal("lowering the price should weaken")
	}
	up := int64(20)
	n, err = cur.Apply(Changes{PriceSats: &up})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) != 0 {
		t.Fatalf("raising the price should not weaken: %v", why)
	}
	protect := []string{"/elsewhere/**"}
	n, err = cur.Apply(Changes{Protect: &protect})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) == 0 {
		t.Fatal("replacing protect patterns should weaken")
	}
	free := map[string]gate.Policy{"unknown": {Action: gate.ActionFree}}
	n, err = cur.Apply(Changes{BotPolicies: &free})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) == 0 {
		t.Fatal("free policy should weaken")
	}
	paused := true
	n, err = cur.Apply(Changes{Paused: &paused})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) == 0 {
		t.Fatal("pausing should weaken")
	}
	sps := 1.0
	n, err = cur.Apply(Changes{PowSecondsPerSat: &sps})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) == 0 {
		t.Fatal("lowering pow_seconds_per_sat should weaken")
	}
	block := map[string]gate.Policy{"unknown": {Action: gate.ActionBlock}}
	n, err = cur.Apply(Changes{BotPolicies: &block})
	if err != nil {
		t.Fatal(err)
	}
	if why := WeakensProtection(cur, n); len(why) != 0 {
		t.Fatalf("block is stricter: %v", why)
	}
}

func TestNeedsConfirmation(t *testing.T) {
	cur := testCfg(t) // price 5, protect from base
	apply := func(ch Changes) []string {
		t.Helper()
		n, err := cur.Apply(ch)
		if err != nil {
			t.Fatal(err)
		}
		return NeedsConfirmation(cur, n)
	}
	price := func(v int64) Changes { return Changes{PriceSats: &v} }
	cpm := func(v int) Changes { return Changes{ChallengesPerMinute: &v} }
	protect := func(p ...string) Changes { return Changes{Protect: &p} }
	pol := func(k string, p gate.Policy) Changes { return Changes{BotPolicies: &map[string]gate.Policy{k: p}} }

	flagged := map[string]Changes{
		"whole site /**":        protect(append(cur.Protect, "/**")...),
		"whole site /*":         protect(append(cur.Protect, "/*")...),
		"whole site /":          protect(append(cur.Protect, "/")...),
		"max price":             price(1_000_000),
		"price above ceiling":   price(1001),
		"price more than twice": price(50),
		"challenges cut":        cpm(1),
		"block verified":        pol("verified", gate.Policy{Action: gate.ActionBlock}),
		"block signed":          pol("verified-signed", gate.Policy{Action: gate.ActionBlock}),
		"verified pay more":     pol("verified", gate.Policy{Action: gate.ActionPay, PriceMultiplier: 3}),
		"unknown x1000":         pol("unknown", gate.Policy{Action: gate.ActionPay, PriceMultiplier: 1000}),
		"price rule":            {Prices: &[]gate.PriceRule{{Pattern: "/premium/**", PriceSats: 900}}},
	}
	for name, ch := range flagged {
		if why := apply(ch); len(why) == 0 {
			t.Errorf("%s: should need confirmation", name)
		}
	}
	// A takedown that WeakensProtection alone does not see.
	wideProtect := append(append([]string(nil), cur.Protect...), "/**")
	n, err := cur.Apply(Changes{
		PriceSats: ptr(int64(1_000_000)), Protect: &wideProtect,
		BotPolicies: &map[string]gate.Policy{"verified": {Action: gate.ActionBlock}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(WeakensProtection(cur, n)) != 0 || len(NeedsConfirmation(cur, n)) < 3 {
		t.Fatalf("weakens=%v needs=%v", WeakensProtection(cur, n), NeedsConfirmation(cur, n))
	}

	ok := map[string]Changes{
		"price up a little":      price(9),
		"price doubles":          price(10),
		"challenges a bit lower": cpm(cur.ChallengesPerMinute - 1),
		"narrow new pattern":     protect(append(cur.Protect, "/archive/**")...),
		"block unknown":          pol("unknown", gate.Policy{Action: gate.ActionBlock}),
		"block impostor":         pol("impostor", gate.Policy{Action: gate.ActionBlock}),
		"price down":             price(3),
	}
	for name, ch := range ok {
		if why := apply(ch); len(why) != 0 {
			t.Errorf("%s: should not need confirmation: %v", name, why)
		}
	}
	// Keeping an existing whole-site pattern is not a widening.
	wide := *cur
	wide.Protect = []string{"/**"}
	same := wide
	if why := NeedsConfirmation(&wide, &same); len(why) != 0 {
		t.Fatalf("unchanged /**: %v", why)
	}
}

// Cumulative AI steps that stay under the per-step limits still need
// confirmation once they go past those limits from the original baseline.
func TestNeedsConfirmationRatchet(t *testing.T) {
	base := testCfg(t)
	price := int64(10)
	cpm := 30
	start, err := base.Apply(Changes{PriceSats: &price, ChallengesPerMinute: &cpm})
	if err != nil {
		t.Fatal(err)
	}

	// Doubling under the 1000-sat ceiling is not flagged in a single step:
	// 10, 20, 40, 80, 160, 320, 640, 1000.
	prices := []int64{20, 40, 80, 160, 320, 640, 1000}
	cur := start
	for _, p := range prices {
		n, err := cur.Apply(Changes{PriceSats: &p})
		if err != nil {
			t.Fatal(err)
		}
		if why := NeedsConfirmation(cur, n); len(why) != 0 {
			t.Fatalf("per-step %d -> %d should not be flagged: %v", cur.PriceSats, p, why)
		}
		if p > 20 {
			if why := NeedsConfirmation(start, n); len(why) == 0 {
				t.Fatalf("from baseline 10, price %d should need confirmation", p)
			}
		} else if why := NeedsConfirmation(start, n); len(why) != 0 {
			t.Fatalf("from baseline 10, first doubling to %d should be allowed: %v", p, why)
		}
		cur = n
	}

	// Cutting in half (or just under) is not flagged in a single step:
	// 30, 15, 8, 4, 2, 1.
	rates := []int{15, 8, 4, 2, 1}
	cur = start
	for _, r := range rates {
		n, err := cur.Apply(Changes{ChallengesPerMinute: &r})
		if err != nil {
			t.Fatal(err)
		}
		if why := NeedsConfirmation(cur, n); len(why) != 0 {
			t.Fatalf("per-step %d -> %d should not be flagged: %v", cur.ChallengesPerMinute, r, why)
		}
		if r < 15 {
			if why := NeedsConfirmation(start, n); len(why) == 0 {
				t.Fatalf("from baseline 30, challenges_per_minute %d should need confirmation", r)
			}
		} else if why := NeedsConfirmation(start, n); len(why) != 0 {
			t.Fatalf("from baseline 30, first half to %d should be allowed: %v", r, why)
		}
		cur = n
	}
}

func ptr[T any](v T) *T { return &v }
