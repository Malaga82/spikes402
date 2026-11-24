package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Choffolo/spikes402/internal/config"
	"github.com/Choffolo/spikes402/internal/gate"
	"github.com/Choffolo/spikes402/internal/lightning"
)

func TestReloadConfig(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"origin":"http://127.0.0.1:8080","price_sats":10,"protect":["/premium/**"],"lightning":{"backend":"fake"}}`)
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	g := gate.New(gate.Options{
		PriceSats: cfg.PriceSats, Protect: cfg.Protect, PoW: cfg.PoW, ChallengeTTL: cfg.ChallengeTTL(),
		SecretKey: []byte(strings.Repeat("s", 32)), Lightning: lightning.NewFake(), Next: http.NotFoundHandler(),
		ChallengesPerMinute: cfg.ChallengesPerMinute, MaxInvoicesPerMinute: 100, MaxPendingInvoices: 100,
	})

	// Valid reload updates price and observe_only live.
	write(`{"origin":"http://127.0.0.1:8080","price_sats":25,"observe_only":true,"protect":["/premium/**","/vip/**"],"lightning":{"backend":"fake"}}`)
	if err := reloadConfig(file, g, nil); err != nil {
		t.Fatalf("valid reload failed: %v", err)
	}
	s := g.Settings()
	if s.PriceSats != 25 || !s.ObserveOnly || len(s.Protect) != 2 {
		t.Fatalf("reloaded settings = %+v", s)
	}

	// Invalid config keeps previous settings untouched.
	write(`{"origin":"not-a-url","price_sats":-1}`)
	if err := reloadConfig(file, g, nil); err == nil {
		t.Fatal("invalid reload should fail")
	}
	if s := g.Settings(); s.PriceSats != 25 || !s.ObserveOnly {
		t.Fatalf("failed reload clobbered settings: %+v", s)
	}
}
