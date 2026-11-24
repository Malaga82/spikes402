package main

import (
	"log"

	"github.com/Choffolo/spikes402/internal/admin"
	"github.com/Choffolo/spikes402/internal/config"
	"github.com/Choffolo/spikes402/internal/gate"
)

// reloadConfig re-reads configFile (plus any overrides) and atomically swaps
// the gate's live settings without dropping connections or Stratum jobs.
// On any error the previous settings stay active.
func reloadConfig(configFile string, g *gate.Gate, adm *admin.Server) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	if err := g.UpdateSettings(cfg.GateSettings()); err != nil {
		return err
	}
	if adm != nil {
		adm.ReloadConfig(cfg)
	}
	log.Printf("reloaded config from %s (price %d sats, protect %v, paused=%v, observe_only=%v)",
		configFile, cfg.PriceSats, cfg.Protect, cfg.Paused, cfg.ObserveOnly)
	return nil
}
