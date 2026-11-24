package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Choffolo/spikes402/internal/gate"
)

// OverridesPath is the legacy sidecar next to the main config: for
// "config.json" it is "config.overrides.json". New writes use
// Config.OverridesFile (in state_dir). The main file is never rewritten.
func OverridesPath(configFile string) string {
	dir, name := filepath.Split(configFile)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if ext == "" {
		ext = ".json"
	}
	return filepath.Join(dir, base+".overrides"+ext)
}

// overrideFile is the on-disk snapshot of dashboard-editable fields.
// Secrets, listen addresses, Lightning, proxies and node invoice limits
// are not present and are rejected if someone writes them here.
type overrideFile struct {
	PriceSats           int64                  `json:"price_sats"`
	Prices              []gate.PriceRule       `json:"prices"`
	Protect             []string               `json:"protect"`
	PowSecondsPerSat    float64                `json:"pow_seconds_per_sat"`
	ChallengesPerMinute int                    `json:"challenges_per_minute"`
	BotPolicies         map[string]gate.Policy `json:"bot_policies"`
	Paused              bool                   `json:"paused"`
	ObserveOnly         bool                   `json:"observe_only,omitempty"`
}

func (o overrideFile) changes() Changes {
	prices := append([]gate.PriceRule(nil), o.Prices...)
	protect := append([]string(nil), o.Protect...)
	policies := o.BotPolicies
	if policies == nil {
		policies = map[string]gate.Policy{}
	}
	sps, cpm := o.PowSecondsPerSat, o.ChallengesPerMinute
	paused := o.Paused
	obs := o.ObserveOnly
	price := o.PriceSats
	return Changes{
		PriceSats:           &price,
		Prices:              &prices,
		Protect:             &protect,
		PowSecondsPerSat:    &sps,
		ChallengesPerMinute: &cpm,
		BotPolicies:         &policies,
		Paused:              &paused,
		ObserveOnly:         &obs,
	}
}

func snapshot(c *Config) overrideFile {
	policies := c.BotPolicies
	if policies == nil {
		policies = map[string]gate.Policy{}
	}
	return overrideFile{
		PriceSats:           c.PriceSats,
		Prices:              append([]gate.PriceRule(nil), c.Prices...),
		Protect:             append([]string(nil), c.Protect...),
		PowSecondsPerSat:    c.PowSecondsPerSat,
		ChallengesPerMinute: c.ChallengesPerMinute,
		BotPolicies:         policies,
		Paused:              c.Paused,
		ObserveOnly:         c.ObserveOnly,
	}
}

func applyOverridesFile(c *Config, configFile string) (*Config, error) {
	path, err := findOverrides(c, configFile)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return c, nil
	}
	n, err := ReadSnapshotFile(path, c)
	if err != nil {
		return nil, err
	}
	fields := changedOverrideFields(c, n)
	if len(fields) == 0 {
		log.Printf("applied overrides from %s (no differences)", path)
	} else {
		log.Printf("applied overrides from %s (%s)", path, strings.Join(fields, ", "))
	}
	return n, nil
}

func findOverrides(c *Config, configFile string) (string, error) {
	path := c.OverridesFile()
	if path != "" {
		_, err := os.Stat(path)
		if err == nil {
			return path, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	legacy := OverridesPath(configFile)
	if legacy == "" || legacy == path {
		return "", nil
	}
	_, err := os.Stat(legacy)
	if err == nil {
		return legacy, nil
	}
	if os.IsNotExist(err) {
		return "", nil
	}
	return "", err
}

func changedOverrideFields(base, n *Config) []string {
	var fields []string
	if base.PriceSats != n.PriceSats {
		fields = append(fields, "price_sats")
	}
	if !priceRulesEqual(base.Prices, n.Prices) {
		fields = append(fields, "prices")
	}
	if !stringSliceEqual(base.Protect, n.Protect) {
		fields = append(fields, "protect")
	}
	if base.PowSecondsPerSat != n.PowSecondsPerSat {
		fields = append(fields, "pow_seconds_per_sat")
	}
	if base.ChallengesPerMinute != n.ChallengesPerMinute {
		fields = append(fields, "challenges_per_minute")
	}
	if !policiesEqual(base.BotPolicies, n.BotPolicies) {
		fields = append(fields, "bot_policies")
	}
	if base.Paused != n.Paused {
		fields = append(fields, "paused")
	}
	return fields
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func priceRulesEqual(a, b []gate.PriceRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Pattern != b[i].Pattern || a[i].PriceSats != b[i].PriceSats {
			return false
		}
	}
	return true
}

func policiesEqual(a, b map[string]gate.Policy) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || v != w {
			return false
		}
	}
	return true
}

// WriteOverrides writes the dashboard-editable fields of c to path
// (mode 0600) using a same-directory rename so a crash cannot leave a
// half-written file. The main config file is not touched.
func WriteOverrides(path string, c *Config) error {
	if path == "" {
		return fmt.Errorf("overrides path is empty")
	}
	data, err := json.MarshalIndent(snapshot(c), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".overrides-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ReadSnapshotFile reads a dashboard-settings snapshot written by
// WriteOverrides and applies those fields onto base. Secrets and other
// file-only fields stay from base.
func ReadSnapshotFile(path string, base *Config) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var o overrideFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	n, err := base.Apply(o.changes())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return n, nil
}
