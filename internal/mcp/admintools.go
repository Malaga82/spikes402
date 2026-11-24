package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AdminClient calls the Spikes402 admin API with the AI key.
type AdminClient struct {
	BaseURL string // e.g. "http://127.0.0.1:8404"
	Key     string // admin.ai_key, never the human admin key
	HTTP    *http.Client

	once    sync.Mutex
	checked bool
}

func (c *AdminClient) do(ctx context.Context, method, path string, body any) (string, error) {
	if err := c.checkRole(ctx); err != nil {
		return "", err
	}
	return c.raw(ctx, method, path, body)
}

func (c *AdminClient) raw(ctx context.Context, method, path string, body any) (string, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := h.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach the Spikes402 admin API: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(out, &e)
		return "", fmt.Errorf("admin API: HTTP %d: %s", resp.StatusCode, e.Error)
	}
	return string(out), nil
}

// checkRole refuses to work with the human admin key: the AI must have
// its own key, which can never withdraw or approve.
func (c *AdminClient) checkRole(ctx context.Context) error {
	c.once.Lock()
	defer c.once.Unlock()
	if c.checked {
		return nil
	}
	out, err := c.raw(ctx, http.MethodGet, "/api/whoami", nil)
	if err != nil {
		return err
	}
	var me struct {
		Role string `json:"role"`
	}
	json.Unmarshal([]byte(out), &me)
	if me.Role != "ai" {
		return errors.New("refusing to run with the human admin key: set admin.ai_key in the Spikes402 config and give that key to the AI")
	}
	c.checked = true
	return nil
}

var changesSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"price_sats":            map[string]any{"type": "integer", "minimum": 1, "description": "default price of one request in sats"},
		"prices":                map[string]any{"type": "array", "description": "per-path prices; first matching rule wins. Unmatched protected paths use price_sats.", "items": map[string]any{"type": "object", "properties": map[string]any{"pattern": map[string]any{"type": "string"}, "price_sats": map[string]any{"type": "integer", "minimum": 1}}, "required": []string{"pattern", "price_sats"}}},
		"protect":               map[string]any{"type": "array", "description": "path patterns that require payment (at least one). Same matching as the config file.", "items": map[string]any{"type": "string"}, "minItems": 1},
		"pow_seconds_per_sat":   map[string]any{"type": "number", "exclusiveMinimum": 0, "description": "seconds of one CPU core of proof-of-work per sat"},
		"challenges_per_minute": map[string]any{"type": "integer", "minimum": 1, "description": "402 answers per client per minute"},
		"bot_policies": map[string]any{"type": "object", "description": `per class ("unknown", "impostor", "verified", "verified-signed"), bot name or Web Bot Auth URL: {"action": "pay"|"pow-only"|"free"|"block", "price_multiplier": number}. {} means everyone pays the same.`,
			"additionalProperties": map[string]any{"type": "object", "properties": map[string]any{
				"action":           map[string]any{"type": "string", "enum": []string{"pay", "pow-only", "free", "block"}},
				"price_multiplier": map[string]any{"type": "number"},
			}, "required": []string{"action"}}},
		"paused": map[string]any{"type": "boolean", "description": "when true, protected paths are served free and no invoices are created. The AI cannot apply this; use propose_settings_change."},
	},
	"additionalProperties": false,
}

func noArgs() map[string]any { return map[string]any{"type": "object", "properties": map[string]any{}} }

// AdminTools are the tools for an AI admin: read, propose and (only if the
// owner allowed it in the config file) apply. There is deliberately no
// withdrawal tool, and the API refuses withdrawals for the AI key anyway.
func AdminTools(c *AdminClient) []Tool {
	get := func(path string) func(context.Context, json.RawMessage) (string, error) {
		return func(ctx context.Context, _ json.RawMessage) (string, error) {
			return c.do(ctx, http.MethodGet, path, nil)
		}
	}
	return []Tool{
		{Name: "get_status", Description: "Spikes402 traffic since start (requests to protected pages by outcome and visitor class), Lightning node health and circuit breaker, and the current settings.",
			InputSchema: noArgs(), Call: get("/api/status")},
		{Name: "get_recent_visits", Description: "Recent requests to protected pages (the 'siege' feed): anonymised visitor, class, bot name, path and outcome. Pass 'since' (a sequence number from a previous call) to get only newer ones.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"since": map[string]any{"type": "integer", "minimum": 0}}},
			Call: func(ctx context.Context, args json.RawMessage) (string, error) {
				var a struct {
					Since uint64 `json:"since"`
				}
				if err := json.Unmarshal(args, &a); err != nil {
					return "", err
				}
				return c.do(ctx, http.MethodGet, fmt.Sprintf("/api/siege?since=%d", a.Since), nil)
			}},
		{Name: "get_settings", Description: "Current Spikes402 settings (no secrets) and which ones can be changed.", InputSchema: noArgs(), Call: get("/api/settings")},
		{Name: "list_proposals", Description: "Settings change proposals and whether the human admin applied or rejected them.", InputSchema: noArgs(), Call: get("/api/proposals")},
		{Name: "propose_settings_change", Description: "Suggest a settings change with a short reason. Nothing changes until the human admin approves it in the dashboard.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"changes": changesSchema, "reason": map[string]any{"type": "string", "maxLength": 500}}, "required": []string{"changes", "reason"}},
			Call: func(ctx context.Context, args json.RawMessage) (string, error) {
				var a struct {
					Changes json.RawMessage `json:"changes"`
					Reason  string          `json:"reason"`
				}
				if err := json.Unmarshal(args, &a); err != nil {
					return "", err
				}
				return c.do(ctx, http.MethodPost, "/api/proposals", map[string]any{"changes": a.Changes, "reason": a.Reason})
			}},
		{Name: "apply_settings_change", Description: "Apply a settings change immediately and save it to the overrides file (config.json is not rewritten). Only works if the site owner set admin.ai_can_apply in the config file; otherwise use propose_settings_change. The AI cannot apply 'paused' even then, and cannot apply a change that would reduce protection (lower prices, easier proof-of-work, fewer protect patterns, a free bot policy, and similar), nor one that needs human confirmation (a whole-site protect pattern, making verified crawlers pay or be blocked, a big price jump or a sharp cut in challenges_per_minute from the last settings a person applied). Propose those instead.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"changes": changesSchema}, "required": []string{"changes"}},
			Call: func(ctx context.Context, args json.RawMessage) (string, error) {
				var a struct {
					Changes json.RawMessage `json:"changes"`
				}
				if err := json.Unmarshal(args, &a); err != nil {
					return "", err
				}
				return c.do(ctx, http.MethodPut, "/api/settings", a.Changes)
			}},
	}
}
