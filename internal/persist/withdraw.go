package persist

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const intentName = "withdraw.intent"

// Intent states. pending is written before the node is called; sent,
// failed, or unknown afterwards. An unresolved (pending or unknown)
// intent blocks further withdrawals.
const (
	IntentPending = "pending"
	IntentSent    = "sent"
	IntentFailed  = "failed"
	IntentUnknown = "unknown"
)

// Intent is one withdrawal as stored on disk. No secrets (no passwords).
type Intent struct {
	AmountSat   int64     `json:"amount_sat"`
	Destination string    `json:"destination"`
	Time        time.Time `json:"time"`
	State       string    `json:"state"`
	PaymentID   string    `json:"payment_id,omitempty"`
	Result      string    `json:"result,omitempty"`
}

// Unresolved reports whether the intent must block new withdrawals.
func (in *Intent) Unresolved() bool {
	return in != nil && (in.State == IntentPending || in.State == IntentUnknown)
}

// Intents is the single withdrawal-intent file in the state directory.
type Intents struct {
	dir string
	key []byte
	mu  sync.Mutex
}

// OpenIntents prepares the intent file's directory.
func OpenIntents(dir string, key []byte) (*Intents, error) {
	if err := Prepare(dir); err != nil {
		return nil, err
	}
	return &Intents{dir: dir, key: append([]byte(nil), key...)}, nil
}

// Load returns the last intent, or nil if the file is missing (first run).
// A tampered or unreadable file returns ErrCorrupt.
func (s *Intents) Load() (*Intent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(s.dir, intentName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("withdraw intent: %w: %w", ErrCorrupt, err)
	}
	payload, err := Unseal(s.key, string(raw))
	if err != nil {
		return nil, fmt.Errorf("withdraw intent: %w", ErrCorrupt)
	}
	var in Intent
	if err := json.Unmarshal(payload, &in); err != nil || in.State == "" {
		return nil, fmt.Errorf("withdraw intent: %w", ErrCorrupt)
	}
	return &in, nil
}

// Save writes the intent and fsyncs it (mode 0600).
func (s *Intents) Save(in *Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, intentName, []byte(Seal(s.key, payload)+"\n"))
}
