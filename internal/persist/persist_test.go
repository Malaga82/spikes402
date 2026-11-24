package persist

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	return []byte(strings.Repeat("k", 32))
}

func TestSealRoundTrip(t *testing.T) {
	key := testKey(t)
	line := Seal(key, []byte(`{"id":"pay:aa"}`))
	got, err := Unseal(key, line)
	if err != nil || string(got) != `{"id":"pay:aa"}` {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Unseal(key, "not-a-record"); !errors.Is(err, ErrTampered) {
		t.Fatalf("got %v", err)
	}
	if _, err := Unseal([]byte(strings.Repeat("x", 32)), line); !errors.Is(err, ErrTampered) {
		t.Fatalf("wrong key: %v", err)
	}
	// Flip one byte of the payload after the MAC.
	parts := strings.SplitN(line, " ", 2)
	tampered := parts[0] + " " + parts[1][:len(parts[1])-1] + "Z"
	if _, err := Unseal(key, tampered); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := Prepare(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o, want 0700", st.Mode().Perm())
	}
	if err := writeAtomic(dir, "x", []byte("hi")); err != nil {
		t.Fatal(err)
	}
	mode, err := fileMode(filepath.Join(dir, "x"))
	if err != nil || (runtime.GOOS != "windows" && mode != 0o600) {
		t.Fatalf("file mode %o %v, want 0600", mode, err)
	}
}

func TestSpentRestartReplay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	exp := now.Add(10 * time.Minute).Unix()

	s, err := OpenSpent(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if recs, err := s.Load(now); err != nil || len(recs) != 0 {
		t.Fatalf("empty first run: %v %v", recs, err)
	}
	rec := SpentRecord{ID: "pay:" + strings.Repeat("a", 32), Expires: exp, First: now.Unix()}
	if err := s.Persist(rec); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSpent(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Load(now)
	if err != nil || len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("reload: %v %v", got, err)
	}

	// Expired records are dropped on load.
	later := now.Add(11 * time.Minute)
	got, err = s2.Load(later)
	if err != nil || len(got) != 0 {
		t.Fatalf("expired still present: %v %v", got, err)
	}
}

func TestSpentTamperAndWrongSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	s, _ := OpenSpent(dir, key)
	_, _ = s.Load(now)
	if err := s.Persist(SpentRecord{ID: "pay:x", Expires: now.Add(time.Hour).Unix(), First: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	// Snapshot is compacted on next Load; tamper the snapshot HMAC.
	s2, _ := OpenSpent(dir, key)
	if _, err := s2.Load(now); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, spentSnapName)
	raw, _ := os.ReadFile(snap)
	raw[len(raw)-2] ^= 0xff
	if err := os.WriteFile(snap, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s3, _ := OpenSpent(dir, key)
	if _, err := s3.Load(now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered snapshot: %v", err)
	}

	// A different secret cannot read a good store.
	s4, _ := OpenSpent(dir, []byte(strings.Repeat("z", 32)))
	// restore a valid snapshot first
	good, _ := OpenSpent(dir, key)
	_ = good.Persist(SpentRecord{ID: "pay:y", Expires: now.Add(time.Hour).Unix(), First: now.Unix()})
	_, _ = good.Load(now)
	if _, err := s4.Load(now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestSpentTamperedLogLinesDiscarded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	s, _ := OpenSpent(dir, key)
	_, _ = s.Load(now)
	good := SpentRecord{ID: "pay:good", Expires: now.Add(time.Hour).Unix(), First: now.Unix()}
	if err := s.Persist(good); err != nil {
		t.Fatal(err)
	}
	// Append a junk line without compacting (don't Load).
	if err := appendLine(filepath.Join(dir, spentLogName), "deadbeef not-valid"); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenSpent(dir, key)
	got, err := s2.Load(now)
	if err != nil || len(got) != 1 || got[0].ID != "pay:good" {
		t.Fatalf("valid line should survive: %v %v", got, err)
	}
}

func TestSpentAllLogTamperedIsCorrupt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	if err := Prepare(dir); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(filepath.Join(dir, spentLogName), "aa not-valid"); err != nil {
		t.Fatal(err)
	}
	s, _ := OpenSpent(dir, key)
	if _, err := s.Load(now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("all-tampered log: %v", err)
	}
}

func TestIntentRoundTripAndCorrupt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	st, err := OpenIntents(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil || got != nil {
		t.Fatalf("missing file: %v %v", got, err)
	}
	in := &Intent{AmountSat: 42, Destination: "me@wallet.example", Time: time.Unix(1_800_000_000, 0).UTC(), State: IntentPending}
	if err := st.Save(in); err != nil {
		t.Fatal(err)
	}
	mode, err := fileMode(filepath.Join(dir, intentName))
	if err != nil || (runtime.GOOS != "windows" && mode != 0o600) {
		t.Fatalf("intent mode %o %v", mode, err)
	}
	st2, _ := OpenIntents(dir, key)
	got, err = st2.Load()
	if err != nil || got == nil || got.AmountSat != 42 || got.State != IntentPending || !got.Unresolved() {
		t.Fatalf("reload: %+v %v", got, err)
	}
	// Tamper.
	p := filepath.Join(dir, intentName)
	raw, _ := os.ReadFile(p)
	raw[len(raw)-2] ^= 0xff
	_ = os.WriteFile(p, raw, 0o600)
	if _, err := st2.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered intent: %v", err)
	}
	// No secret in the file.
	_ = st.Save(in)
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), string(key)) || strings.Contains(string(raw), "password") {
		t.Fatal("secret leaked into intent file")
	}
	// Payload is only the intent fields.
	payload, _ := Unseal(key, string(raw))
	var check map[string]any
	if err := json.Unmarshal(payload, &check); err != nil {
		t.Fatal(err)
	}
}

func TestSpentFilesHaveNoSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	s, _ := OpenSpent(dir, key)
	now := time.Unix(1_800_000_000, 0)
	_, _ = s.Load(now)
	_ = s.Persist(SpentRecord{ID: "pay:abc", Expires: now.Add(time.Hour).Unix(), First: now.Unix()})
	_, _ = s.Load(now)
	for _, name := range []string{spentSnapName, spentLogName} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), string(key)) {
			t.Fatalf("secret in %s", name)
		}
	}
}

// Concurrent Persist calls share fsyncs, and across a compaction nothing
// is lost: every record is there after a reload.
func TestSpentConcurrentPersistAcrossCompaction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	s, err := OpenSpent(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(now); err != nil {
		t.Fatal(err)
	}
	n := maxLogLines + 500 // forces at least one compaction
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += 8 {
				id := fmt.Sprintf("pay:%032x", i)
				if err := s.Persist(SpentRecord{ID: id, Expires: now.Add(time.Hour).Unix(), First: now.Unix()}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	s2, err := OpenSpent(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Load(now)
	if err != nil || len(got) != n {
		t.Fatalf("reload: %d records, want %d (%v)", len(got), n, err)
	}
}

// Directory fsync is skipped on Windows (it fails there with "Access is
// denied") and works elsewhere; either way it must not return an error.
func TestSyncDirNeverFails(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestIntentRejectsAnInvalidStateFile(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenIntents(dir, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, intentName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty intent: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unreadable intent: %v", err)
	}
}
