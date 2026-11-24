package lightning

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLNDBackend(t *testing.T) {
	preimage := [32]byte{1, 2, 3, 4}
	hash := sha256.Sum256(preimage[:])
	hashHex := hex.EncodeToString(hash[:])
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])
	preB64 := base64.StdEncoding.EncodeToString(preimage[:])

	state := "OPEN"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Grpc-Metadata-macaroon") != "deadbeef" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/invoices":
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["value"] != "25" || req["expiry"] != "300" {
				t.Fatalf("unexpected invoice payload: %v", req)
			}
			json.NewEncoder(w).Encode(map[string]string{
				"r_hash":          hashB64,
				"payment_request": "lnbc250n1test",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/invoice/"+hashHex:
			json.NewEncoder(w).Encode(map[string]string{
				"r_hash":       hashB64,
				"r_preimage":   preB64,
				"state":        state,
				"amt_paid_sat": "25",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/getinfo":
			json.NewEncoder(w).Encode(map[string]any{
				"identity_pubkey":     "02abc",
				"version":             "0.18.0",
				"num_active_channels": 3,
				"chains":              []map[string]string{{"chain": "bitcoin", "network": "mainnet"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/balance/channels":
			json.NewEncoder(w).Encode(map[string]any{
				"local_balance": map[string]string{"sat": "12345"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	lnd := &LND{URL: srv.URL, Macaroon: "deadbeef", HTTP: srv.Client()}
	ctx := context.Background()

	inv, err := lnd.CreateInvoice(ctx, 25, "test", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if inv.PaymentRequest != "lnbc250n1test" || inv.PaymentHash != hash {
		t.Fatalf("got invoice %+v", inv)
	}

	pay, err := lnd.LookupIncoming(ctx, hash)
	if err != nil || pay.Paid || pay.Expired {
		t.Fatalf("open lookup: %+v err=%v", pay, err)
	}

	state = "SETTLED"
	pay, err = lnd.LookupIncoming(ctx, hash)
	if err != nil || !pay.Paid || pay.Preimage != preimage || pay.ReceivedSat != 25 {
		t.Fatalf("settled lookup: %+v err=%v", pay, err)
	}

	if _, err := lnd.LookupIncoming(ctx, [32]byte{9}); err != ErrNotFound {
		t.Fatalf("missing invoice: got %v, want ErrNotFound", err)
	}

	info, err := lnd.NodeInfo(ctx)
	if err != nil || info.NodeID != "02abc" || info.Chain != "mainnet" || info.Channels != 3 || info.BalanceSat != 12345 {
		t.Fatalf("node info: %+v err=%v", info, err)
	}
}
