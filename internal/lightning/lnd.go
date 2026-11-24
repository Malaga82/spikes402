package lightning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LND talks to a self-hosted LND node over its REST API (v1).
// Use a receive-only invoice.macaroon so the proxy can create and look up
// invoices without being able to spend funds.
type LND struct {
	URL         string // e.g. "https://127.0.0.1:8080"
	Macaroon    string // hex-encoded macaroon (Grpc-Metadata-macaroon)
	TLSCertPath string // optional path to LND's tls.cert PEM
	HTTP        *http.Client

	clientOnce sync.Once
	client     *http.Client
	clientErr  error
}

func (l *LND) httpClient() (*http.Client, error) {
	if l.HTTP != nil {
		return l.HTTP, nil
	}
	l.clientOnce.Do(func() {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if l.TLSCertPath != "" {
			pem, err := os.ReadFile(l.TLSCertPath)
			if err != nil {
				l.clientErr = fmt.Errorf("lnd: tls cert: %w", err)
				return
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				l.clientErr = fmt.Errorf("lnd: tls cert %s: no valid PEM certificate", l.TLSCertPath)
				return
			}
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		l.client = &http.Client{Timeout: 10 * time.Second, Transport: tr}
	})
	return l.client, l.clientErr
}

func (l *LND) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	client, err := l.httpClient()
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.URL, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Grpc-Metadata-macaroon", l.Macaroon)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("lnd: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("lnd: %w", err)
	}
	return resp.StatusCode, data, nil
}

// CreateInvoice implements Backend via POST /v1/invoices.
func (l *LND) CreateInvoice(ctx context.Context, amountSat int64, memo string, expiry time.Duration) (Invoice, error) {
	if len(memo) > 128 {
		memo = memo[:128]
	}
	payload := map[string]string{
		"value": strconv.FormatInt(amountSat, 10),
		"memo":  memo,
	}
	if expiry > 0 {
		payload["expiry"] = strconv.FormatInt(int64(expiry/time.Second), 10)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Invoice{}, err
	}
	status, body, err := l.do(ctx, http.MethodPost, "/v1/invoices", raw)
	if err != nil {
		return Invoice{}, err
	}
	if status != http.StatusOK {
		return Invoice{}, fmt.Errorf("lnd: HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var out struct {
		RHash          string `json:"r_hash"`
		PaymentRequest string `json:"payment_request"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Invoice{}, fmt.Errorf("lnd: bad response: %w", err)
	}
	hash, err := base64.StdEncoding.DecodeString(out.RHash)
	if err != nil || len(hash) != 32 || out.PaymentRequest == "" {
		return Invoice{}, fmt.Errorf("lnd: bad response: %q", body)
	}
	inv := Invoice{PaymentRequest: out.PaymentRequest}
	copy(inv.PaymentHash[:], hash)
	return inv, nil
}

// LookupIncoming implements IncomingLookup via GET /v1/invoice/{r_hash_str}.
func (l *LND) LookupIncoming(ctx context.Context, paymentHash [32]byte) (IncomingPayment, error) {
	status, body, err := l.do(ctx, http.MethodGet, "/v1/invoice/"+hex.EncodeToString(paymentHash[:]), nil)
	if err != nil {
		return IncomingPayment{}, err
	}
	if status == http.StatusNotFound {
		return IncomingPayment{}, ErrNotFound
	}
	if status != http.StatusOK {
		return IncomingPayment{}, fmt.Errorf("lnd: HTTP %d: %.200s", status, body)
	}
	var out struct {
		RHash      string `json:"r_hash"`
		RPreimage  string `json:"r_preimage"`
		State      string `json:"state"`
		AmtPaidSat string `json:"amt_paid_sat"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return IncomingPayment{}, fmt.Errorf("lnd: bad response: %w", err)
	}
	got, err := base64.StdEncoding.DecodeString(out.RHash)
	if err != nil || len(got) != 32 {
		return IncomingPayment{}, fmt.Errorf("lnd: bad r_hash: %q", out.RHash)
	}
	recv, _ := strconv.ParseInt(out.AmtPaidSat, 10, 64)
	pay := IncomingPayment{Expired: out.State == "CANCELED", ReceivedSat: recv}
	copy(pay.PaymentHash[:], got)
	if out.State != "SETTLED" {
		return pay, nil
	}
	pre, err := base64.StdEncoding.DecodeString(out.RPreimage)
	if err != nil || len(pre) != 32 {
		return IncomingPayment{}, fmt.Errorf("lnd: settled invoice missing r_preimage")
	}
	copy(pay.Preimage[:], pre)
	if sha256.Sum256(pre) != pay.PaymentHash {
		return IncomingPayment{}, fmt.Errorf("lnd: preimage does not match payment hash")
	}
	pay.Paid = true
	pay.Expired = false
	return pay, nil
}

// NodeInfo implements Inspector via GET /v1/getinfo and GET /v1/balance/channels.
func (l *LND) NodeInfo(ctx context.Context) (NodeInfo, error) {
	status, body, err := l.do(ctx, http.MethodGet, "/v1/getinfo", nil)
	if err != nil {
		return NodeInfo{}, err
	}
	if status != http.StatusOK {
		return NodeInfo{}, fmt.Errorf("lnd: HTTP %d", status)
	}
	var info struct {
		IdentityPubkey    string `json:"identity_pubkey"`
		Version           string `json:"version"`
		NumActiveChannels int    `json:"num_active_channels"`
		Chains            []struct {
			Chain   string `json:"chain"`
			Network string `json:"network"`
		} `json:"chains"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return NodeInfo{}, err
	}
	chain := ""
	if len(info.Chains) > 0 {
		chain = info.Chains[0].Network
		if chain == "" {
			chain = info.Chains[0].Chain
		}
	}
	out := NodeInfo{
		NodeID:   info.IdentityPubkey,
		Chain:    chain,
		Version:  info.Version,
		Channels: info.NumActiveChannels,
	}
	if st, b, err := l.do(ctx, http.MethodGet, "/v1/balance/channels", nil); err == nil && st == http.StatusOK {
		var bal struct {
			LocalBalance struct {
				Sat string `json:"sat"`
			} `json:"local_balance"`
		}
		if json.Unmarshal(b, &bal) == nil {
			out.BalanceSat, _ = strconv.ParseInt(bal.LocalBalance.Sat, 10, 64)
		}
	}
	return out, nil
}
