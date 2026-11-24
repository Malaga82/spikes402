package pow

import (
	"context"
	"encoding/hex"
	"testing"
)

// Mainnet block 976943: its header without the nonce, the nonce, and its hash as Bitcoin shows it.
const (
	blockHeader = "00e0ff3fbb508a13be4f341c330b16580780de6e5c4d03220069000000000000000000004d01ef84a1dc5ad8e2dd065421f1752e481bcef8b328db37ac0901fb76120d6911fb016b73160217"
	blockNonce  = 703130899
	blockHash   = "00000000000000000000873aafdcd40e99d6739a1f530dad993552edebe58b06"
)

func TestHeaderHashOfARealBlock(t *testing.T) {
	h, _ := hex.DecodeString(blockHeader)
	got := HeaderHash(h, blockNonce)
	rev := make([]byte, 32)
	for i := range got {
		rev[31-i] = got[i]
	}
	if hex.EncodeToString(rev) != blockHash {
		t.Fatalf("hash %x", rev)
	}
	if z := HashZeroBits(got); z != 80 {
		t.Fatalf("zero bits %d, want 80 (20 hex zeros)", z)
	}
	w := BitcoinWork{Header: h, Bits: 30}
	if !w.Check(blockNonce) || w.Check(blockNonce+1) {
		t.Fatal("Check")
	}
}

func TestBitcoinWork(t *testing.T) {
	h := make([]byte, HeaderPrefixLen)
	w := BitcoinWork{Header: h, Bits: 12}
	n, err := w.Solve(context.Background(), 2)
	if err != nil || !w.Check(n) {
		t.Fatalf("solve: %d %v", n, err)
	}
	for _, bad := range []BitcoinWork{{Header: h[:75], Bits: 8}, {Header: h, Bits: 0}, {Header: h, Bits: MaxBitcoinBits + 1}} {
		if bad.Validate() == nil || bad.Check(0) {
			t.Errorf("%d bytes, %d bits accepted", len(bad.Header), bad.Bits)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (BitcoinWork{Header: h, Bits: 30}).Solve(ctx, 1); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
}
