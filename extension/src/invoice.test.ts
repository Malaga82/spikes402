import { describe, expect, it } from "vitest";
import {
  InvoiceError,
  assertPreimageMatchesInvoice,
  encodeBolt11ForTest,
  isBolt11,
  parseBolt11AmountSats,
  parseBolt11PaymentHash,
  preimageMatchesInvoice,
  verifyBolt11Checksum,
} from "./invoice";

const inv = (hrp: string) => encodeBolt11ForTest(hrp);

describe("parseBolt11AmountSats", () => {
  it("reads the usual multipliers", () => {
    expect(parseBolt11AmountSats(inv("lnbc20m"))).toBe(2_000_000);
    expect(parseBolt11AmountSats(inv("lnbc1u"))).toBe(100);
    expect(parseBolt11AmountSats(inv("lnbc100n"))).toBe(10);
    expect(parseBolt11AmountSats(inv("lnbc10n"))).toBe(1);
    expect(parseBolt11AmountSats(inv("lnbc2500u"))).toBe(250_000);
  });

  it("rounds fractional sats up (nano and pico)", () => {
    expect(parseBolt11AmountSats(inv("lnbc15n"))).toBe(2); // 1.5 sat
    expect(parseBolt11AmountSats(inv("lnbc1n"))).toBe(1); // 0.1 sat
    expect(parseBolt11AmountSats(inv("lnbc1p"))).toBe(1);
  });

  it("treats a bare number as whole bitcoin", () => {
    expect(parseBolt11AmountSats(inv("lnbc1"))).toBe(100_000_000); // 1 BTC
  });

  it("returns null for amountless invoices", () => {
    expect(parseBolt11AmountSats(inv("lnbc"))).toBeNull();
    expect(parseBolt11AmountSats("  " + inv("LNBC").toUpperCase() + "  ")).toBeNull();
  });

  it("accepts testnet and regtest prefixes, and a lightning: prefix", () => {
    expect(parseBolt11AmountSats(inv("lntb100n"))).toBe(10);
    expect(parseBolt11AmountSats(inv("lnbcrt2u"))).toBe(200);
    expect(parseBolt11AmountSats("lightning:" + inv("lnbc1u"))).toBe(100);
  });

  it("rejects junk", () => {
    expect(() => parseBolt11AmountSats("")).toThrow(InvoiceError);
    expect(() => parseBolt11AmountSats("chromescar71@phoenixwallet.me")).toThrow(InvoiceError);
    expect(() => parseBolt11AmountSats("bc1qnotaninvoice")).toThrow(InvoiceError);
    expect(() => parseBolt11AmountSats("lnbc")).toThrow(InvoiceError);
    expect(() => parseBolt11AmountSats("lnbc20m1qqqqqq")).toThrow(/checksum/);
  });
});

describe("isBolt11", () => {
  it("spots invoices and leaves addresses alone", () => {
    const good = inv("lnbc100n");
    expect(isBolt11(good)).toBe(true);
    expect(isBolt11("lightning:" + good)).toBe(true);
    expect(isBolt11("lnbc100n1qqqqqqqqqqqq")).toBe(false); // bad checksum
    expect(isBolt11("me@wallet.example")).toBe(false);
    expect(isBolt11("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")).toBe(false);
  });
});

describe("BOLT11 checksum", () => {
  it("accepts a checksum we just created and rejects a flipped character", () => {
    const good = inv("lnbc100n");
    expect(verifyBolt11Checksum(good)).toBe(true);
    const flipped = good.slice(0, -1) + (good.endsWith("q") ? "p" : "q");
    expect(verifyBolt11Checksum(flipped)).toBe(false);
    expect(() => parseBolt11AmountSats(flipped)).toThrow(/checksum/);
  });
});

// BOLT11 spec vector: 250,000 sat donation invoice. payment_hash is 000102…0102.
const SPEC_2500U =
  "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp";
const SPEC_HASH = "0001020304050607080900010203040506070809000102030405060708090102";

describe("parseBolt11PaymentHash and preimage check", () => {
  it("reads the payment hash from a BOLT11 spec invoice, including a lightning: prefix", () => {
    expect(parseBolt11PaymentHash(SPEC_2500U)).toBe(SPEC_HASH);
    expect(parseBolt11PaymentHash("lightning:" + SPEC_2500U.toUpperCase())).toBe(SPEC_HASH);
    expect(parseBolt11AmountSats(SPEC_2500U)).toBe(250_000);
  });

  it("accepts a preimage that hashes to the invoice payment hash, and refuses a wrong one", async () => {
    const preimage = "aa".repeat(32);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(preimage)));
    const invoice = makeInvoiceWithPaymentHash(digest);
    expect(parseBolt11PaymentHash(invoice)).toBe(hex(digest));
    expect(await preimageMatchesInvoice(invoice, preimage)).toBe(true);
    expect(await preimageMatchesInvoice(invoice, "0x" + preimage.toUpperCase())).toBe(true);
    expect(await preimageMatchesInvoice(invoice, "bb".repeat(32))).toBe(false);
    await expect(assertPreimageMatchesInvoice(invoice, "bb".repeat(32))).rejects.toThrow(InvoiceError);
  });

  it("reads the payment hash when the amount contains the digit 1", () => {
    const hash = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    for (const hrp of ["lnbc10n", "lnbc100n", "lnbc1u", "lnbc10u", "lnbc210n", "lnbc1", "lnbcrt1u"]) {
      expect(parseBolt11PaymentHash(makeInvoiceWithPaymentHash(hash, hrp))).toBe(hex(hash));
    }
  });

  it("rejects a short or odd preimage", async () => {
    const invoice = makeInvoiceWithPaymentHash(new Uint8Array(32));
    await expect(preimageMatchesInvoice(invoice, "aa")).rejects.toThrow(/32 bytes/);
  });
});

function hexToBytes(h: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Minimal lnbc…1 invoice carrying only a payment-hash tagged field. Checksum is fake. */
function makeInvoiceWithPaymentHash(hash: Uint8Array, hrp = "lnbc"): string {
  const bits: number[] = Array(7).fill(0); // timestamp
  bits.push(1, 1, 20); // type 1, length 52 (260 bits)
  let acc = 0;
  let n = 0;
  for (const b of hash) {
    acc = (acc << 8) | b;
    n += 8;
    while (n >= 5) {
      n -= 5;
      bits.push((acc >> n) & 31);
    }
  }
  if (n > 0) bits.push((acc << (5 - n)) & 31);
  bits.push(...Array(104).fill(0)); // signature
  return encodeBolt11ForTest(hrp, bits);
}
