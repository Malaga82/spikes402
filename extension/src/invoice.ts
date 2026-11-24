/** Errors about a string that is not a usable BOLT11 invoice. */
export class InvoiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvoiceError";
  }
}

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/** BOLT11 tagged-field type for the 32-byte payment hash. */
const TAG_PAYMENT_HASH = 1;

/**
 * Reads the amount encoded in a BOLT11 invoice, in satoshis, rounded up.
 * Returns null if the invoice is valid-looking but has no amount (amountless).
 * Verifies the bech32 checksum. Addresses (name@domain, Spark, on-chain) are not invoices.
 */
export function parseBolt11AmountSats(invoice: string): number | null {
  const raw = requireBolt11(invoice);
  const m = raw.match(/^ln[a-z]+(?:(\d+)([munp])?)?1/);
  if (!m) throw new InvoiceError("Invoice is malformed");
  if (m[1] === undefined) return null;
  return unitsToSats(BigInt(m[1]), m[2]);
}

/** 32-byte payment hash as lowercase hex, from the invoice's `p` field. */
export function parseBolt11PaymentHash(invoice: string): string {
  const raw = requireBolt11(invoice);
  const sep = raw.lastIndexOf("1"); // the bech32 separator; the amount (lnbc10n…) may contain 1s too
  if (sep < 0 || sep + 7 >= raw.length) throw new InvoiceError("Invoice is malformed");
  const data = raw.slice(sep + 1, raw.length - 6); // drop the 6-character checksum
  const words: number[] = [];
  for (const ch of data) {
    const v = BECH32.indexOf(ch);
    if (v < 0) throw new InvoiceError("Invoice is malformed");
    words.push(v);
  }
  // BOLT11: 7-word timestamp, tagged fields, 104-word signature.
  if (words.length < 7 + 104) throw new InvoiceError("Invoice is malformed");
  const tagged = words.slice(7, words.length - 104);
  let i = 0;
  while (i + 3 <= tagged.length) {
    const type = tagged[i];
    const len = tagged[i + 1] * 32 + tagged[i + 2];
    i += 3;
    if (i + len > tagged.length) throw new InvoiceError("Invoice is malformed");
    const field = tagged.slice(i, i + len);
    i += len;
    if (type === TAG_PAYMENT_HASH) {
      const bytes = wordsToBytes(field);
      if (bytes.length < 32) throw new InvoiceError("Invoice payment hash is truncated");
      return hex(bytes.subarray(0, 32));
    }
  }
  throw new InvoiceError("Invoice has no payment hash");
}

/**
 * True if sha256(preimage) equals the invoice's payment hash.
 * Accepts a hex preimage (with or without a 0x prefix).
 */
export async function preimageMatchesInvoice(invoice: string, preimage: string): Promise<boolean> {
  const want = parseBolt11PaymentHash(invoice);
  const bytes = parsePreimage(preimage);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return hex(hash) === want;
}

export async function assertPreimageMatchesInvoice(invoice: string, preimage: string): Promise<void> {
  if (!(await preimageMatchesInvoice(invoice, preimage))) {
    throw new InvoiceError("The payment preimage does not match this invoice's payment hash.");
  }
}

/** True if s is a BOLT11 invoice with a valid bech32 checksum (lnbc…, lntb…, lnbcrt…). */
export function isBolt11(s: string): boolean {
  try {
    requireBolt11(s);
    return true;
  } catch {
    return false;
  }
}

/** The invoice as wallets expect it: trimmed, lower case, without a lightning: prefix. */
export function normalizeInvoice(invoice: string): string {
  let raw = invoice.trim().toLowerCase();
  if (raw.startsWith("lightning:")) raw = raw.slice("lightning:".length);
  return raw;
}

function requireBolt11(invoice: string): string {
  const raw = normalizeInvoice(invoice);
  if (raw === "") throw new InvoiceError("Invoice is empty");
  if (!raw.startsWith("ln")) throw new InvoiceError("Not a Lightning invoice");
  if (!verifyBolt11Checksum(raw)) throw new InvoiceError("Invoice checksum is invalid");
  return raw;
}

/** BIP-173 bech32 checksum as used by BOLT11. */
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export function verifyBolt11Checksum(invoice: string): boolean {
  const parts = splitBolt11(normalizeInvoice(invoice));
  if (!parts) return false;
  const words: number[] = [];
  for (const ch of parts.data) {
    const v = BECH32.indexOf(ch);
    if (v < 0) return false;
    words.push(v);
  }
  if (words.length < 6) return false;
  return bech32Polymod(bech32HrpExpand(parts.hrp).concat(words)) === 1;
}

/** Encode a BOLT11-shaped string with a valid checksum. Used by tests. */
export function encodeBolt11ForTest(hrp: string, dataWords: number[] = []): string {
  const checksumWords = bech32Checksum(hrp.toLowerCase(), dataWords);
  return hrp.toLowerCase() + "1" + [...dataWords, ...checksumWords].map((w) => BECH32[w]).join("");
}

function splitBolt11(raw: string): { hrp: string; data: string } | null {
  const m = raw.match(/^(ln[a-z]+(?:\d+[munp]?)?)1([0-9a-z]+)$/);
  if (!m) return null;
  return { hrp: m[1], data: m[2] };
}

function bech32HrpExpand(hrp: string): number[] {
  const chars = [...hrp].map((c) => c.charCodeAt(0));
  return [...chars.map((c) => c >> 5), 0, ...chars.map((c) => c & 31)];
}

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= BECH32_GEN[i];
    }
  }
  return chk;
}

function bech32Checksum(hrp: string, dataWords: number[]): number[] {
  const polymod = bech32Polymod(bech32HrpExpand(hrp).concat(dataWords).concat([0, 0, 0, 0, 0, 0])) ^ 1;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((polymod >> (5 * (5 - i))) & 31);
  return out;
}

function parsePreimage(preimage: string): Uint8Array<ArrayBuffer> {
  let h = preimage.trim().toLowerCase();
  if (h.startsWith("0x")) h = h.slice(2);
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new InvoiceError("Payment preimage must be 32 bytes of hex.");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function wordsToBytes(words: number[]): Uint8Array {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function unitsToSats(amount: bigint, multiplier: string | undefined): number {
  // 1 bitcoin = 100_000_000 sat. Multipliers are the usual BOLT11 ones.
  let sats: bigint;
  switch (multiplier) {
    case undefined:
      sats = amount * 100_000_000n;
      break;
    case "m":
      sats = amount * 100_000n;
      break;
    case "u":
      sats = amount * 100n;
      break;
    case "n":
      sats = ceilDiv(amount, 10n); // 1 nano-BTC = 0.1 sat
      break;
    case "p":
      sats = ceilDiv(amount, 10_000n);
      break;
    default:
      throw new InvoiceError("Unknown amount multiplier");
  }
  if (sats <= 0n) throw new InvoiceError("Invoice amount is zero");
  if (sats > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new InvoiceError("Invoice amount is too large");
  }
  return Number(sats);
}

function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}
