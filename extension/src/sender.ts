/**
 * Who is allowed to talk to the background and the wallet host.
 * Web pages never get a direct channel (no externally_connectable). These
 * checks are defense in depth, and they stop a compromised content script
 * from calling privileged methods (unlock, send, confirm, connect).
 */

export function isExtensionPage(sender: { url?: string; tab?: { id?: number } | undefined }, extensionBase: string): boolean {
  if (!sender.url || !sender.url.startsWith(extensionBase)) return false;
  // A content script's sender.url is the page URL, not an extension URL.
  // If a tab is present, this message came from a tab (content script).
  if (sender.tab) return false;
  return true;
}

/** Origin of the page a content-script message came from. Never trust a value the page supplied. */
export function pageOrigin(sender: { origin?: string; url?: string; tab?: { url?: string } }): string | undefined {
  // A sandboxed document has an opaque origin: it is not the site in the tab's URL.
  if (sender.origin === "null") return undefined;
  if (sender.origin && sender.origin !== "null" && /^https?:\/\//.test(sender.origin)) {
    return sender.origin;
  }
  const raw = sender.tab?.url ?? sender.url;
  if (!raw) return undefined;
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    return u.origin;
  } catch {
    return undefined;
  }
}

const MAX_CAP = 21_000_000 * 100_000_000; // all sats that will ever exist

export function sanitizeSettings(patch: Record<string, unknown>): {
  maxSatsPerPayment?: number;
  maxSatsPerSitePerDay?: number;
  maxSatsPerDay?: number;
  network?: "regtest" | "mainnet";
} {
  const out: ReturnType<typeof sanitizeSettings> = {};
  for (const key of ["maxSatsPerPayment", "maxSatsPerSitePerDay", "maxSatsPerDay"] as const) {
    if (patch[key] === undefined) continue;
    const n = patch[key];
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > MAX_CAP) {
      throw new Error(`Settings: ${key} must be a whole number of sats between 1 and ${MAX_CAP}.`);
    }
    out[key] = n;
  }
  if (patch.network !== undefined) {
    if (patch.network !== "regtest" && patch.network !== "mainnet") {
      throw new Error("Settings: network must be mainnet or regtest.");
    }
    out.network = patch.network;
  }
  return out;
}
