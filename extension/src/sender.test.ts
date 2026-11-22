import { describe, expect, it } from "vitest";
import { isExtensionPage, pageOrigin, sanitizeSettings } from "./sender";

const base = "chrome-extension://abcdefghijklmnop/";

describe("isExtensionPage", () => {
  it("accepts the popup and the offscreen document, and refuses a content script", () => {
    expect(isExtensionPage({ url: base + "index.html" }, base)).toBe(true);
    expect(isExtensionPage({ url: base + "offscreen.html" }, base)).toBe(true);
    expect(isExtensionPage({ url: base + "background.js" }, base)).toBe(true);
    expect(isExtensionPage({ url: "https://evil.example/", tab: { id: 1 } }, base)).toBe(false);
    expect(isExtensionPage({ url: "https://evil.example/" }, base)).toBe(false);
    expect(isExtensionPage({ url: base + "index.html", tab: { id: 1 } }, base)).toBe(false);
    expect(isExtensionPage({}, base)).toBe(false);
  });
});

describe("pageOrigin", () => {
  it("prefers sender.origin and falls back to the tab URL", () => {
    expect(pageOrigin({ origin: "https://pay.example" })).toBe("https://pay.example");
    expect(pageOrigin({ tab: { url: "https://pay.example/a?b=1" } })).toBe("https://pay.example");
    // A sandboxed document (opaque origin) is not the site in the tab's URL.
    expect(pageOrigin({ origin: "null", url: "https://pay.example/x", tab: { url: "https://pay.example/x" } })).toBeUndefined();
    expect(pageOrigin({ origin: "chrome-extension://abc" })).toBeUndefined();
    expect(pageOrigin({})).toBeUndefined();
  });
});

describe("sanitizeSettings", () => {
  it("accepts well-formed values and rejects NaN, fractions, and zero", () => {
    expect(sanitizeSettings({ maxSatsPerPayment: 10, network: "mainnet" })).toEqual({
      maxSatsPerPayment: 10,
      network: "mainnet",
    });
    expect(() => sanitizeSettings({ maxSatsPerPayment: Number.NaN })).toThrow(/whole number/);
    expect(() => sanitizeSettings({ maxSatsPerDay: 1.5 })).toThrow(/whole number/);
    expect(() => sanitizeSettings({ maxSatsPerSitePerDay: 0 })).toThrow(/whole number/);
    expect(() => sanitizeSettings({ network: "testnet" })).toThrow(/mainnet or regtest/);
  });
});
