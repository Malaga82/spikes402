import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  badgeAfterPriceReport,
  badgeColor,
  badgeTitle,
  flashPaidIcon,
  formatBadgeText,
  ICON_FLASH_COUNT,
  ICON_FLASH_MS,
  pageKey,
  restoreTabIcon,
  samePage,
  satWord,
} from "./badge";

describe("formatBadgeText", () => {
  it("shows sats up to 9999, then thousands", () => {
    expect(formatBadgeText(1)).toBe("1");
    expect(formatBadgeText(10)).toBe("10");
    expect(formatBadgeText(9999)).toBe("9999");
    expect(formatBadgeText(10_000)).toBe("10k");
    expect(formatBadgeText(19999)).toBe("19k");
    expect(formatBadgeText(1_000_000)).toBe("1M+");
    expect(formatBadgeText(0)).toBe("");
  });
});

describe("badge copy and color", () => {
  it("changes the title and colour for paid and confirm states", () => {
    const base = { amountSats: 10, paid: false, needsConfirm: false };
    expect(badgeTitle(base)).toBe("This page costs 10 sats to open.");
    expect(badgeColor(base)).toBe("#44403c");
    expect(badgeTitle({ ...base, paid: true })).toMatch(/^Paid 10 sats/);
    expect(badgeColor({ ...base, paid: true })).toBe("#0f766e");
    expect(badgeTitle({ ...base, needsConfirm: true })).toMatch(/Confirm in the popup/);
    expect(badgeColor({ ...base, needsConfirm: true })).toBe("#b45309");
  });

  it("uses singular sat for 1 and plural sats otherwise", () => {
    expect(satWord(1)).toBe("sat");
    expect(satWord(0)).toBe("sats");
    expect(satWord(2)).toBe("sats");
    const one = { amountSats: 1, paid: false, needsConfirm: false };
    expect(badgeTitle(one)).toBe("This page costs 1 sat to open.");
    expect(badgeTitle({ ...one, paid: true })).toBe("Paid 1 sat to open this page.");
    expect(badgeTitle({ ...one, needsConfirm: true })).toBe("This page costs 1 sat to open. Confirm in the popup.");
  });
});

describe("same page URL", () => {
  it("compares origin, path and query, and ignores the hash", () => {
    expect(pageKey("https://a.example/premium/a?x=1#y")).toBe("https://a.example/premium/a?x=1");
    expect(samePage("https://a.example/premium/a", "https://a.example/premium/a?")).toBe(true);
    expect(samePage("https://a.example/premium/a", "https://a.example/premium/a/")).toBe(false);
    expect(samePage("https://a.example/premium/a", "https://a.example/other")).toBe(false);
    expect(samePage("https://a.example/premium/a", "chrome://extensions")).toBe(false);
    expect(samePage(undefined, "https://a.example/")).toBe(false);
  });
});

describe("badgeAfterPriceReport", () => {
  const url = "https://a.example/premium/article";
  const paid = { amountSats: 2, paid: true, needsConfirm: false, pageUrl: url };

  it("shows the muted price on a 402 page, and keeps paid + confirm across a same-URL reload", () => {
    expect(badgeAfterPriceReport(undefined, 2, url)).toEqual({
      amountSats: 2, paid: false, needsConfirm: false, pageUrl: url,
    });
    // After redeem the invoice is gone, so the script reports no price on the same URL.
    expect(badgeAfterPriceReport(paid, undefined, url)).toEqual(paid);
    // A report of the same price on the same URL (for example pageshow) stays paid.
    expect(badgeAfterPriceReport(paid, 2, url)?.paid).toBe(true);
  });

  it("clears the badge when the tab moves to another URL, or to a page with no price that was not just paid", () => {
    expect(badgeAfterPriceReport(paid, undefined, "https://a.example/blog")).toBeUndefined();
    expect(badgeAfterPriceReport(paid, 5, "https://a.example/other")).toMatchObject({
      amountSats: 5, paid: false, pageUrl: "https://a.example/other",
    });
    expect(badgeAfterPriceReport({ ...paid, paid: false }, undefined, url)).toBeUndefined();
  });
});

describe("flashPaidIcon", () => {
  const calls: { tabId: number; path: Record<string, string> }[] = [];

  beforeEach(() => {
    calls.length = 0;
    (globalThis as unknown as { chrome: unknown }).chrome = {
      action: {
        setIcon: async (opts: { tabId: number; path: Record<string, string> }) => {
          calls.push(opts);
        },
      },
    };
  });

  afterEach(() => {
    vi.useRealTimers();
    restoreTabIcon(1);
  });

  it("flashes the yellow icon three times in about 1.5 seconds, then restores the usual icon", async () => {
    vi.useFakeTimers();
    flashPaidIcon(1);
    await vi.advanceTimersByTimeAsync(0);
    const yellow = "icons/icon-flash-16.png";
    const usual = "icons/icon-16.png";
    const kinds = () => calls.map((c) => (c.path["16"] === yellow ? "y" : c.path["16"] === usual ? "u" : "?"));

    await vi.advanceTimersByTimeAsync(ICON_FLASH_MS * 2 * ICON_FLASH_COUNT);
    expect(kinds().join("")).toBe("yuyuyu");
    expect(calls[0].tabId).toBe(1);
    expect(calls.length).toBe(ICON_FLASH_COUNT * 2);
  });
});
