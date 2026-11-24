/** Toolbar badge: the sats this tab's page costs to open. */

export type TabPrice = {
  amountSats: number;
  paid: boolean;
  needsConfirm: boolean;
  /** Origin + path + query of the page this price belongs to. */
  pageUrl?: string;
};

const PAID = "#0f766e";
const CONFIRM = "#b45309";
const PRICE = "#44403c";

/** Short text for chrome.action.setBadgeText (about four characters). */
export function formatBadgeText(amountSats: number): string {
  if (!Number.isFinite(amountSats) || amountSats < 1) return "";
  if (amountSats < 10_000) return String(Math.floor(amountSats));
  if (amountSats < 1_000_000) return `${Math.floor(amountSats / 1000)}k`;
  return "1M+";
}

export function badgeColor(state: TabPrice): string {
  if (state.needsConfirm) return CONFIRM;
  if (state.paid) return PAID;
  return PRICE;
}

export function satWord(n: number): string {
  return n === 1 ? "sat" : "sats";
}

export function badgeTitle(state: TabPrice): string {
  const n = state.amountSats;
  const unit = satWord(n);
  if (state.paid) return `Paid ${n} ${unit} to open this page.`;
  if (state.needsConfirm) return `This page costs ${n} ${unit} to open. Confirm in the popup.`;
  return `This page costs ${n} ${unit} to open.`;
}

export async function applyTabBadge(tabId: number, state: TabPrice | undefined): Promise<void> {
  if (tabId < 0) return;
  try {
    if (!state) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      await chrome.action.setTitle({ tabId, title: "Spikes402 Wallet" });
      return;
    }
    await chrome.action.setBadgeText({ tabId, text: formatBadgeText(state.amountSats) });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor(state) });
    await chrome.action.setTitle({ tabId, title: badgeTitle(state) });
  } catch {
    /* tab may already be gone */
  }
}

/** http(s) origin + path + query; empty if the URL is not a page. */
export function pageKey(url: string | undefined): string {
  if (!url) return "";
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.origin + u.pathname + u.search;
  } catch {
    return "";
  }
}

export function samePage(a: string | undefined, b: string | undefined): boolean {
  const ka = pageKey(a);
  const kb = pageKey(b);
  return !!ka && ka === kb;
}

/**
 * The next badge after the content script reports a price (or none).
 *
 * After a successful pay the page reloads on the same URL and the invoice is
 * gone, so the script reports no price — and Chrome also clears a tab's badge
 * on that navigation. If we just paid this URL, keep the teal badge and write
 * it again. A different URL clears it.
 */
export function badgeAfterPriceReport(
  prev: TabPrice | undefined,
  amount: number | undefined,
  pageUrl: string | undefined,
): TabPrice | undefined {
  const key = pageKey(pageUrl);
  if (amount) {
    const same = samePage(prev?.pageUrl, pageUrl);
    return {
      amountSats: amount,
      paid: !!prev?.paid && prev.amountSats === amount && same,
      needsConfirm: !!prev?.needsConfirm && same,
      pageUrl: key || prev?.pageUrl,
    };
  }
  if (prev?.paid && samePage(prev.pageUrl, pageUrl)) return prev;
  return undefined;
}

const DEFAULT_ICONS: Record<string, string> = {
  "16": "icons/icon-16.png",
  "32": "icons/icon-32.png",
  "48": "icons/icon-48.png",
  "128": "icons/icon-128.png",
};
const FLASH_ICONS: Record<string, string> = {
  "16": "icons/icon-flash-16.png",
  "32": "icons/icon-flash-32.png",
  "48": "icons/icon-flash-48.png",
  "128": "icons/icon-flash-128.png",
};

/** Three 250 ms flashes of the yellow icon, then back to the usual one (~1.5 s). */
export const ICON_FLASH_MS = 250;
export const ICON_FLASH_COUNT = 3;

const flashes = new Map<number, ReturnType<typeof setTimeout>[]>();

async function setTabIcon(tabId: number, path: Record<string, string>): Promise<void> {
  try {
    await chrome.action.setIcon({ tabId, path });
  } catch {
    /* tab may already be gone */
  }
}

function cancelFlash(tabId: number): void {
  const timers = flashes.get(tabId);
  if (timers) {
    for (const t of timers) clearTimeout(t);
    flashes.delete(tabId);
  }
}

/** Stop a flash in progress and put the usual icon back (for example after leaving the page). */
export function restoreTabIcon(tabId: number): void {
  cancelFlash(tabId);
  void setTabIcon(tabId, DEFAULT_ICONS);
}

/** A short yellow flash on the toolbar icon, then the usual icon again. */
export function flashPaidIcon(tabId: number): void {
  if (tabId < 0) return;
  cancelFlash(tabId);
  const timers: ReturnType<typeof setTimeout>[] = [];
  flashes.set(tabId, timers);
  for (let i = 0; i < ICON_FLASH_COUNT; i++) {
    const on = i * 2 * ICON_FLASH_MS;
    const off = on + ICON_FLASH_MS;
    timers.push(setTimeout(() => void setTabIcon(tabId, FLASH_ICONS), on));
    timers.push(setTimeout(() => void setTabIcon(tabId, DEFAULT_ICONS), off));
  }
}
