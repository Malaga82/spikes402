import {
  applyTabBadge,
  badgeAfterPriceReport,
  flashPaidIcon,
  pageKey,
  restoreTabIcon,
  samePage,
  type TabPrice,
} from "./badge";
import {
  adjustSpend,
  decidePayment,
  paymentCost,
  recordSpend,
  spendForToday,
  todayLocal,
  withSiteAllowance,
  withSiteRule,
  withoutSite,
  type ConfirmChoice,
  type Decision,
} from "./budget";
import { encryptMnemonic, generateMnemonic, isValidMnemonic, normalizeMnemonic } from "./crypto";
import type { QuizAnswer } from "./backup";
import { InvoiceError, isBolt11, parseBolt11AmountSats } from "./invoice";
import { looksLikeLightningAddress, parseLightningAddress, resolveLightningAddress, UNSUPPORTED_ADDRESS } from "./lnaddress";
import { lightningHint } from "./backend";
import { isExtensionPage, pageOrigin, sanitizeSettings } from "./sender";
import { siteKey } from "./site";
import { maxFeeSatsFor } from "./spark-util";
import {
  appendHistory,
  loadState,
  pushHistory,
  saveSettings,
  saveVault,
  truncateDestination,
  updateState,
} from "./storage";
import type { PaymentRecord, PendingPayment, Reservation, Settings, WalletInfo } from "./types";

const CONFIRM_TTL_MS = 5 * 60 * 1000;
const MAX_PROMPTS = 10;
const RECONCILE_EVERY_MS = 30 * 1000;
const waiters = new Map<string, { resolve: (choice: ConfirmChoice) => void }>();
const tabPrices = new Map<number, TabPrice>();

// A restarted worker has lost the callbacks of every waiting prompt and of
// every payment that was being sent: drop the prompts, and treat the
// payments as unconfirmed (they stay counted in the budget).
void updateState((s) => {
  s.prompts = [];
  s.reservations = s.reservations.map((r) => (r.state === "in_flight" ? { ...r, state: "uncertain" } : r));
}).then(reconcile).catch(() => undefined);

type PopupMsg =
  | { type: "getState" }
  | { type: "createWallet"; password: string }
  | { type: "restoreWallet"; mnemonic: string; password: string }
  | { type: "revealPhrase"; password: string }
  | { type: "confirmBackup"; password: string; answers: QuizAnswer[] }
  | { type: "unlock"; password: string }
  | { type: "lock" }
  | { type: "saveSettings"; settings: Partial<Settings> }
  | { type: "receive"; amountSats: number }
  | { type: "send"; destination: string; amountSats?: number }
  | { type: "walletRequestId"; id: string; requestId: string }
  | { type: "confirmPayment"; id: string; choice: ConfirmChoice; dailySats?: number }
  | { type: "forgetSite"; site: string };

type PageMsg = { type: "webln"; method: "enable" | "getInfo" | "sendPayment"; origin: string; invoice?: string };
type PagePriceMsg = { type: "pagePrice"; amountSats: number | null };
type AutoPayMsg = { type: "autoPayCheck"; invoice: string };

chrome.runtime.onInstalled.addListener(() => {
  void ensureWalletHost();
});

chrome.runtime.onStartup?.addListener(() => {
  void ensureWalletHost();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabPrices.delete(tabId);
  restoreTabIcon(tabId);
});

// The badge is per-tab and Chrome clears it on navigation. If the new URL
// is not the page we just paid, drop the memory and the icon flash too.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (!info.url) return;
  const prev = tabPrices.get(tabId);
  if (!prev) return;
  if (samePage(prev.pageUrl, info.url)) return;
  tabPrices.delete(tabId);
  restoreTabIcon(tabId);
  void applyTabBadge(tabId, undefined);
});

chrome.runtime.onMessage.addListener((msg: PopupMsg | PageMsg | PagePriceMsg | AutoPayMsg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || !("type" in msg)) return;
  if ((msg as { target?: string }).target === "wallet") return; // for the wallet host
  handle(msg, sender)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ error: e instanceof Error ? e.message : String(e) }));
  return true;
});

async function handle(msg: PopupMsg | PageMsg | PagePriceMsg | AutoPayMsg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  if (msg.type === "autoPayCheck") return autoPayCheck(msg, sender);
  if (msg.type === "pagePrice") {
    handlePagePrice(msg, sender);
    return { ok: true };
  }
  if (msg.type === "walletRequestId") {
    // The wallet host reports the Spark request id as soon as the send starts,
    // so a send whose answer is lost can still be looked up after a restart.
    // Checked by exact URL, before the popup-only gate: on Firefox the host is
    // a popup window, so its messages carry sender.tab.
    if (sender.url !== chrome.runtime.getURL("offscreen.html")) throw new Error("Only the wallet host can register a send.");
    const uncertain = await updateState((s) => {
      const r = s.reservations.find((x) => x.id === msg.id);
      if (r) r.requestId = msg.requestId;
      return r?.state === "uncertain";
    });
    if (uncertain) scheduleReconcile();
    return { ok: true };
  }
  if (msg.type !== "webln" && !isExtensionPage(sender, chrome.runtime.getURL(""))) {
    throw new Error("This action is only available from the extension popup.");
  }
  switch (msg.type) {
    case "getState":
      return snapshot();
    case "createWallet":
      return createWallet(msg.password);
    case "restoreWallet":
      return restoreWallet(msg.mnemonic, msg.password);
    case "revealPhrase":
      return revealPhrase(msg.password);
    case "confirmBackup":
      return confirmBackup(msg.password, msg.answers);
    case "unlock":
      return unlock(msg.password);
    case "lock":
      return lock();
    case "saveSettings":
      await saveSettings(sanitizeSettings(msg.settings as unknown as Record<string, unknown>));
      return snapshot();
    case "receive":
      return receiveInvoice(msg.amountSats);
    case "send":
      return sendFromPopup(msg.destination, msg.amountSats);
    case "confirmPayment":
      return resolvePending(msg.id, msg.choice, msg.dailySats);
    case "forgetSite":
      return forgetSite(msg.site);
    case "webln":
      return handleWebln(msg, sender);
    default:
      throw new Error("Unknown message");
  }
}

async function snapshot(): Promise<{
  info: WalletInfo;
  settings: Settings;
  history: PaymentRecord[];
  pending?: PendingPayment;
  pendingCount: number;
}> {
  void reconcile();
  const s = await loadState();
  const host = await walletCall<{ unlocked?: boolean }>("status").catch(() => ({ unlocked: false }));
  const unlocked = !!host.unlocked;
  const hint = lightningHint(s.settings.network);
  const info: WalletInfo = {
    unlocked,
    hasVault: !!s.vault,
    backupPending: !!s.backupPending,
    network: s.settings.network,
    lightningReady: hint.ready,
    lightningHint: hint.hint,
  };
  if (unlocked) {
    try {
      const w = await walletCall<{ balanceSats: number; pubkey: string }>("getInfo");
      info.balanceSats = w.balanceSats;
    } catch (e) {
      info.lightningHint = e instanceof Error ? e.message : String(e);
    }
  }
  return { info, settings: s.settings, history: [...s.history].reverse(), pending: s.prompts[0], pendingCount: s.prompts.length };
}

async function createWallet(password: string): Promise<{ mnemonic: string }> {
  const s = await loadState();
  if (s.vault) throw new Error("A wallet already exists in this browser. Unlock it, or remove the extension data first.");
  const mnemonic = generateMnemonic();
  const vault = await encryptMnemonic(mnemonic, password);
  // The wallet stays locked until the owner proves they saved the words (see
  // confirmBackup). The flag is stored with the vault in one step, so closing
  // the popup at any moment resumes the backup instead of skipping it.
  await updateState((st) => {
    st.vault = vault;
    st.backupPending = true;
  });
  return { mnemonic };
}

/** Show the phrase again; only with the password, and only decrypted in the wallet host. */
async function revealPhrase(password: string): Promise<{ mnemonic: string }> {
  const s = await loadState();
  if (!s.vault) throw new Error("No wallet is stored yet.");
  await ensureWalletHost();
  return walletCall<{ mnemonic: string }>("reveal", { vault: s.vault, password });
}

/** The owner typed back some of the words: the wallet may now be used. */
async function confirmBackup(password: string, answers: QuizAnswer[]): Promise<{ ok: true }> {
  const s = await loadState();
  if (!s.vault || !s.backupPending) throw new Error("There is nothing to confirm.");
  await ensureWalletHost();
  await walletCall("checkWords", { vault: s.vault, password, answers });
  await updateState((st) => {
    st.backupPending = false;
  });
  return unlock(password);
}

async function restoreWallet(mnemonic: string, password: string): Promise<{ ok: true }> {
  const s = await loadState();
  if (s.vault) throw new Error("A wallet already exists in this browser. Unlock it, or remove the extension data first.");
  const words = normalizeMnemonic(mnemonic);
  if (!isValidMnemonic(words)) throw new Error("That is not a valid 12- or 24-word recovery phrase.");
  await saveVault(await encryptMnemonic(words, password));
  await unlock(password);
  return { ok: true };
}

async function unlock(password: string): Promise<{ ok: true }> {
  const s = await loadState();
  if (!s.vault) throw new Error("No wallet is stored yet.");
  if (s.backupPending) throw new Error("First check that you saved your 12 words. Open the wallet to finish setting up.");
  await ensureWalletHost();
  // Decrypt only in the wallet host, so the service worker never holds the phrase.
  await walletCall("connect", {
    vault: s.vault,
    password,
    network: s.settings.network,
  });
  void reconcile();
  return { ok: true };
}

async function lock(): Promise<{ ok: true }> {
  await walletCall("disconnect").catch(() => undefined);
  return { ok: true };
}

async function receiveInvoice(amountSats: number): Promise<{ invoice: string; feeSats: number }> {
  if (!Number.isInteger(amountSats) || amountSats < 1) throw new Error("Enter an amount of at least 1 sat.");
  return walletCall("receive", { amountSats });
}

async function sendFromPopup(destination: string, amountSats?: number): Promise<{ detail: string }> {
  let dest = destination.trim();
  if (!dest) throw new Error("Enter an invoice or address.");
  let amount = amountSats;
  let paidTo: string | undefined;
  if (looksLikeLightningAddress(dest)) {
    // name@domain: ask the address for an invoice of exactly this amount, then pay that invoice.
    const parsed = parseLightningAddress(dest);
    if (!parsed) throw new Error(UNSUPPORTED_ADDRESS);
    paidTo = `${parsed.user}@${parsed.domain}`;
    dest = (await resolveLightningAddress(parsed, amount ?? 0)).invoice;
  }
  if (isBolt11(dest)) {
    const encoded = parseBolt11AmountSats(dest);
    if (encoded !== null) amount = encoded;
  }
  // Same fee rule as page payments: the wallet may not spend more fee than this.
  const maxFeeSats = isBolt11(dest) ? maxFeeSatsFor(amount ?? 0) : undefined;
  const res = await walletCall<{ preimage?: string; detail: string; feeSats?: number }>("send", {
    destination: dest,
    amountSats: amount,
    ...(maxFeeSats === undefined ? {} : { maxFeeSats }),
  });
  await appendHistory({
    time: new Date().toISOString(),
    origin: "popup",
    amountSats: (amount ?? 0) + (res.feeSats ?? 0),
    priceSats: amount ?? 0,
    ...(res.feeSats === undefined ? {} : { feeSats: res.feeSats }),
    destination: truncateDestination(paidTo ?? dest),
    result: "sent",
    detail: "Sent.", // never keep the preimage in the history
  });
  const sent = amount ?? 0;
  return { detail: `Sent ${sent} sats${res.feeSats === undefined ? "" : ` (fee ${res.feeSats})`}.` };
}

async function handleWebln(msg: PageMsg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const origin = pageOrigin(sender);
  if (!origin) throw new Error("This payment request has no page origin.");
  const site = siteKey(origin);
  if (!site) throw new Error("The Spikes402 wallet only works on https sites (and http://localhost for development).");
  // Before anything else, and whether or not the wallet is unlocked, so an
  // unknown site learns nothing about the wallet: it must be trusted first.
  await requireTrust(site, origin, sender.tab?.id);

  const host = await walletCall<{ unlocked?: boolean }>("status").catch(() => ({ unlocked: false }));
  if (!host.unlocked) throw new Error("The Spikes402 wallet is locked. Open the extension and unlock it.");

  if (msg.method === "enable") return { enabled: true };
  if (msg.method === "getInfo") {
    return { node: { alias: "Spikes402" }, methods: ["sendPayment", "getInfo"] };
  }
  if (msg.method !== "sendPayment" || !msg.invoice) throw new Error("sendPayment needs an invoice.");
  const invoice = msg.invoice;

  let amountSats: number | null;
  try {
    amountSats = parseBolt11AmountSats(invoice);
  } catch (e) {
    const reason = e instanceof InvoiceError ? e.message : "Invoice could not be read.";
    await log(origin, 0, invoice, "refused", reason);
    throw new Error(reason);
  }
  // One fee rule: the amount we count in every cap is the amount we allow the wallet to spend.
  const feeSats = amountSats === null ? 0 : maxFeeSatsFor(amountSats);

  let reserved = await reserve({ origin, site, amountSats, feeSats, invoice, force: false });
  if (reserved.action === "refuse") {
    await log(origin, amountSats ?? 0, invoice, "refused", reserved.reason);
    throw new Error(reserved.reason);
  }
  if (reserved.action === "confirm") {
    const choice = await askUser({
      origin,
      invoice,
      amountSats: amountSats ?? 0,
      costSats: paymentCost(amountSats ?? 0, feeSats),
      reason: reserved.reason,
      tabId: sender.tab?.id,
    });
    if (choice === "refuse") {
      await log(origin, amountSats ?? 0, invoice, "refused", "You declined the payment.");
      throw new Error("Payment declined.");
    }
    reserved = await reserve({ origin, site, amountSats, feeSats, invoice, force: true });
  }
  if (reserved.action !== "reserved") throw new Error("The payment could not be reserved.");
  const reservation = reserved.reservation;

  // The budget is already booked, so the wallet call runs outside any lock:
  // a slow or hostile invoice cannot hold up other payments.
  try {
    const res = await walletCall<{ preimage?: string; detail: string; feeSats?: number }>("send", {
      destination: invoice,
      maxFeeSats: feeSats,
      reservationId: reservation.id,
    });
    if (!res?.preimage) throw new WalletCallError("The wallet did not return a preimage.", true);
    await finishReservation(reservation.id, { settled: true, feeSats: res.feeSats }, "Paid.");
    markPaid(sender.tab?.id, amountSats ?? 0, sender.tab?.url);
    return { preimage: res.preimage };
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    if (e instanceof WalletCallError && e.uncertain) {
      await markUncertain(reservation.id, e.requestId, detail);
      scheduleReconcile();
      throw new Error(
        "The payment has not been confirmed yet. It may still go through, so it stays counted in your budget until it settles or fails. Do not pay this invoice again.",
      );
    }
    await finishReservation(reservation.id, { settled: false }, detail);
    throw e;
  }
}

const NOT_ALLOWED = "This site is not allowed to use the Spikes402 wallet.";
// One question per site at a time: further calls from the same site wait for the same answer.
const trustAsks = new Map<string, Promise<void>>();

/**
 * A site may use the wallet only after the user said so. The first request
 * from a site (enable or sendPayment) asks; "Allow" stores the site with its
 * daily limit, "Don't allow" stores it as turned down so it does not nag.
 * No answer in time rejects this call and stores nothing.
 */
async function requireTrust(site: string, origin: string, tabId: number | undefined): Promise<void> {
  const rule = (await loadState()).settings.sites[site];
  if (rule) {
    if (rule.trusted) return;
    throw new Error(NOT_ALLOWED);
  }
  let ask = trustAsks.get(site);
  if (!ask) {
    ask = (async () => {
      try {
        const s = await loadState();
        await askUser({
          kind: "trust",
          site,
          origin,
          invoice: "",
          amountSats: 0,
          costSats: 0,
          reason: `Allow automatic payments on ${site}, up to ${s.settings.maxSatsPerSitePerDay} sats a day?`,
          tabId,
        });
      } finally {
        trustAsks.delete(site);
      }
    })();
    trustAsks.set(site, ask);
  }
  await ask;
  // The answer is in the stored list (askUser alone only says what was clicked).
  if (!(await loadState()).settings.sites[site]?.trusted) throw new Error(NOT_ALLOWED);
}

/** Remove a site from the list: it is no longer trusted (or turned down) and asks again next time. */
async function forgetSite(site: string): Promise<{ ok: true }> {
  if (typeof site !== "string") throw new Error("Unknown site.");
  await updateState((s) => {
    s.settings = withoutSite(s.settings, site);
  });
  return { ok: true };
}

/**
 * Will this page be paid without asking? The page content script uses the
 * answer to cover the 402 page with a "Paying…" notice at once, instead of
 * showing the QR code for the few seconds a payment takes. It reserves
 * nothing and pays nothing.
 */
async function autoPayCheck(msg: AutoPayMsg, sender: chrome.runtime.MessageSender): Promise<{ willPay: boolean; amountSats?: number }> {
  const origin = pageOrigin(sender);
  const site = origin ? siteKey(origin) : undefined;
  if (!site || typeof msg.invoice !== "string") return { willPay: false };
  const host = await walletCall<{ unlocked?: boolean }>("status").catch(() => ({ unlocked: false }));
  if (!host.unlocked) return { willPay: false };
  let amountSats: number | null;
  try {
    amountSats = parseBolt11AmountSats(msg.invoice);
  } catch {
    return { willPay: false };
  }
  if (amountSats === null) return { willPay: false };
  const s = await loadState();
  const today = todayLocal();
  const d = decidePayment({
    amountSats,
    site,
    settings: s.settings,
    spend: spendForToday(s.spend, today),
    today,
    feeSats: maxFeeSatsFor(amountSats),
  });
  return d.action === "pay" ? { willPay: true, amountSats } : { willPay: false };
}

type Reserved = Decision | { action: "reserved"; reservation: Reservation };

/**
 * Check the caps and book the full cost (amount plus fee cap) in one atomic
 * step. After a user confirmation (force) the caps are not asked again.
 */
function reserve(p: {
  origin: string;
  site: string;
  amountSats: number | null;
  feeSats: number;
  invoice: string;
  force: boolean;
}): Promise<Reserved> {
  return updateState((s): Reserved => {
    const today = todayLocal();
    const spend = spendForToday(s.spend, today);
    const d = decidePayment({
      amountSats: p.amountSats,
      site: p.site,
      settings: s.settings,
      spend,
      today,
      feeSats: p.feeSats,
    });
    if (d.action === "refuse" || (d.action === "confirm" && !p.force)) return d;
    const cost = paymentCost(p.amountSats ?? 0, p.feeSats);
    const reservation: Reservation = {
      id: crypto.randomUUID(),
      origin: p.origin,
      day: today,
      amountSats: p.amountSats ?? 0,
      feeSats: p.feeSats,
      invoice: p.invoice,
      state: "in_flight",
      time: new Date().toISOString(),
    };
    s.spend = recordSpend(spend, today, p.site, cost);
    // A payment without a request id cannot be looked up; its day is over, so is its budget.
    s.reservations = [...s.reservations.filter((r) => r.requestId || r.day === today), reservation];
    return { action: "reserved", reservation };
  });
}

/** Settle a reservation: count the real cost, or release it on a confirmed failure. */
function finishReservation(
  id: string,
  outcome: { settled: true; feeSats?: number } | { settled: false },
  detail: string,
): Promise<void> {
  return updateState((s) => {
    const r = s.reservations.find((x) => x.id === id);
    if (!r) return;
    s.reservations = s.reservations.filter((x) => x.id !== id);
    const reserved = paymentCost(r.amountSats, r.feeSats);
    const actual = outcome.settled ? paymentCost(r.amountSats, outcome.feeSats ?? r.feeSats) : 0;
    s.spend = adjustSpend(spendForToday(s.spend, todayLocal()), r.day, siteKey(r.origin) ?? r.origin, actual - reserved);
    pushHistory(s, {
      time: new Date().toISOString(),
      origin: r.origin,
      amountSats: outcome.settled ? actual : r.amountSats,
      priceSats: r.amountSats,
      ...(outcome.settled ? { feeSats: outcome.feeSats ?? r.feeSats } : {}),
      destination: truncateDestination(r.invoice),
      result: outcome.settled ? "sent" : "failed",
      detail,
    });
  });
}

function markUncertain(id: string, requestId: string | undefined, detail: string): Promise<void> {
  return updateState((s) => {
    const r = s.reservations.find((x) => x.id === id);
    if (!r) return;
    r.state = "uncertain";
    if (requestId) r.requestId = requestId;
    pushHistory(s, {
      time: new Date().toISOString(),
      origin: r.origin,
      amountSats: paymentCost(r.amountSats, r.feeSats),
      priceSats: r.amountSats,
      destination: truncateDestination(r.invoice),
      result: "pending",
      detail: `${detail} Not confirmed; still counted in the budget.`,
    });
  });
}

let reconciling = false;
let reconcileTimer: ReturnType<typeof setTimeout> | undefined;

/** Retry the lookup of unconfirmed payments until each is settled or failed. */
function scheduleReconcile(): void {
  if (reconcileTimer !== undefined) return;
  reconcileTimer = setTimeout(() => {
    reconcileTimer = undefined;
    void reconcile();
  }, RECONCILE_EVERY_MS);
}

/**
 * Ask the wallet about every unconfirmed payment that has a request id. Only
 * a confirmed answer changes the budget: settled counts the real cost,
 * failed releases it, pending leaves it as it is.
 */
async function reconcile(): Promise<void> {
  if (reconciling) return;
  reconciling = true;
  try {
    const todo = (await loadState()).reservations.filter((r) => r.state === "uncertain" && r.requestId);
    let unresolved = false;
    for (const r of todo) {
      try {
        const res = await walletCall<{ state: "settled" | "failed" | "pending"; feeSats?: number }>("lookupSend", {
          requestId: r.requestId,
          invoice: r.invoice,
        });
        if (res.state === "settled") {
          await finishReservation(r.id, { settled: true, feeSats: res.feeSats }, "Confirmed later: the payment settled.");
        } else if (res.state === "failed") {
          await finishReservation(r.id, { settled: false }, "Confirmed later: the payment failed; the amount is free again.");
        } else {
          unresolved = true;
        }
      } catch {
        unresolved = true; // wallet locked or busy: try again later
      }
    }
    if (unresolved) scheduleReconcile();
  } finally {
    reconciling = false;
  }
}

/**
 * Queue a confirmation for the user. Each prompt has its own id and timer;
 * an expired or answered prompt is gone and cannot be answered again.
 */
function askUser(p: Omit<PendingPayment, "id" | "createdAt">): Promise<ConfirmChoice> {
  const id = crypto.randomUUID();
  const pending: PendingPayment = { ...p, id, createdAt: Date.now() };
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (!waiters.delete(id)) return; // already answered
      void updateState((s) => {
        s.prompts = s.prompts.filter((x) => x.id !== id);
      });
      markConfirm(pending.tabId, false);
      resolve("refuse");
    }, CONFIRM_TTL_MS);
    waiters.set(id, {
      resolve: (choice) => {
        clearTimeout(timer);
        resolve(choice);
      },
    });
    updateState((s) => {
      if (s.prompts.length >= MAX_PROMPTS) return false;
      s.prompts = [...s.prompts, pending];
      return true;
    }).then(
      (queued) => {
        if (!queued) {
          clearTimeout(timer);
          waiters.delete(id);
          resolve("refuse");
          return;
        }
        markConfirm(pending.tabId, true);
        void openPopup(pending);
      },
      () => {
        clearTimeout(timer);
        waiters.delete(id);
        resolve("refuse");
      },
    );
  });
}

async function resolvePending(id: string, choice: ConfirmChoice, dailySats?: number): Promise<{ ok: true }> {
  let answered: { pending: PendingPayment; waiter: { resolve: (c: ConfirmChoice) => void } } | undefined;
  await updateState((s) => {
    const pending = s.prompts.find((x) => x.id === id);
    const waiter = waiters.get(id);
    // No waiter means it expired or the worker restarted: drop it and store nothing.
    if (!pending || !waiter) {
      s.prompts = s.prompts.filter((x) => x.id !== id);
      return;
    }
    // A bad answer throws before anything is taken, so the question stays open.
    if (pending.kind === "trust") {
      if (!pending.site || (choice !== "always" && choice !== "refuse")) throw new Error("Choose to allow or not to allow this site.");
      const limit = dailySats ?? s.settings.maxSatsPerSitePerDay;
      if (choice === "always" && (!Number.isSafeInteger(limit) || limit < 1)) throw new Error("The daily limit must be a whole number of sats, at least 1.");
      s.settings = withSiteRule(s.settings, pending.site, { trusted: choice === "always", dailySats: limit, since: new Date().toISOString() });
    } else if (choice === "always") {
      s.settings = { ...s.settings, ...withSiteAllowance(s.settings, pending.site ?? siteKey(pending.origin) ?? pending.origin, pending.costSats) };
    }
    s.prompts = s.prompts.filter((x) => x.id !== id);
    waiters.delete(id); // same synchronous step as the check: the timer cannot slip in
    answered = { pending, waiter };
  });
  if (!answered) throw new Error("This confirmation has expired.");
  markConfirm(answered.pending.tabId, false);
  answered.waiter.resolve(choice);
  return { ok: true };
}

function handlePagePrice(msg: PagePriceMsg, sender: chrome.runtime.MessageSender): void {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return;
  const amount =
    typeof msg.amountSats === "number" && Number.isFinite(msg.amountSats) && msg.amountSats > 0
      ? Math.floor(msg.amountSats)
      : undefined;
  const pageUrl = sender.tab?.url ?? sender.url;
  const state = badgeAfterPriceReport(tabPrices.get(tabId), amount, pageUrl);
  if (state) tabPrices.set(tabId, state);
  else tabPrices.delete(tabId);
  void applyTabBadge(tabId, state);
}

function markPaid(tabId: number | undefined, amountSats: number, pageUrl?: string): void {
  if (tabId === undefined) return;
  const prev = tabPrices.get(tabId);
  const state: TabPrice = {
    amountSats: prev?.amountSats ?? amountSats,
    paid: true,
    needsConfirm: false,
    pageUrl: pageKey(pageUrl) || prev?.pageUrl,
  };
  tabPrices.set(tabId, state);
  void applyTabBadge(tabId, state);
  flashPaidIcon(tabId);
}

function markConfirm(tabId: number | undefined, needsConfirm: boolean): void {
  if (tabId === undefined) return;
  const prev = tabPrices.get(tabId);
  if (!prev) return;
  const state = { ...prev, needsConfirm };
  tabPrices.set(tabId, state);
  void applyTabBadge(tabId, state);
}

async function log(
  origin: string,
  amountSats: number,
  destination: string,
  result: PaymentRecord["result"],
  detail: string,
) {
  await appendHistory({
    time: new Date().toISOString(),
    origin,
    amountSats,
    destination: truncateDestination(destination),
    result,
    detail,
  });
}

async function openPopup(pending?: { kind?: "trust"; site?: string; origin: string; amountSats: number; costSats: number }) {
  try {
    if (chrome.action.openPopup) await chrome.action.openPopup();
  } catch {
    /* some Chrome views refuse this; the toolbar badge still shows the page price */
  }
  const summary = pending?.kind === "trust"
    ? `${pending.site ?? pending.origin} wants to pay with your wallet. Open the wallet to allow or refuse.`
    : pending
    ? `${pending.origin} asks for ${pending.amountSats} sats + a fee of up to ${pending.costSats - pending.amountSats}. Open the wallet to pay or decline.`
    : "Open the wallet to pay or decline.";
  try {
    await chrome.notifications.create("spikes402-confirm", {
      type: "basic",
      iconUrl: "icons/icon-128.png",
      title: pending?.kind === "trust" ? "Spikes402: a site wants to pay" : "Spikes402: a payment needs your OK",
      message: summary,
      priority: 2,
    });
  } catch {
    /* notifications permission may be missing on some browsers */
  }
}

/** A wallet call failed. `uncertain` means the payment may still have gone out. */
class WalletCallError extends Error {
  constructor(
    message: string,
    readonly uncertain = false,
    readonly requestId?: string,
  ) {
    super(message);
  }
}

// The message never reached the wallet host, so nothing was sent.
const NOT_DELIVERED = /receiving end does not exist|could not establish connection/i;

function walletCall<T = unknown>(type: string, extra?: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ target: "wallet", type, ...extra }, (res) => {
      if (chrome.runtime.lastError) {
        const m = chrome.runtime.lastError.message ?? "The wallet host did not answer.";
        reject(new WalletCallError(m, type === "send" && !NOT_DELIVERED.test(m)));
        return;
      }
      if (res && typeof res === "object" && "error" in res && res.error) {
        const r = res as { error: unknown; uncertain?: boolean; requestId?: string };
        reject(new WalletCallError(String(r.error), !!r.uncertain, r.requestId));
        return;
      }
      resolve(res as T);
    });
  });
}

async function ensureWalletHost(): Promise<void> {
  const url = chrome.runtime.getURL("offscreen.html");
  if (chrome.offscreen) {
    const already = await chrome.runtime.getContexts?.({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    if (already && already.length > 0) return;
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.WORKERS],
      justification: "Run the local Spark wallet outside the short-lived service worker.",
    });
    return;
  }
  // Firefox has no offscreen documents. A small host window is the fallback;
  // see README.
  const wins = await chrome.windows.getAll({ populate: true });
  const open = wins.some((w) => w.tabs?.some((t) => t.url === url));
  if (open) return;
  await chrome.windows.create({ url, type: "popup", width: 360, height: 200, focused: false });
}
