/**
 * Isolated content script: a bridge between the page (inject-webln) and
 * the extension background, and a reader of this page's price for the
 * toolbar badge. The origin sent with every request is taken from this
 * frame (location.origin). The background also ignores any origin the
 * page includes and uses sender.origin / sender.tab.url.
 */
import { parseBolt11AmountSats } from "./invoice";

const SOURCE = "spikes402-webln";
const REPLY = "spikes402-webln-reply";
const METHODS = new Set(["enable", "getInfo", "sendPayment"]);

window.addEventListener("message", (ev: MessageEvent) => {
  const d = ev.data;
  // A sandboxed document (opaque origin "null") is not the site it is served from.
  if (ev.source !== window || ev.origin !== location.origin || location.origin === "null") return;
  if (!d || d.source !== SOURCE || typeof d.id !== "number") return;
  if (typeof d.method !== "string" || !METHODS.has(d.method)) return;
  const origin = location.origin;
  chrome.runtime.sendMessage(
    { type: "webln", method: d.method, origin, invoice: d.invoice },
    (res) => {
      const error = chrome.runtime.lastError?.message ?? (res && res.error);
      if (d.method === "sendPayment") {
        // Failed: show the page again so the person can see why. Paid: the
        // page reloads itself; the timer only covers a page that does not.
        if (error) hidePaying();
        else setTimeout(hidePaying, 10_000);
      }
      window.postMessage(
        { source: REPLY, id: d.id, result: error ? undefined : res, error: error || undefined },
        location.origin,
      );
    },
  );
});

function findPagePrice(): number | null {
  const btn = document.getElementById("webln-pay");
  const fromBtn = btn?.getAttribute("data-invoice");
  const fromLink = document.querySelector("a[href^='lightning:']")?.getAttribute("href");
  for (const raw of [fromBtn, fromLink]) {
    if (!raw) continue;
    try {
      const n = parseBolt11AmountSats(raw);
      if (n !== null && n > 0) return n;
    } catch {
      /* not a usable invoice */
    }
  }
  return null;
}

function reportPrice() {
  chrome.runtime.sendMessage({ type: "pagePrice", amountSats: findPagePrice() }, () => {
    void chrome.runtime.lastError;
  });
}

chrome.runtime.sendMessage({ type: "pagePrice", amountSats: null }, () => {
  void chrome.runtime.lastError;
});
document.addEventListener("DOMContentLoaded", reportPrice);
window.addEventListener("pageshow", reportPrice);
if (document.readyState !== "loading") reportPrice();

// A payment takes a few seconds. When the wallet will pay this 402 page by
// itself, cover the page at once with a short notice instead of letting
// people look at the QR code and wonder.
let overlay: HTMLElement | undefined;

function showPaying(sats: number) {
  if (overlay) return;
  const box = document.createElement("div");
  Object.assign(box.style, {
    position: "fixed",
    inset: "0",
    zIndex: "2147483647",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: "8px",
    background: "#fafaf9",
    color: "#1c1917",
    font: "18px system-ui, sans-serif",
    textAlign: "center",
  });
  const title = document.createElement("div");
  title.textContent = `Paying ${sats} sat${sats === 1 ? "" : "s"}…`;
  const hint = document.createElement("div");
  hint.textContent = "Spikes402 Wallet is paying for this page. It opens in a moment.";
  Object.assign(hint.style, { fontSize: "13px", color: "#57534e" });
  box.append(title, hint);
  overlay = box;
  document.documentElement.append(box);
}

function hidePaying() {
  overlay?.remove();
  overlay = undefined;
}

let checked = false;
function checkAutoPay() {
  if (checked) return;
  const invoice = document.getElementById("webln-pay")?.getAttribute("data-invoice");
  if (!invoice) return;
  checked = true;
  chrome.runtime.sendMessage({ type: "autoPayCheck", invoice }, (res) => {
    void chrome.runtime.lastError;
    if (res && res.willPay === true && typeof res.amountSats === "number") showPaying(res.amountSats);
  });
}

// Look as soon as the invoice button is parsed, not only when the page is done.
const watcher = new MutationObserver(checkAutoPay);
watcher.observe(document, { childList: true, subtree: true });
document.addEventListener("DOMContentLoaded", () => {
  checkAutoPay();
  watcher.disconnect();
});
