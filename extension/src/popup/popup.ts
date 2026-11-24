import { pickPositions, type QuizAnswer } from "../backup";
import { isValidMnemonic, normalizeMnemonic } from "../crypto";
import type { PaymentRecord, PendingPayment, Settings, WalletInfo } from "../types";
import { satWord } from "../badge";
import { historyRow } from "./format";
import { invoiceQrSvg } from "./qr";

type Snapshot = { info: WalletInfo; settings: Settings; history: PaymentRecord[]; pending?: PendingPayment; pendingCount?: number };

const LIVE_EVERY_MS = 4000;
const REVEAL_SHOWN_MS = 60_000;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const input = (id: string) => $<HTMLInputElement>(id);

let current = "";
let lastSnap: Snapshot | undefined;
let lastBalance: number | undefined;
let setup: { mode: "create" | "restore"; words?: string } = { mode: "create" };
// Only in this popup's memory: gone when it closes, so reopening asks for the password again.
let backup: { password: string; mnemonic: string } | undefined;
let revealTimer: ReturnType<typeof setTimeout> | undefined;

type MsgKind = "ok" | "err" | "info";

function showMsg(text: string, kind: MsgKind | boolean = "ok") {
  const el = $("msg");
  el.hidden = !text;
  el.textContent = text;
  // `true` is kept as a synonym of "err" so existing call sites stay obvious.
  const k: MsgKind = kind === true ? "err" : kind === false ? "ok" : kind;
  el.classList.toggle("err", k === "err");
  el.classList.toggle("info", k === "info");
}

const fail = (e: unknown) => showMsg(e instanceof Error ? e.message : String(e), "err");

function call<T>(msg: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (res) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (res && typeof res === "object" && "error" in res && res.error) {
        reject(new Error(String(res.error)));
        return;
      }
      resolve(res as T);
    });
  });
}

function show(id: string) {
  current = id;
  for (const sec of Array.from(document.querySelectorAll("section"))) {
    (sec as HTMLElement).hidden = sec.id !== id;
  }
}

/** A real form: Enter submits it. */
function onSubmit(id: string, fn: () => Promise<void> | void) {
  $(id).addEventListener("submit", (ev) => {
    ev.preventDefault();
    showMsg("");
    void Promise.resolve()
      .then(fn)
      .catch(fail);
  });
}

function fillWords(list: HTMLElement, mnemonic: string) {
  list.replaceChildren();
  for (const word of mnemonic.split(" ")) {
    const li = document.createElement("li");
    li.textContent = word;
    list.append(li);
  }
}

// ---- drawing

async function refresh(keepMessage = false) {
  if (!keepMessage) showMsg("");
  render(await call<Snapshot>({ type: "getState" }), true);
}

function render(snap: Snapshot, full: boolean) {
  lastSnap = snap;
  const { info, settings, pending, pendingCount = 0 } = snap;
  $("network-flag").textContent = info.network === "mainnet" ? "Real bitcoin" : "Test network (no real money)";

  // A site asking to be trusted comes first, whatever else the wallet shows.
  if (pending?.kind === "trust") {
    const box = $("view-trust");
    if (box.dataset.id !== pending.id) {
      box.dataset.id = pending.id;
      $("trust-site").textContent = pending.site ?? pending.origin;
      $("trust-origin").textContent = `Asked from ${pending.origin}`;
      input("trust-limit").value = String(settings.maxSatsPerSitePerDay);
    }
    show("view-trust");
    return;
  }
  delete $("view-trust").dataset.id;

  if (!info.hasVault) {
    if (current !== "view-restore" && current !== "view-password") show("view-setup");
    return;
  }
  if (info.backupPending) {
    showBackup();
    return;
  }
  if (!info.unlocked) {
    show("view-unlock");
    return;
  }

  if (current !== "view-history") show("view-main");
  if (info.balanceSats !== undefined) {
    if (lastBalance !== undefined && info.balanceSats > lastBalance && !$("recv-out").hidden) {
      showMsg(`Received ${info.balanceSats - lastBalance} sats.`);
      $("recv-out").hidden = true;
    }
    lastBalance = info.balanceSats;
  }
  $("balance").textContent = info.balanceSats === undefined ? "—" : String(info.balanceSats);
  $("lightning-hint").textContent = info.lightningHint ?? "";
  $("lightning-hint").hidden = !info.lightningHint;

  const pendingBox = $("pending-box");
  if (pending) {
    pendingBox.hidden = false;
    const fee = pending.costSats - pending.amountSats;
    const more = pendingCount > 1 ? ` (${pendingCount - 1} more waiting)` : "";
    $("pending-text").textContent = `This page costs ${pending.amountSats} ${satWord(pending.amountSats)} + a fee of up to ${fee} ${satWord(fee)}. ${pending.reason}${more}`;
    $("pending-origin").textContent = pending.origin;
    pendingBox.dataset.id = pending.id;
  } else {
    pendingBox.hidden = true;
    delete pendingBox.dataset.id;
  }

  renderSites(settings.sites ?? {});
  if (full) {
    input("set-per-pay").value = String(settings.maxSatsPerPayment);
    input("set-per-site").value = String(settings.maxSatsPerSitePerDay);
    input("set-per-day").value = String(settings.maxSatsPerDay);
    $<HTMLSelectElement>("set-network").value = settings.network;
  }
  if (current === "view-history") renderHistory(snap.history);
}

function renderSites(sites: Settings["sites"]) {
  const entries = Object.entries(sites).sort(([a], [b]) => a.localeCompare(b));
  const list = $("sites");
  if (!entries.length) {
    const li = document.createElement("li");
    li.textContent = "None yet. A site asks the first time it wants to pay.";
    return list.replaceChildren(li);
  }
  list.replaceChildren(
    ...entries.map(([site, rule]) => {
      const li = document.createElement("li");
      const name = document.createElement("strong");
      name.textContent = site;
      const note = document.createTextNode(rule.trusted ? ` up to ${rule.dailySats} sats a day ` : " not allowed ");
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "secondary";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => void call({ type: "forgetSite", site }).then(() => refresh(true)).catch(fail));
      li.append(name, note, remove);
      return li;
    }),
  );
}

function renderHistory(history: PaymentRecord[]) {
  const list = $("history");
  list.replaceChildren();
  if (history.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No payments yet.";
    list.append(li);
    return;
  }
  for (const rec of history) {
    const row = historyRow(rec);
    const li = document.createElement("li");
    const top = document.createElement("div");
    top.className = "h-top";
    const site = document.createElement("span");
    site.className = "h-site";
    site.textContent = row.site;
    site.title = row.site;
    const time = document.createElement("span");
    time.className = "h-time";
    time.textContent = row.time;
    top.append(site, time);

    const nums = document.createElement("div");
    nums.className = "h-nums";
    const cell = (label: string, value: string) => {
      const c = document.createElement("span");
      c.textContent = `${label} ${value}`;
      return c;
    };
    if (row.status === "paid") {
      nums.append(cell("Price", `${row.price}`), cell("Fee", `${row.fee ?? "?"}`), cell("Total", `${row.total} sats`));
    } else {
      const label = { failed: "Not paid", declined: "Declined", waiting: "Waiting for the result" }[row.status];
      nums.append(cell(label + " ·", `${row.price} sats`));
    }
    li.append(top, nums);
    list.append(li);
  }
}

// ---- onboarding: choose, (words,) password

$("btn-create").addEventListener("click", () => {
  setup = { mode: "create" };
  openPasswordStep();
});

$("btn-show-restore").addEventListener("click", () => {
  showMsg("");
  setup = { mode: "restore" };
  show("view-restore");
});

$("btn-restore-back").addEventListener("click", () => {
  showMsg("");
  ($("restore-words") as HTMLTextAreaElement).value = "";
  show("view-setup");
});

onSubmit("form-restore-words", () => {
  const words = normalizeMnemonic(($("restore-words") as HTMLTextAreaElement).value);
  const n = words ? words.split(" ").length : 0;
  if (n !== 12 && n !== 24) throw new Error(`Type all 12 words, with a space between them. You typed ${n}.`);
  if (!isValidMnemonic(words)) throw new Error("These words are not a valid recovery phrase. Check each word for typing mistakes.");
  setup.words = words;
  openPasswordStep();
});

function openPasswordStep() {
  showMsg("");
  const restore = setup.mode === "restore";
  $("password-title").textContent = restore ? "Choose a password" : "Choose a password";
  $("password-help").textContent = restore
    ? "It protects the wallet on this computer. You need it every time you unlock."
    : "It protects the wallet on this computer. You need it every time you unlock. We cannot reset it.";
  $("btn-password-submit").textContent = restore ? "Restore wallet" : "Create wallet";
  show("view-password");
}

$("btn-password-back").addEventListener("click", () => {
  showMsg("");
  input("setup-pass").value = "";
  input("setup-pass2").value = "";
  show(setup.mode === "restore" ? "view-restore" : "view-setup");
});

onSubmit("form-password", async () => {
  const a = input("setup-pass").value;
  if (a.length < 8) throw new Error("Use a password of at least 8 characters.");
  if (a !== input("setup-pass2").value) throw new Error("The two passwords are not the same.");
  if (setup.mode === "restore") {
    await call({ type: "restoreWallet", mnemonic: setup.words ?? "", password: a });
    setup = { mode: "create" };
    ($("restore-words") as HTMLTextAreaElement).value = "";
  } else {
    const { mnemonic } = await call<{ mnemonic: string }>({ type: "createWallet", password: a });
    backup = { password: a, mnemonic };
  }
  input("setup-pass").value = "";
  input("setup-pass2").value = "";
  await refresh();
});

// ---- backup: the wallet only opens after the words are checked

function showBackup() {
  show("view-backup");
  $("form-backup-gate").hidden = !!backup;
  $("backup-words").hidden = !backup;
  $("form-backup-quiz").hidden = true;
  if (backup) fillWords($("mnemonic-list"), backup.mnemonic);
}

onSubmit("form-backup-gate", async () => {
  const password = input("gate-pass").value;
  const { mnemonic } = await call<{ mnemonic: string }>({ type: "revealPhrase", password });
  backup = { password, mnemonic };
  input("gate-pass").value = "";
  showBackup();
});

$("btn-backup-next").addEventListener("click", () => {
  if (!backup) return;
  const words = backup.mnemonic.split(" ");
  const box = $("quiz-fields");
  box.replaceChildren();
  for (const index of pickPositions(words.length)) {
    const label = document.createElement("label");
    label.textContent = `Word number ${index + 1}`;
    const field = document.createElement("input");
    field.type = "text";
    field.dataset.index = String(index);
    field.autocomplete = "off";
    field.autocapitalize = "none";
    field.spellcheck = false;
    label.append(field);
    box.append(label);
  }
  $("backup-words").hidden = true;
  $("form-backup-quiz").hidden = false;
  box.querySelector("input")?.focus();
});

$("btn-quiz-back").addEventListener("click", () => {
  showMsg("");
  $("form-backup-quiz").hidden = true;
  $("backup-words").hidden = false;
});

onSubmit("form-backup-quiz", async () => {
  if (!backup) return;
  const answers: QuizAnswer[] = Array.from($("quiz-fields").querySelectorAll("input")).map((f) => ({
    index: Number(f.dataset.index),
    word: f.value,
  }));
  await call({ type: "confirmBackup", password: backup.password, answers });
  backup = undefined;
  $("mnemonic-list").replaceChildren();
  $("quiz-fields").replaceChildren();
  await refresh();
});

// ---- unlock, lock

onSubmit("form-unlock", async () => {
  await call({ type: "unlock", password: input("unlock-pass").value });
  input("unlock-pass").value = "";
  await refresh();
});

$("btn-lock").addEventListener("click", async () => {
  hideReveal();
  await call({ type: "lock" });
  await refresh();
});

// ---- wallet

onSubmit("form-receive", async () => {
  const amountSats = Number(input("recv-amount").value);
  const res = await call<{ invoice: string }>({ type: "receive", amountSats });
  $("recv-out").hidden = false;
  $("recv-invoice").textContent = res.invoice;
  $("recv-qr").innerHTML = invoiceQrSvg(res.invoice);
});

$("btn-copy-invoice").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("recv-invoice").textContent ?? "");
  showMsg("Invoice copied.");
});

onSubmit("form-send", async () => {
  const destination = ($("send-dest") as HTMLTextAreaElement).value;
  const raw = input("send-amount").value;
  const amountSats = raw ? Number(raw) : undefined;
  const button = $<HTMLButtonElement>("form-send").querySelector("button[type=submit]") as HTMLButtonElement;
  button.disabled = true; // one send at a time
  showMsg("Sending…", "info");
  try {
    const res = await call<{ detail: string }>({ type: "send", destination, amountSats });
    ($("send-dest") as HTMLTextAreaElement).value = "";
    input("send-amount").value = "";
    await refresh(true);
    showMsg(res.detail || "Sent.");
    setTimeout(() => void live(), 1500); // the balance can take a moment to follow
  } finally {
    button.disabled = false;
  }
});

$("btn-history").addEventListener("click", () => {
  showMsg("");
  show("view-history");
  if (lastSnap) renderHistory(lastSnap.history);
  void refresh();
});

$("btn-history-back").addEventListener("click", () => {
  show("view-main");
  void refresh().catch(fail);
});

$("btn-save-budget").addEventListener("click", async () => {
  try {
    await call({
      type: "saveSettings",
      settings: {
        maxSatsPerPayment: Number(input("set-per-pay").value),
        maxSatsPerSitePerDay: Number(input("set-per-site").value),
        maxSatsPerDay: Number(input("set-per-day").value),
      },
    });
    await refresh(true);
    showMsg("Limits saved.");
  } catch (e) {
    fail(e);
  }
});

$("btn-save-network").addEventListener("click", async () => {
  try {
    await call({ type: "saveSettings", settings: { network: $<HTMLSelectElement>("set-network").value } });
    await refresh(true);
    showMsg("Saved. Lock and unlock the wallet to use the new network.");
  } catch (e) {
    fail(e);
  }
});

// ---- recovery words, behind the password

function hideReveal() {
  clearTimeout(revealTimer);
  $("reveal-out").hidden = true;
  $("reveal-list").replaceChildren();
}

onSubmit("form-reveal", async () => {
  const { mnemonic } = await call<{ mnemonic: string }>({ type: "revealPhrase", password: input("reveal-pass").value });
  input("reveal-pass").value = "";
  fillWords($("reveal-list"), mnemonic);
  $("reveal-out").hidden = false;
  clearTimeout(revealTimer);
  revealTimer = setTimeout(hideReveal, REVEAL_SHOWN_MS);
});

$("btn-reveal-hide").addEventListener("click", hideReveal);

// ---- payment confirmation

onSubmit("form-trust", () => answerTrust("always"));
$("btn-trust-refuse").addEventListener("click", () => void answerTrust("refuse").catch(fail));

async function answerTrust(choice: "always" | "refuse") {
  const id = $("view-trust").dataset.id;
  if (!id) return;
  await call({ type: "confirmPayment", id, choice, dailySats: Number(input("trust-limit").value) });
  await refresh();
}

async function confirmPending(choice: "once" | "always" | "refuse") {
  const id = $("pending-box").dataset.id;
  if (!id) return;
  await call({ type: "confirmPayment", id, choice });
  await refresh();
}

$("btn-accept-once").addEventListener("click", () => void confirmPending("once").catch(fail));
$("btn-accept-always").addEventListener("click", () => void confirmPending("always").catch(fail));
$("btn-decline").addEventListener("click", () => void confirmPending("refuse").catch(fail));

// ---- keep the open popup up to date (balance after a receive or a payment, new confirmations)

let polling = false;
async function live() {
  if (polling || (current !== "view-main" && current !== "view-history" && current !== "view-trust")) return;
  polling = true;
  try {
    const snap = await call<Snapshot>({ type: "getState" });
    if (!snap.info.unlocked || snap.info.backupPending) render(snap, true); // locked meanwhile: show the right screen
    else render(snap, false);
  } catch {
    /* the next tick tries again */
  } finally {
    polling = false;
  }
}
setInterval(() => void live(), LIVE_EVERY_MS);

void refresh().catch(fail);
