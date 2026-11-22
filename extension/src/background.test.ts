import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encodeBolt11ForTest } from "./invoice";
import { maxFeeSatsFor } from "./spark-util";
import type { PendingPayment, Reservation } from "./types";

type Listener = (msg: unknown, sender: unknown, send: (r: unknown) => void) => boolean | void;
type Reply = Record<string, unknown>;

let store: Record<string, unknown>;
let listener: Listener;
let walletSend: (msg: Record<string, unknown>) => Promise<Reply>;
let walletLookup: (msg: Record<string, unknown>) => Promise<Reply>;
let sends: Record<string, unknown>[];
let walletOther: (msg: Record<string, unknown>) => Reply;
let hostUnlocked: boolean;
let walletCalls: Record<string, unknown>[];
let badges: Record<number, { text?: string; color?: string; title?: string }>;
let icons: { tabId: number; path: Record<string, string> }[];
let tabUpdated: ((tabId: number, info: { url?: string }, tab?: { url?: string }) => void) | undefined;

const OK = (feeSats?: number): Reply => ({ preimage: "00".repeat(32), detail: "ok", ...(feeSats === undefined ? {} : { feeSats }) });
const PENDING_REPLY: Reply = { error: "Timed out waiting for the Lightning payment preimage.", uncertain: true, requestId: "req-1" };

function installChrome() {
  store = {};
  sends = [];
  walletSend = async () => OK();
  walletLookup = async () => ({ state: "pending" });
  walletOther = () => ({});
  hostUnlocked = true;
  walletCalls = [];
  badges = {};
  icons = [];
  tabUpdated = undefined;
  const noop = async () => undefined;
  const badge = (tabId: number) => (badges[tabId] ??= {});
  (globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      onInstalled: { addListener: () => undefined },
      onStartup: { addListener: () => undefined },
      onMessage: { addListener: (l: Listener) => (listener = l) },
      getURL: (path = "") => "chrome-extension://abc/" + path,
      getContexts: async () => [{}], // the wallet host is already running
      lastError: undefined,
      sendMessage: (msg: Record<string, unknown>, cb: (r: unknown) => void) => {
        if (msg.target !== "wallet") return;
        const done = (r: unknown) => queueMicrotask(() => cb(r));
        walletCalls.push(msg);
        if (msg.type === "status") return done({ unlocked: hostUnlocked });
        if (msg.type === "send") {
          sends.push(msg);
          void walletSend(msg).then(done);
          return;
        }
        if (msg.type === "lookupSend") {
          void walletLookup(msg).then(done);
          return;
        }
        done(walletOther(msg));
      },
    },
    offscreen: { createDocument: noop, Reason: { WORKERS: "WORKERS" } },
    tabs: {
      onRemoved: { addListener: () => undefined },
      onUpdated: { addListener: (l: typeof tabUpdated) => (tabUpdated = l) },
    },
    storage: {
      local: {
        get: async (k: string) => ({ [k]: structuredClone(store[k]) }),
        set: async (o: Record<string, unknown>) => {
          Object.assign(store, structuredClone(o));
        },
      },
    },
    action: {
      setBadgeText: async (o: { tabId: number; text: string }) => {
        badge(o.tabId).text = o.text;
      },
      setTitle: async (o: { tabId: number; title: string }) => {
        badge(o.tabId).title = o.title;
      },
      setBadgeBackgroundColor: async (o: { tabId: number; color: string }) => {
        badge(o.tabId).color = o.color;
      },
      setIcon: async (o: { tabId: number; path: Record<string, string> }) => {
        icons.push(o);
      },
      openPopup: noop,
    },
    notifications: { create: noop },
  };
}

const pageSender = (origin: string, tab = 1) => ({ origin, url: origin + "/", tab: { id: tab, url: origin + "/" } });
const ext = { url: "chrome-extension://abc/index.html" };
const call = (msg: unknown, sender: unknown) =>
  new Promise<{ error?: string } & Record<string, unknown>>((res) => listener(msg, sender, res as (r: unknown) => void));
const pay = (origin: string, invoice: string, tab = 1) =>
  call({ type: "webln", method: "sendPayment", origin, invoice }, pageSender(origin, tab));
const answer = (id: string, choice: "once" | "always" | "refuse") => call({ type: "confirmPayment", id, choice }, ext);

type Stored = {
  spend?: { globalSats: number; perSite: Record<string, number> };
  history?: { result: string; detail: string; amountSats: number; priceSats?: number; feeSats?: number; origin?: string }[];
  vault?: unknown;
  backupPending?: boolean;
  prompts?: PendingPayment[];
  reservations?: Reservation[];
  settings?: { siteAllowances: Record<string, number>; maxSatsPerSitePerDay: number };
};
const state = () => (store["spikes402"] ?? {}) as Stored;
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

const small = () => encodeBolt11ForTest("lnbc50n"); // 5 sats, fee cap 5: costs 10, fits the default caps
const big = () => encodeBolt11ForTest("lnbc2500n"); // 250 sats: above the 10 sat cap, asks the user

async function boot() {
  vi.resetModules();
  await import("./background");
  await tick(1);
}

const SITES = ["a.example", "one.example", "two.example", "evil.example", "example.com", "hold.example", "other.example"];
const trustedSites = (dailySats = 100) =>
  Object.fromEntries(SITES.map((d) => [d, { trusted: true, dailySats, since: "2026-11-01T00:00:00.000Z" }]));

beforeEach(async () => {
  installChrome();
  // The sites these tests pay from are trusted already; trust itself is tested at the end.
  store["spikes402"] = { settings: { sites: trustedSites() } };
  await boot();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("a payment that does not finish in time", () => {
  it("reconciles a send registered by the wallet host even after the background restarts", async () => {
    walletSend = () => new Promise(() => undefined);
    void pay("https://evil.example", small());
    await vi.waitFor(() => expect(sends).toHaveLength(1));
    const id = sends[0].reservationId;
    const msg = { type: "walletRequestId", id, requestId: "req-registered" };
    expect((await call(msg, pageSender("https://evil.example"))).error).toBeTruthy();
    expect((await call(msg, ext)).error).toMatch(/wallet host/);
    expect(await call(msg, { url: "chrome-extension://abc/offscreen.html" })).toEqual({ ok: true });
    expect(state().reservations?.[0]).toMatchObject({ state: "in_flight", requestId: "req-registered" });
    walletLookup = async () => ({ state: "settled", feeSats: 1 });
    await boot();
    await vi.waitFor(() => expect(state().reservations).toHaveLength(0));
    expect(state().spend?.globalSats).toBe(6);
  });

  it("stays counted in the budget as unconfirmed, not failed", async () => {
    walletSend = async () => PENDING_REPLY;
    const r = await pay("https://evil.example", small());
    expect(r.error).toMatch(/not been confirmed/);
    const s = state();
    expect(s.spend?.globalSats).toBe(10); // amount + fee cap are still reserved
    expect(s.reservations).toHaveLength(1);
    expect(s.reservations?.[0]).toMatchObject({ state: "uncertain", requestId: "req-1" });
    expect(s.history?.[0].result).toBe("pending");

    walletSend = async () => OK();
    expect((await pay("https://evil.example", small())).error).toBeUndefined();
    expect(state().spend?.globalSats).toBe(20); // the first payment was not forgotten
  });

  it("is released only when the wallet confirms the payment failed", async () => {
    walletSend = async () => PENDING_REPLY;
    await pay("https://evil.example", small());

    await call({ type: "getState" }, ext); // still pending: nothing changes
    await tick();
    expect(state().spend?.globalSats).toBe(10);
    expect(state().reservations).toHaveLength(1);

    walletLookup = async () => ({ state: "failed" });
    await call({ type: "getState" }, ext);
    await vi.waitFor(() => expect(state().reservations).toHaveLength(0));
    expect(state().spend?.globalSats).toBe(0);
    expect(state().history?.at(-1)?.result).toBe("failed");
  });

  it("is booked at the real cost when the wallet confirms it settled", async () => {
    walletSend = async () => PENDING_REPLY;
    await pay("https://evil.example", small());
    walletLookup = async () => ({ state: "settled", feeSats: 1 });
    await call({ type: "getState" }, ext);
    await vi.waitFor(() => expect(state().reservations).toHaveLength(0));
    expect(state().spend?.globalSats).toBe(6); // 5 sats + 1 sat real fee
    expect(state().history?.at(-1)).toMatchObject({ result: "sent", amountSats: 6 });
  });

  it("a clear wallet failure releases the reservation at once", async () => {
    walletSend = async () => ({ error: "Insufficient balance" });
    const r = await pay("https://evil.example", small());
    expect(r.error).toMatch(/Insufficient/);
    expect(state().spend?.globalSats).toBe(0);
    expect(state().reservations).toHaveLength(0);
    expect(state().history?.[0].result).toBe("failed");
  });

  it("a restart marks payments that were being sent as unconfirmed, and drops waiting prompts", async () => {
    store["spikes402"] = {
      spend: { day: "2026-11-21", globalSats: 10, perSite: {} },
      prompts: [{ id: "p", origin: "https://a.example", invoice: "x", amountSats: 1, costSats: 6, reason: "r", createdAt: 1 }],
      reservations: [
        { id: "r", origin: "https://a.example", day: "2026-11-21", amountSats: 5, feeSats: 5, invoice: "x", state: "in_flight", time: "t" },
      ],
    };
    await boot();
    expect(state().prompts).toEqual([]);
    expect(state().reservations?.[0].state).toBe("uncertain");
  });
});

describe("locking", () => {
  it("a hold invoice does not stall other payments, and caps stay race-free", async () => {
    let release!: () => void;
    walletSend = () => new Promise((res) => (release = () => res(OK())));
    const first = pay("https://hold.example", small(), 1);
    await tick();
    expect(sends).toHaveLength(1);

    walletSend = async () => OK();
    const second = await pay("https://other.example", small(), 2); // returns while the first is still pending
    expect(second.error).toBeUndefined();
    expect(state().reservations).toHaveLength(1);
    release();
    expect((await first).error).toBeUndefined();
    expect(state().spend?.globalSats).toBe(20);
    expect(state().reservations).toHaveLength(0);
  });

  it("two payments cannot both pass a cap that fits only one", async () => {
    store["spikes402"] = {
      settings: { maxSatsPerPayment: 10, maxSatsPerSitePerDay: 15, maxSatsPerDay: 500, siteAllowances: {}, sites: trustedSites(15), network: "mainnet" },
    };
    await boot();
    walletSend = () => new Promise(() => undefined); // both would be in flight together
    void pay("https://a.example", small(), 1);
    void pay("https://a.example", small(), 2);
    await tick();
    expect(sends).toHaveLength(1); // the second one is asked about, not paid
    expect(state().prompts).toHaveLength(1);
    expect(state().spend?.globalSats).toBe(10);
  });
});

describe("confirmation prompts", () => {
  it("queues prompts instead of overwriting one slot", async () => {
    const p1 = pay("https://one.example", big(), 1);
    const p2 = pay("https://two.example", big(), 2);
    await tick();
    const prompts = state().prompts ?? [];
    expect(prompts.map((p) => p.origin).sort()).toEqual(["https://one.example", "https://two.example"]);

    const snap = (await call({ type: "getState" }, ext)) as unknown as { pending?: PendingPayment; pendingCount: number };
    expect(snap.pendingCount).toBe(2);

    const first = prompts.find((p) => p.origin === "https://one.example")!;
    expect((await answer(first.id, "once")).error).toBeUndefined();
    expect((await p1).error).toBeUndefined();
    expect(state().prompts?.map((p) => p.origin)).toEqual(["https://two.example"]); // the other is still waiting

    expect((await answer(prompts.find((p) => p.origin === "https://two.example")!.id, "refuse")).error).toBeUndefined();
    expect((await p2).error).toMatch(/declined/);
  });

  it("an expiry timer only removes its own prompt", async () => {
    vi.useFakeTimers();
    const p1 = pay("https://one.example", big(), 1);
    await vi.advanceTimersByTimeAsync(10);
    await vi.advanceTimersByTimeAsync(2 * 60 * 1000);
    const p2 = pay("https://two.example", big(), 2);
    await vi.advanceTimersByTimeAsync(10);
    expect(state().prompts).toHaveLength(2);

    await vi.advanceTimersByTimeAsync(3 * 60 * 1000 + 100); // the 1st prompt (5 min old) expires, the 2nd is 3 min old
    expect((await p1).error).toMatch(/declined/);
    expect(state().prompts?.map((p) => p.origin)).toEqual(["https://two.example"]);

    const second = state().prompts![0];
    expect((await answer(second.id, "once")).error).toBeUndefined();
    expect((await p2).error).toBeUndefined();
  });

  it("an expired or answered prompt cannot be answered again or store an 'always' allowance", async () => {
    vi.useFakeTimers();
    const p = pay("https://one.example", big(), 1);
    await vi.advanceTimersByTimeAsync(10);
    const id = state().prompts![0].id;
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 100);
    await p.catch(() => undefined);
    expect(state().prompts).toEqual([]);

    expect((await answer(id, "always")).error).toMatch(/expired/);
    expect(state().settings?.siteAllowances ?? {}).toEqual({});
    expect(sends).toHaveLength(0);

    vi.useRealTimers();
    const q = pay("https://two.example", big(), 2);
    await tick();
    const id2 = state().prompts![0].id;
    expect((await answer(id2, "refuse")).error).toBeUndefined();
    await q.catch(() => undefined);
    expect((await answer(id2, "always")).error).toMatch(/expired/); // a declined prompt cannot be revived
    expect(state().settings?.siteAllowances ?? {}).toEqual({});
  });
});

describe("fee cap", () => {
  it("gives the wallet the same fee cap the budget counted", async () => {
    const q = pay("https://one.example", big(), 1);
    await tick();
    await answer(state().prompts![0].id, "once");
    await q;
    expect(sends[0].maxFeeSats).toBe(maxFeeSatsFor(250)); // 25, not the SDK default of 5
    expect(state().spend?.globalSats).toBe(250 + 25); // fee not reported: the cap is what was counted

    await pay("https://two.example", small(), 2);
    expect(sends[1].maxFeeSats).toBe(maxFeeSatsFor(5));
  });
});

describe("history and prompts show the fee", () => {
  it("records price, real fee and total of a paid page, without the preimage", async () => {
    walletSend = async () => OK(4);
    expect((await pay("https://a.example", encodeBolt11ForTest("lnbc20n"))).error).toBeUndefined(); // 2 sats
    expect(state().history?.at(-1)).toMatchObject({ result: "sent", priceSats: 2, feeSats: 4, amountSats: 6, origin: "https://a.example" });
    expect(JSON.stringify(state().history)).not.toMatch(/preimage|0000/);
  });

  it("the page price and the biggest fee must fit the per-page cap together", async () => {
    // 6 sats + fee cap 5 = 11 > 10: asks, and the prompt carries both numbers.
    const p = pay("https://a.example", encodeBolt11ForTest("lnbc60n"));
    await tick();
    const prompt = state().prompts![0];
    expect(prompt).toMatchObject({ amountSats: 6, costSats: 11 });
    expect(prompt.reason).toMatch(/more than your limit for one page \(10 sats, fee included\)/);
    expect(sends).toHaveLength(0);
    await answer(prompt.id, "refuse");
    await p;
    // 5 sats + 5 = 10 fits exactly: paid without asking.
    expect((await pay("https://a.example", small())).error).toBeUndefined();
  });
});

describe("a new wallet is not usable until the words are confirmed", () => {
  const PW = "correct horse battery";

  it("creating keeps it locked, remembers the pending backup, and refuses to unlock", async () => {
    const r = await call({ type: "createWallet", password: PW }, ext);
    expect(r.error).toBeUndefined();
    expect(String(r.mnemonic).split(" ")).toHaveLength(12);
    expect(state().backupPending).toBe(true);
    expect(state().vault).toBeTruthy();
    expect(JSON.stringify(store)).not.toContain(String(r.mnemonic)); // only the encrypted vault is stored
    expect(walletCalls.some((m) => m.type === "connect")).toBe(false);

    expect((await call({ type: "unlock", password: PW }, ext)).error).toMatch(/12 words/);
    expect(walletCalls.some((m) => m.type === "connect")).toBe(false);
    const snap = (await call({ type: "getState" }, ext)) as unknown as { info: { backupPending: boolean } };
    expect(snap.info.backupPending).toBe(true); // reopening the popup resumes the backup step
  });

  it("a wrong quiz keeps it locked; a right one clears the flag and unlocks", async () => {
    await call({ type: "createWallet", password: PW }, ext);
    const answers = [{ index: 0, word: "a" }, { index: 3, word: "b" }, { index: 7, word: "c" }];

    walletOther = (m) => (m.type === "checkWords" ? { error: "Those words do not match your recovery phrase." } : {});
    expect((await call({ type: "confirmBackup", password: PW, answers }, ext)).error).toMatch(/do not match/);
    expect(state().backupPending).toBe(true);
    expect(walletCalls.some((m) => m.type === "connect")).toBe(false);

    walletOther = () => ({});
    expect((await call({ type: "confirmBackup", password: PW, answers }, ext)).error).toBeUndefined();
    expect(state().backupPending).toBe(false);
    expect(walletCalls.some((m) => m.type === "connect")).toBe(true);
    expect(walletCalls.find((m) => m.type === "checkWords")).toMatchObject({ answers, password: PW });
  });

  it("confirming and revealing are only for the popup, and revealing needs a wallet", async () => {
    expect((await call({ type: "confirmBackup", password: PW, answers: [] }, pageSender("https://evil.example"))).error).toMatch(/only available/);
    expect((await call({ type: "revealPhrase", password: PW }, pageSender("https://evil.example"))).error).toMatch(/only available/);
    expect((await call({ type: "revealPhrase", password: PW }, ext)).error).toMatch(/No wallet/);
    expect((await call({ type: "confirmBackup", password: PW, answers: [] }, ext)).error).toMatch(/nothing to confirm/);
  });

  it("the phrase is decrypted in the wallet host, never in the service worker", async () => {
    await call({ type: "createWallet", password: PW }, ext);
    walletOther = (m) => (m.type === "reveal" ? { mnemonic: "one two three" } : {});
    const r = await call({ type: "revealPhrase", password: PW }, ext);
    expect(r.mnemonic).toBe("one two three");
    expect(walletCalls.find((m) => m.type === "reveal")).toMatchObject({ password: PW });
  });

  it("restoring from known words needs no quiz", async () => {
    const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    expect((await call({ type: "restoreWallet", mnemonic: words, password: PW }, ext)).error).toBeUndefined();
    expect(state().backupPending).toBeFalsy();
    expect(walletCalls.some((m) => m.type === "connect")).toBe(true);
  });
});

describe("will this page be paid without asking? (the Paying… notice)", () => {
  const check = (invoice: string, origin = "https://a.example") => call({ type: "autoPayCheck", invoice }, pageSender(origin));

  it("says yes for a page that fits, no for one that needs a confirmation, and pays nothing", async () => {
    expect(await check(small())).toEqual({ willPay: true, amountSats: 5 });
    expect(await check(big())).toEqual({ willPay: false });
    expect(await check("junk")).toEqual({ willPay: false });
    expect(sends).toHaveLength(0);
    expect(state().reservations ?? []).toHaveLength(0);
    expect(state().spend?.globalSats ?? 0).toBe(0);
  });

  it("says no while the wallet is locked", async () => {
    hostUnlocked = false;
    expect(await check(small())).toEqual({ willPay: false });
  });
});

describe("sending from the popup", () => {
  it("tells how much was sent and the fee, gives the wallet the fee cap, and keeps no preimage", async () => {
    walletSend = async () => OK(3);
    const r = await call({ type: "send", destination: big() }, ext);
    expect(r.detail).toBe("Sent 250 sats (fee 3).");
    expect(sends[0].maxFeeSats).toBe(maxFeeSatsFor(250));
    expect(state().history?.at(-1)).toMatchObject({ result: "sent", priceSats: 250, feeSats: 3, amountSats: 253, detail: "Sent." });
  });

  it("a Lightning address is turned into an invoice for the typed amount, then paid with the fee cap", async () => {
    const inv = encodeBolt11ForTest("lnbc210n"); // 21 sats
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      calls.push(String(url));
      const body = String(url).includes("/.well-known/")
        ? { tag: "payRequest", callback: "https://example.com/cb", minSendable: 1000, maxSendable: 1_000_000 }
        : { pr: inv };
      return new Response(JSON.stringify(body));
    });
    try {
      walletSend = async () => OK(1);
      const r = await call({ type: "send", destination: "₿bob@example.com", amountSats: 21 }, ext);
      expect(r.detail).toBe("Sent 21 sats (fee 1).");
      expect(calls).toEqual(["https://example.com/.well-known/lnurlp/bob", "https://example.com/cb?amount=21000"]);
      expect(sends[0]).toMatchObject({ destination: inv, maxFeeSats: maxFeeSatsFor(21) });
      expect(state().history?.at(-1)).toMatchObject({ result: "sent", priceSats: 21, feeSats: 1 });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("an invoice for another amount is never paid, and a BOLT12-only address gets a clear message", async () => {
    vi.stubGlobal("fetch", async (url: string) =>
      String(url).includes("/.well-known/")
        ? new Response(JSON.stringify({ tag: "payRequest", callback: "https://example.com/cb", minSendable: 1000, maxSendable: 1_000_000 }))
        : new Response(JSON.stringify({ pr: encodeBolt11ForTest("lnbc2100n") })),
    );
    try {
      expect((await call({ type: "send", destination: "bob@example.com", amountSats: 21 }, ext)).error).toMatch(/different amount/);
      expect(sends).toHaveLength(0);
      vi.stubGlobal("fetch", async () => {
        throw new TypeError("Failed to fetch");
      });
      expect((await call({ type: "send", destination: "chromescar71@phoenixwallet.me", amountSats: 21 }, ext)).error).toBe(
        "This address type isn't supported yet. Paste an invoice instead.",
      );
      expect(sends).toHaveLength(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("toolbar badge after a page is paid", () => {
  const url = "https://a.example/premium/a";
  const sender = (href = url, tab = 1) => ({
    origin: "https://a.example",
    url: href,
    tab: { id: tab, url: href },
  });
  const report = (amount: number | null, href = url, tab = 1) =>
    call({ type: "pagePrice", amountSats: amount }, sender(href, tab));
  const payHere = () =>
    call({ type: "webln", method: "sendPayment", origin: "https://a.example", invoice: encodeBolt11ForTest("lnbc20n") }, sender());

  it("shows the muted price on the 402 page, then keeps a teal paid badge after the unlock reload", async () => {
    await report(2);
    expect(badges[1]).toMatchObject({ text: "2", color: "#44403c" });

    expect((await payHere()).error).toBeUndefined();
    expect(badges[1]).toMatchObject({ text: "2", color: "#0f766e", title: expect.stringMatching(/^Paid 2 sats/) });

    // The page reloads on the same URL; the content script reports no invoice
    // (and Chrome has cleared the tab badge). Write the paid badge again.
    badges[1] = {}; // as Chrome does on navigation
    await report(null);
    expect(badges[1]).toMatchObject({ text: "2", color: "#0f766e" });
  });

  it("clears the badge when the tab leaves that URL", async () => {
    await report(2);
    await payHere();
    await report(null);
    expect(badges[1].text).toBe("2");

    await report(null, "https://a.example/blog");
    expect(badges[1]).toMatchObject({ text: "", title: "Spikes402 Wallet" });
  });

  it("clears the badge when the tab navigates to another URL (tabs.onUpdated)", async () => {
    await report(2);
    await payHere();
    expect(tabUpdated).toBeDefined();
    tabUpdated!(1, { url: "https://a.example/blog" });
    await tick();
    expect(badges[1]).toMatchObject({ text: "", title: "Spikes402 Wallet" });
  });

  it("does not clear the badge on a same-URL reload event", async () => {
    await report(2);
    await payHere();
    tabUpdated!(1, { url });
    await tick();
    expect(badges[1]).toMatchObject({ text: "2", color: "#0f766e" });
  });

  it("flashes the yellow toolbar icon when the payment succeeds", async () => {
    vi.useFakeTimers();
    try {
      const pending = payHere();
      await vi.advanceTimersByTimeAsync(20);
      await pending;
      await vi.advanceTimersByTimeAsync(0);
      expect(icons.some((i) => i.path["16"] === "icons/icon-flash-16.png")).toBe(true);
      await vi.advanceTimersByTimeAsync(1500);
      expect(icons.at(-1)?.path["16"]).toBe("icons/icon-16.png");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("trusted sites", () => {
  const enable = (origin: string, tab = 1) => call({ type: "webln", method: "enable", origin }, pageSender(origin, tab));
  const answerTrust = (id: string, choice: "once" | "always" | "refuse", dailySats?: number) =>
    call({ type: "confirmPayment", id, choice, dailySats }, ext);
  const sites = () => (state().settings as unknown as { sites: Record<string, { trusted: boolean; dailySats: number }> }).sites ?? {};

  beforeEach(async () => {
    store["spikes402"] = {}; // no site is trusted yet
    await boot();
  });

  it("asks the first time a site calls enable, and only then enables it", async () => {
    let settled = false;
    const p = enable("https://shop.example.org").then((r) => ((settled = true), r));
    await tick();
    expect(settled).toBe(false);
    const prompt = state().prompts?.[0];
    expect(prompt).toMatchObject({ kind: "trust", site: "example.org", origin: "https://shop.example.org" });
    expect(prompt?.reason).toMatch(/Allow automatic payments on example\.org, up to 100 sats a day\?/);

    expect((await answerTrust(prompt!.id, "always", 25)).error).toBeUndefined();
    expect(await p).toEqual({ enabled: true });
    expect(sites()["example.org"]).toMatchObject({ trusted: true, dailySats: 25 });

    // Asked once: another subdomain of the same site is already trusted.
    expect(await enable("https://pay.example.org", 2)).toEqual({ enabled: true });
    expect(state().prompts ?? []).toHaveLength(0);
  });

  it("rejects, and remembers, a site the user turns down", async () => {
    const p = enable("https://bad.example");
    await tick();
    await answerTrust(state().prompts![0].id, "refuse");
    expect((await p).error).toMatch(/not allowed/);
    expect(sites()["bad.example"]).toMatchObject({ trusted: false });

    // No new question, no payment, nothing sent to the wallet.
    expect((await enable("https://bad.example")).error).toMatch(/not allowed/);
    expect((await pay("https://bad.example", small())).error).toMatch(/not allowed/);
    expect(state().prompts ?? []).toHaveLength(0);
    expect(sends).toHaveLength(0);
  });

  it("asks on a first sendPayment too, and pays only after approval", async () => {
    const p = pay("https://new.example", small());
    await tick();
    expect(sends).toHaveLength(0);
    await answerTrust(state().prompts![0].id, "always");
    expect((await p).error).toBeUndefined();
    expect(sends).toHaveLength(1);
  });

  it("behaves the same whether or not the wallet is unlocked (no lock-state leak)", async () => {
    hostUnlocked = false;
    const p = enable("https://probe.example");
    await tick();
    expect(state().prompts?.[0]).toMatchObject({ kind: "trust" }); // asked, not "wallet is locked"
    await answerTrust(state().prompts![0].id, "refuse");
    expect((await p).error).not.toMatch(/locked/);
  });

  it("one question per site, however many calls arrive", async () => {
    const calls = [enable("https://spam.example", 1), enable("https://www.spam.example", 2), pay("https://x.spam.example", small(), 3)];
    await tick();
    expect(state().prompts).toHaveLength(1);
    await answerTrust(state().prompts![0].id, "refuse");
    for (const r of await Promise.all(calls)) expect(r.error).toMatch(/not allowed/);
  });

  it("a trust question needs allow or refuse, and a sane limit", async () => {
    void enable("https://odd.example");
    await tick();
    const id = state().prompts![0].id;
    expect((await answerTrust(id, "once")).error).toBeTruthy();
    expect((await answerTrust(id, "always", 0)).error).toBeTruthy();
    expect(state().prompts).toHaveLength(1); // still waiting
    expect(sites()["odd.example"]).toBeUndefined();
    await answerTrust(id, "refuse");
  });

  it("does not answer when nobody answers, and stores nothing", async () => {
    vi.useFakeTimers();
    const p = enable("https://silent.example");
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 10);
    expect((await p).error).toMatch(/not allowed/);
    expect(sites()["silent.example"]).toBeUndefined();
  });

  it("only https pages (and http://localhost for development) may use the wallet", async () => {
    for (const o of ["http://example.com", "http://192.168.0.2", "http://localhost.evil.com"]) {
      expect((await enable(o)).error).toMatch(/only works on https/);
    }
    expect(state().prompts ?? []).toHaveLength(0);
    const p = enable("http://localhost:3000");
    await tick();
    expect(state().prompts?.[0]).toMatchObject({ kind: "trust", site: "localhost:3000" });
    await answerTrust(state().prompts![0].id, "always");
    expect(await p).toEqual({ enabled: true });
  });

  it("subdomains share one daily cap: minting subdomains does not buy more", async () => {
    store["spikes402"] = { settings: { sites: { "evil.example": { trusted: true, dailySats: 100, since: "2026-11-01T00:00:00.000Z" } } } };
    await boot();
    for (let i = 0; i < 10; i++) expect((await pay(`https://sub${i}.evil.example`, small(), 1 + i)).error).toBeUndefined();
    expect(sends).toHaveLength(10); // 10 x (5 + fee cap 5) = the 100 sat cap
    void pay("https://sub10.evil.example", small(), 20);
    await tick();
    expect(sends).toHaveLength(10); // the 11th is asked about, not paid
    expect(state().prompts?.[0]).toMatchObject({ origin: "https://sub10.evil.example" });
    expect(state().spend?.perSite).toEqual({ "evil.example": 100 });
  });

  it("revoking a site makes it ask again; a page cannot do it", async () => {
    store["spikes402"] = { settings: { sites: { "a.example": { trusted: true, dailySats: 100, since: "2026-11-01T00:00:00.000Z" } } } };
    await boot();
    expect((await call({ type: "forgetSite", site: "a.example" }, pageSender("https://a.example"))).error).toBeTruthy();
    expect(sites()["a.example"]).toBeDefined();
    expect((await call({ type: "forgetSite", site: "a.example" }, ext)).error).toBeUndefined();
    expect(sites()["a.example"]).toBeUndefined();
    void enable("https://a.example");
    await tick();
    expect(state().prompts?.[0]).toMatchObject({ kind: "trust", site: "a.example" });
    await answerTrust(state().prompts![0].id, "refuse");
  });

  it("a page is never covered by the Paying notice unless its site is trusted", async () => {
    const check = (origin: string) => call({ type: "autoPayCheck", invoice: small() }, pageSender(origin));
    expect(await check("https://unknown.example")).toEqual({ willPay: false });
    store["spikes402"] = { settings: { sites: { "ok.example": { trusted: true, dailySats: 100, since: "2026-11-01T00:00:00.000Z" } } } };
    expect(await check("https://ok.example")).toMatchObject({ willPay: true });
    expect(await check("http://ok.example")).toEqual({ willPay: false });
  });
});
