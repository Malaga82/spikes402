import { beforeEach, describe, expect, it, vi } from "vitest";

// The content script relays window.webln calls from the page to the background.
// These tests load it with just enough of a page around it.
let onMessage: ((ev: { source: unknown; origin: string; data: unknown }) => void) | undefined;
let sent: Record<string, unknown>[];

async function load(origin: string) {
  sent = [];
  onMessage = undefined;
  const win = {
    addEventListener: (type: string, l: typeof onMessage) => {
      if (type === "message") onMessage = l;
    },
    postMessage: () => undefined,
  };
  const g = globalThis as Record<string, unknown>;
  g.window = win;
  g.location = { origin };
  g.document = {
    readyState: "loading",
    addEventListener: () => undefined,
    getElementById: () => null,
    querySelector: () => null,
  };
  g.MutationObserver = class {
    observe() {}
    disconnect() {}
  };
  g.chrome = { runtime: { sendMessage: (msg: Record<string, unknown>) => sent.push(msg), lastError: undefined } };
  vi.resetModules();
  await import("./content");
  return win;
}

const ask = (win: unknown, origin: string) =>
  onMessage?.({ source: win, origin, data: { source: "spikes402-webln", id: 1, method: "enable" } });

describe("content script relay", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("relays a WebLN call from the page itself", async () => {
    const win = await load("https://pay.example");
    ask(win, "https://pay.example");
    expect(sent.filter((m) => m.type === "webln")).toHaveLength(1);
  });

  it("ignores a sandboxed document (opaque origin), even when the origins match", async () => {
    const win = await load("null");
    ask(win, "null");
    expect(sent.filter((m) => m.type === "webln")).toHaveLength(0);
  });
});
