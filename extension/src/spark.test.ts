import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encodeBolt11ForTest } from "./invoice";
import { PaymentPendingError } from "./backend";
import { maxFeeSatsFor } from "./spark-util";

const wallet = {
  payLightningInvoice: vi.fn(),
  getLightningSendRequest: vi.fn(),
  cleanup: vi.fn(async () => undefined),
};
vi.mock("@buildonspark/spark-sdk", () => ({
  SparkWallet: { initialize: async () => ({ wallet }) },
}));

const invoice = encodeBolt11ForTest("lnbc2500n"); // 250 sats

beforeEach(async () => {
  wallet.payLightningInvoice.mockReset().mockResolvedValue({ id: "req-1" });
  wallet.getLightningSendRequest.mockReset().mockResolvedValue({ status: "LIGHTNING_PAYMENT_INITIATED" });
  const { sparkBackend } = await import("./spark");
  await sparkBackend.connect({ mnemonic: "x", network: "regtest" });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("spark backend send", () => {
  it("passes the fee cap it was given, or the shared rule from the invoice amount", async () => {
    vi.useFakeTimers();
    const { sparkBackend } = await import("./spark");
    const run = (opts?: { maxFeeSats?: number }) => {
      const p = sparkBackend.send(invoice, undefined, opts).catch((e: unknown) => e);
      return vi.advanceTimersByTimeAsync(61_000).then(() => p);
    };
    await run({ maxFeeSats: 25 });
    expect(wallet.payLightningInvoice.mock.calls[0][0].maxFeeSats).toBe(25);
    await run();
    expect(wallet.payLightningInvoice.mock.calls[1][0].maxFeeSats).toBe(maxFeeSatsFor(250));
  });

  it("reports a timeout as pending, with the request id, not as a plain failure", async () => {
    vi.useFakeTimers();
    const { sparkBackend } = await import("./spark");
    const p = sparkBackend.send(invoice, undefined, { maxFeeSats: 25 }).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(61_000);
    const err = await p;
    expect(err).toBeInstanceOf(PaymentPendingError);
    expect((err as PaymentPendingError).requestId).toBe("req-1");
  });

  it("a payment the SSP reports as failed is a plain failure", async () => {
    wallet.getLightningSendRequest.mockResolvedValue({ status: "LIGHTNING_PAYMENT_FAILED" });
    const { sparkBackend } = await import("./spark");
    const err = await sparkBackend.send(invoice, undefined, { maxFeeSats: 25 }).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(PaymentPendingError);
    expect((err as Error).message).toMatch(/failed/);
  });

  it("keeps a request pending when its status check is interrupted", async () => {
    wallet.getLightningSendRequest.mockRejectedValueOnce(new Error("connection reset"));
    const { sparkBackend } = await import("./spark");
    await expect(sparkBackend.send(invoice)).rejects.toMatchObject({
      name: "PaymentPendingError",
      requestId: "req-1",
    });
  });

  it("keeps an interrupted send pending even without a request id", async () => {
    wallet.payLightningInvoice.mockRejectedValueOnce(new Error("connection reset"));
    const { sparkBackend } = await import("./spark");
    await expect(sparkBackend.send(invoice)).rejects.toBeInstanceOf(PaymentPendingError);
  });
});

describe("spark backend send speed", () => {
  it("looks for the preimage every quarter second at first, so a quick payment is not held back", async () => {
    vi.useFakeTimers();
    wallet.getLightningSendRequest
      .mockReset()
      .mockResolvedValueOnce({ status: "LIGHTNING_PAYMENT_INITIATED" })
      .mockResolvedValueOnce({ status: "LIGHTNING_PAYMENT_INITIATED" })
      .mockResolvedValue({ status: "LIGHTNING_PAYMENT_SUCCEEDED", paymentPreimage: "00".repeat(32) });
    const { sparkBackend } = await import("./spark");
    let settled = false;
    const p = sparkBackend.send(invoice, undefined, { maxFeeSats: 25 }).catch(() => undefined).then(() => (settled = true));
    await vi.advanceTimersByTimeAsync(600); // two polls at 250 ms, the third finds it
    expect(wallet.getLightningSendRequest).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(1);
    await p;
    expect(settled).toBe(true);
  });
});

describe("spark backend lookupSend", () => {
  it("tells settled, failed and pending apart", async () => {
    const { sparkBackend } = await import("./spark");
    expect(await sparkBackend.lookupSend("req-1", invoice)).toEqual({ state: "pending" });
    wallet.getLightningSendRequest.mockResolvedValue({ status: "PENDING_USER_SWAP_RETURN" });
    expect(await sparkBackend.lookupSend("req-1", invoice)).toEqual({ state: "pending" });
    wallet.getLightningSendRequest.mockResolvedValue({ status: "TRANSFER_FAILED" });
    expect(await sparkBackend.lookupSend("req-1", invoice)).toEqual({ state: "failed" });
  });
});
