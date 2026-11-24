import type { Network } from "./types";

/** The wallet implementation the rest of the extension talks to. */
export type WalletBackend = {
  connect(opts: { mnemonic: string; network: Network }): Promise<void>;
  disconnect(): Promise<void>;
  getInfo(): Promise<{ balanceSats: number; pubkey: string }>;
  /** Create a BOLT11 invoice for the given amount. */
  receiveLightning(amountSats: number): Promise<{ invoice: string; feeSats: number }>;
  /**
   * Pay a BOLT11 invoice or a Spark address.
   * amountSats is required when the destination has no amount of its own.
   */
  send(
    destination: string,
    amountSats?: number,
    opts?: { maxFeeSats?: number; onRequest?: (id: string) => Promise<void> },
  ): Promise<{ preimage?: string; detail: string; feeSats?: number }>;
  /** Ask the wallet what became of a Lightning payment that did not finish in time. */
  lookupSend(requestId: string, invoice: string): Promise<{ state: "settled" | "failed" | "pending"; feeSats?: number }>;
};

export class WalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WalletError";
  }
}

/**
 * The payment may have been sent, but its outcome is unknown. Keep it counted.
 */
export class PaymentPendingError extends WalletError {
  constructor(
    message: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "PaymentPendingError";
  }
}

export { lightningHint } from "./spark-util";
