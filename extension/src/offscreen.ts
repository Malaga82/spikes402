import { sparkBackend } from "./spark";
import { PaymentPendingError, WalletError } from "./backend";
import { decryptMnemonic, type EncryptedVault } from "./crypto";
import { quizPasses } from "./backup";
import { isExtensionPage } from "./sender";

type WalletMsg =
  | { target: "wallet"; type: "connect"; mnemonic: string; network: "regtest" | "mainnet" }
  | { target: "wallet"; type: "connect"; vault: EncryptedVault; password: string; network: "regtest" | "mainnet" }
  | { target: "wallet"; type: "reveal"; vault: EncryptedVault; password: string }
  | { target: "wallet"; type: "checkWords"; vault: EncryptedVault; password: string; answers: unknown }
  | { target: "wallet"; type: "disconnect" }
  | { target: "wallet"; type: "getInfo" }
  | { target: "wallet"; type: "receive"; amountSats: number }
  | { target: "wallet"; type: "send"; destination: string; amountSats?: number; maxFeeSats?: number; reservationId?: string }
  | { target: "wallet"; type: "lookupSend"; requestId: string; invoice: string }
  | { target: "wallet"; type: "status" };

let unlocked = false;
const AUTO_LOCK_MS = 15 * 60 * 1000;
let autoLockTimer: ReturnType<typeof setTimeout> | undefined;

chrome.runtime.onMessage.addListener((msg: WalletMsg, sender, sendResponse) => {
  if (!msg || msg.target !== "wallet") return;
  if (!isExtensionPage(sender, chrome.runtime.getURL(""))) {
    sendResponse({ error: "Wallet messages are only accepted from the extension itself." });
    return;
  }
  handle(msg)
    .then(sendResponse)
    .catch((e: unknown) =>
      sendResponse({
        error: e instanceof Error ? e.message : String(e),
        // Tells the caller the payment may still settle: keep it counted.
        ...(e instanceof PaymentPendingError ? { uncertain: true, requestId: e.requestId } : {}),
      }),
    );
  return true;
});

async function handle(msg: WalletMsg): Promise<unknown> {
  switch (msg.type) {
    case "status":
      return { unlocked };
    case "connect": {
      const mnemonic = await mnemonicFrom(msg);
      try {
        await sparkBackend.connect({ mnemonic, network: msg.network });
        unlocked = true;
        bumpAutoLock();
        return { ok: true };
      } finally {
        // Best-effort: drop our reference. JS strings are immutable, so this
        // does not erase other copies; it avoids keeping one in this closure.
        (msg as { mnemonic?: string; password?: string }).mnemonic = "";
        (msg as { password?: string }).password = "";
      }
    }
    case "reveal":
      // Decrypted here, like unlock, so the service worker never holds the phrase.
      return { mnemonic: await decryptMnemonic(msg.vault, msg.password) };
    case "checkWords": {
      const mnemonic = await decryptMnemonic(msg.vault, msg.password);
      if (!quizPasses(mnemonic, msg.answers)) throw new WalletError("Those words do not match your recovery phrase. Check your notes and try again.");
      return { ok: true };
    }
    case "disconnect":
      await sparkBackend.disconnect();
      unlocked = false;
      clearAutoLock();
      return { ok: true };
    case "getInfo":
      if (!unlocked) throw new WalletError("The wallet is locked.");
      bumpAutoLock();
      return sparkBackend.getInfo();
    case "receive":
      if (!unlocked) throw new WalletError("The wallet is locked.");
      bumpAutoLock();
      return sparkBackend.receiveLightning(msg.amountSats);
    case "send":
      if (!unlocked) throw new WalletError("The wallet is locked.");
      bumpAutoLock();
      return sparkBackend.send(msg.destination, msg.amountSats, {
        maxFeeSats: msg.maxFeeSats,
        onRequest: msg.reservationId ? async (requestId) => {
          await chrome.runtime.sendMessage({ type: "walletRequestId", id: msg.reservationId, requestId });
        } : undefined,
      });
    case "lookupSend":
      if (!unlocked) throw new WalletError("The wallet is locked.");
      return sparkBackend.lookupSend(msg.requestId, msg.invoice);
    default:
      throw new WalletError("Unknown wallet message");
  }
}

async function mnemonicFrom(msg: WalletMsg): Promise<string> {
  if (msg.type !== "connect") throw new WalletError("Not a connect message.");
  if ("vault" in msg && msg.vault && "password" in msg && typeof msg.password === "string") {
    return decryptMnemonic(msg.vault, msg.password);
  }
  if ("mnemonic" in msg && typeof msg.mnemonic === "string" && msg.mnemonic) {
    return msg.mnemonic;
  }
  throw new WalletError("Connect needs a vault and password, or a recovery phrase.");
}

function bumpAutoLock() {
  clearAutoLock();
  autoLockTimer = setTimeout(() => {
    void sparkBackend
      .disconnect()
      .catch(() => undefined)
      .finally(() => {
        unlocked = false;
      });
  }, AUTO_LOCK_MS);
}

function clearAutoLock() {
  if (autoLockTimer !== undefined) {
    clearTimeout(autoLockTimer);
    autoLockTimer = undefined;
  }
}
