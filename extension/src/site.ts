import { getDomain } from "tldts";

/**
 * Which sites may use the wallet, and how they are told apart.
 *
 * Trust and the per-site daily cap belong to a *site*: the registrable
 * domain (eTLD+1), so shop.example.com and pay.example.com share one entry
 * and one cap, and an attacker cannot mint fresh allowances with new
 * subdomains. The registrable domain comes from the Public Suffix List
 * (tldts), including its private section, so tenants of shared hosts such
 * as alice.github.io and bob.github.io stay separate sites.
 */

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * https pages only. http is allowed for local development (localhost and
 * 127.0.0.1): an http page can be rewritten by anyone on the network, so it
 * must never be able to spend.
 */
export function isAllowedOrigin(origin: string): boolean {
  try {
    const u = new URL(origin);
    return u.protocol === "https:" || (u.protocol === "http:" && LOCAL_HOSTS.has(u.hostname));
  } catch {
    return false;
  }
}

/**
 * The site an origin belongs to, or undefined if it may not use the wallet
 * at all. Local development hosts and IP addresses have no registrable
 * domain; they are keyed by host (with the port for localhost, since
 * different local apps are different sites). Anything else with no
 * registrable domain (a bare public suffix) is keyed by its exact host.
 */
export function siteKey(origin: string): string | undefined {
  if (!isAllowedOrigin(origin)) return undefined;
  const u = new URL(origin);
  if (LOCAL_HOSTS.has(u.hostname)) return u.host;
  const host = u.hostname.replace(/\.$/, "");
  const key = getDomain(host, { allowPrivateDomains: true }) ?? host;
  // Keys index plain objects (sites, allowances, spend): "constructor" or "__proto__" would hit Object.prototype.
  return key in Object.prototype ? undefined : key;
}
