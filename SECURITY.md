# Security

## Reporting a vulnerability

Please do not report security problems in public issues.

- Preferred: GitHub private vulnerability reporting, under the repository's
  **Security** tab → **Report a vulnerability**.
- If that button is not available, open an issue titled "Security contact"
  **without any details**, and we will reply with a private channel.

Include the version or commit, your configuration (without secrets) and the
steps to reproduce. Please give us a
reasonable time to release a fix before publishing.

Only the latest commit on `main` gets security fixes.

## Running it safely

- Put Spikes402 behind your own TLS reverse proxy, list only that proxy in
  `trusted_proxies` (client-IP and `X-Forwarded-*` headers are believed only
  from those addresses), and keep the admin dashboard on `127.0.0.1`.
- Keep withdrawals off. While they are on, the internet-facing process holds
  phoenixd's full-access password, which can spend all funds; a bug there
  could empty the node. Withdraw with phoenixd's own tools instead, or turn
  withdrawals on only for the time you need them.
- Keep the node's balance low; move earnings out regularly.
- Keep `ai_can_apply` off (see below).
- Give `state_dir` to the process only (directory mode 0700, files 0600).
  Records are HMAC-sealed with `secret_key`; no secrets are written to
  the files. In Docker, mount `state_dir` as a writable volume. If the
  spent-token store is missing or cannot be verified, the process
  refuses to start. If a withdrawal intent is unverified, withdrawals
  stay blocked until you check the node and resolve it.


## Browser wallet

The Manifest V3 extension in `extension/` is a **prototype**. Use only tiny
amounts on mainnet. See [Try the wallet](docs/try-the-wallet.md).

- The 12-word recovery phrase is created or restored locally and stored
  encrypted (PBKDF2-SHA-256, 600,000 iterations, AES-256-GCM). Unlock
  decrypts it only in the wallet host, not in the service worker. The host
  locks after 15 minutes of inactivity.
- Spark's trust model is not a self-custodial Lightning node. The wallet
  talks to three signing operators (threshold 2-of-3): Lightspark, Breez,
  and Flashnet. Lightning send and receive go through Lightspark as the
  default Lightning service provider (LSP). There is no published
  third-party code audit of this protocol or of the Spark SDK we use.
- Spark allows a unilateral on-chain exit; that button is **not** in the
  extension yet. Recovering funds that way today needs the phrase and an
  external tool (`sparkcli`).
- A site can use the wallet only after you allow it: the first request
  from a site asks you ("Allow automatic payments on <site>, up to N sats a
  day?"), and you can remove sites again in the popup. Sites are told apart
  by registrable domain (eTLD+1), so subdomains share one entry and one
  limit. Only https pages (and `http://localhost` / `127.0.0.1` for
  development) are served.
- While the wallet is unlocked, a page of an allowed site can be paid
  automatically if it fits the caps (default: 10 sats per page, 100 per
  site per day, 500 per day, fees included). Over a cap, the popup asks for
  confirmation.
- Keys never leave this machine; there is no Spikes402 server for the
  wallet. Report extension bugs the same way as above.

## Known limitations

These are known and not fixed yet. Contributions are welcome.

- **Rate limiter overflow.** Clients are tracked individually up to 100,000
  addresses a minute; beyond that, new clients share one bucket and get
  `429`. An attacker with that many addresses (easy with IPv6) can lock out
  new visitors for a while. The Lightning node stays protected.
- **Reverse DNS saturation.** The crawler classifier limits concurrent DNS
  lookups. When those slots are full, requests that need a new lookup are
  classified as unknown and follow the configured unknown-client policy.
- **AI admin with `ai_can_apply`.** When enabled, the AI admin can apply
  changes that make protection stricter or equal (for example a higher
  price). It cannot apply a change that would reduce protection (making
  pages free, lowering prices, easier proof-of-work, narrowing `protect`)
  or one that could take the site down (a whole-site `protect` pattern,
  blocking or charging verified crawlers, a big price jump or a sharp
  rate-limit cut from the last settings a person applied), toggle pause, withdraw, or approve proposals. Those stay suggestions
  for the human admin. It still reads text chosen by visitors (paths, bot
  host names), which could carry prompt injection. Leave `ai_can_apply`
  off, or review its proposals.
- **Key-directory fetches (Web Bot Auth).** The fetcher only connects over
  https, on port 443, to public addresses, but a few rarely used special
  ranges (for example NAT64 `64:ff9b::/96`, 6to4, Teredo, `198.18.0.0/15`,
  `240.0.0.0/4`) are not blocked yet. The fetch budget is global, so anyone
  can use it up and delay the discovery of a new, legitimate bot directory
  (that bot then just pays like everyone else).
- **Spent-token store full.** Up to 1,000,000 unexpired tokens are
  remembered to stop replays. If an attacker fills it (it takes a large,
  sustained number of valid redemptions from many addresses), new
  redemptions, including paid ones, get "server busy" until entries expire.
- **Argon2id memory.** Concurrent checks share `argon2_max_memory_mib`
  (default 256 MiB). With the default 16 MiB per check, that is 16 at once;
  with 256 MiB per check, one. A setting where one check needs more than
  the budget is refused.


## Software bill of materials and VEX

A CycloneDX SBOM of the Go module, the browser extension's npm dependencies
(including devDependencies), and the runtime Docker image is generated on
every push and pull request by the `sbom` workflow and attached as the
`spikes402-sbom` artifact (`spikes402-source.cdx.json` and
`spikes402-image.cdx.json`). There is no separate release workflow; when a
GitHub Release is published, the same job attaches those files (and the VEX
document) to the release.

To generate and scan locally (linux/amd64, Docker optional for the image):

```sh
./scripts/sbom.sh
```

Known findings are recorded in
[`vex/spikes402.openvex.json`](vex/spikes402.openvex.json) (OpenVEX). The
scan fails CI only on reachable Go issues (`govulncheck`) and on scanner
findings that are not yet addressed in that file.
