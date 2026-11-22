# Five-minute quickstart

Put Spikes402 in front of a website. On the paths you choose, a visitor
must solve a short proof-of-work puzzle. No Lightning node is needed for
this path.

This example is for a **Linux VPS** (or any Linux host) with Docker. It
uses the published image `ghcr.io/choffolo/spikes402:v0.2.0`, listens only
on localhost, and offers proof-of-work only.

The ready-to-copy files live in [`examples/quickstart/`](../examples/quickstart/).
For every config key, see the [README](../README.md). For phoenixd, TLS
details and backups, see [Deploying Spikes402](deploy.md).

## 1. Prerequisites

- Linux, with [Docker](https://docs.docker.com/engine/install/) and Compose
  v2 (`docker compose version`)
- A website already running, or the tiny site bundled in the example folder
- `openssl`, to make a secret

You do not need a Lightning node, a domain, or TLS yet. **Do not publish
port 8402 on a public address.**

## 2. Copy the files

```sh
git clone https://github.com/Choffolo/spikes402
cd spikes402/examples/quickstart
printf 'SPIKES402_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > .env
```

Keep `.env` on the machine. Do not commit it, and do not put secrets in
`config.json`.

## 3. Set the upstream and the protected paths

If you are trying the bundled site, you can skip this step. The example
already protects `/premium/**` and points at `http://127.0.0.1:8080`.

Otherwise edit `config.json`:

- `origin`: your website, as the proxy will reach it (for example
  `http://127.0.0.1:8080` if it already listens on this machine)
- `protect`: the paths that should require work, for example
  `["/premium/**"]`. Everything else stays open.

Leave `lightning.backend` as `fake` and `bot_policies` as `pow-only` until
you enable Lightning below. The fake backend lets you skip a Lightning
node; it is only acceptable because the proxy listens on localhost and
these policies issue no invoices. **Do not change policies to `pay` until
you have switched to your own phoenixd.**

## 4. Start it

```sh
docker compose up -d
```

The proxy uses Docker's host network so "listen on localhost" is the
host's localhost, which the fake backend requires. After it starts:

- proxy: `http://127.0.0.1:8402`
- bundled origin: `http://127.0.0.1:8080`
- admin dashboard (loopback only): `http://127.0.0.1:8404`

To use the dashboard, also set `SPIKES402_ADMIN_KEY` in `.env` to a
different 32+ character secret.

## 5. Check that it works

```sh
curl -i http://127.0.0.1:8402/premium/
```

You should see `402 Payment Required`. Opening that URL in a browser
shows the 402 page; you can solve the puzzle there. `http://127.0.0.1:8402/`
should stay free.

Optional, from the repository root after `go build -o bin/ ./cmd/...`:

```sh
bin/spikes-bot -mode pow http://127.0.0.1:8402/premium/
```

You should see `200 OK` and the premium page.

### Put TLS in front

Before you point a public domain at this, put a TLS reverse proxy on the
same host. A starter `Caddyfile` is in the example folder:

```
example.com {
    reverse_proxy 127.0.0.1:8402
}
```

When Caddy (or nginx) is in front, add these keys to `config.json` and
recreate the proxy (`docker compose up -d`):

```json
"client_ip_header": "X-Forwarded-For",
"trusted_proxies": ["127.0.0.1/32"]
```

Never set `trusted_proxies` to the whole internet.

## Optional: enable Lightning with your own phoenixd

Payments must go to **your** node. Spikes402 is not a wallet, never holds
your keys or funds, and should not be pointed at a hosted wallet run by
someone else.

1. Run [phoenixd](https://github.com/ACINQ/phoenixd) yourself. The official
   image and a full Compose file are in [Deploying Spikes402](deploy.md).
   Do not publish phoenixd's HTTP port on the host; keep it on an internal
   network, or on `127.0.0.1` only.
2. Back up `seed.dat` and keep the copy offline. If you lose it, you lose
   the funds.
3. Put phoenixd's *limited-access* password in `.env` as `PHOENIXD_PASSWORD`
   (it can create invoices, not spend). Leave `withdraw.enabled` false.
   Prefer phoenixd's own tools if you later need to spend.
4. Switch the backend and allow invoices. If the proxy stays on the host
   network and phoenixd is reachable at `127.0.0.1:9740`:

   ```json
   "lightning": {
     "backend": "phoenixd",
     "phoenixd_url": "http://127.0.0.1:9740"
   },
   "bot_policies": {}
   ```

   Then `docker compose up -d`. If phoenixd lives only on a Compose
   network, follow [deploy.md](deploy.md) instead (the fake-backend
   localhost rule no longer applies, so the proxy can join that network).

Invoice rate limits stay on by default: 30 challenges per client per
minute, 300 invoices per minute, at most 10,000 pending invoices. Leave
them in place so the node cannot be flooded with invoice requests.
