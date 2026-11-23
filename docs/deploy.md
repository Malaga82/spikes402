# Deploying Spikes402

A short guide for running the proxy in Docker, with TLS in front of it.
For flags and every config key, see the [README](../README.md).

## Docker and Compose

The repository has a multi-stage `Dockerfile` (static binary, distroless
non-root runtime, no shell; linux/amd64 and linux/arm64) and an example
`docker-compose.yml`: Spikes402 plus the official
[ACINQ phoenixd](https://hub.docker.com/r/acinq/phoenixd) image, pinned by
digest.

Released images are published to the GitHub Container Registry as
`ghcr.io/choffolo/spikes402`. Tags follow the git tag (`v0.1.0` and
`0.1.0`); `latest` points at the newest stable release (not a pre-release
such as `v0.1.0-rc.1`).

```sh
docker pull ghcr.io/choffolo/spikes402:v0.1.0   # or :latest
```

To run the published image instead of building locally, in
`docker-compose.yml` set `image: ghcr.io/choffolo/spikes402:v0.1.0` on the
`spikes402` service and remove the `build: .` line. Volumes, environment
and ports stay the same.

```sh
docker run --rm -p 127.0.0.1:8402:8402 \
  -v "$PWD/config.json:/etc/spikes402/config.json:ro" \
  -v spikes402-state:/var/lib/spikes402 \
  -e SPIKES402_SECRET_KEY -e PHOENIXD_PASSWORD \
  ghcr.io/choffolo/spikes402:v0.1.0
```

The package may be private until it is set public once in the GitHub
package settings (Packages → `spikes402` → Package settings → Change
visibility → Public), or with:

```sh
gh api --method PUT /user/packages/container/spikes402/visibility -f visibility=public
```

That can only be done after the first image has been pushed (the package
does not exist before then). The repository is public, so the package
may already inherit public visibility; if a `docker pull` without a
login works, there is nothing to change.

### Verifying the image signature

Each release image is signed keylessly with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
(Sigstore, GitHub Actions identity). The signature covers the multi-arch
index. A provenance attestation and an image SBOM are also attached.

```sh
cosign verify ghcr.io/choffolo/spikes402:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/Choffolo/spikes402/.github/workflows/release.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```


1. Copy the example config and edit the `origin` (the site you are
   protecting). Leave passwords out of the file; they come from the
   environment.

   ```sh
   cp config.docker.example.json config.json
   ```

2. Create a `.env` next to `docker-compose.yml` (do not commit it):

   ```sh
   printf 'SPIKES402_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
   printf 'SPIKES402_ADMIN_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
   ```

   The two keys must be different and at least 32 characters.

3. Start **phoenixd first**, once, so it can write its data directory:

   ```sh
   docker compose up -d phoenixd
   ```

   On first start it creates `seed.dat` and `phoenix.conf` in the
   `phoenixd-data` volume. **Back up `seed.dat` now** (see [Backups](#backups)).
   Copy `http-password-limited-access` from `phoenix.conf` into `.env` as
   `PHOENIXD_PASSWORD`. That password can create invoices but cannot spend.

   ```sh
   docker compose exec phoenixd cat /phoenix/.phoenix/phoenix.conf
   ```

4. Start the proxy:

   ```sh
   docker compose up --build -d
   ```

   The public proxy listens on port 8402. The admin dashboard is published
   only on the host's loopback interface (`127.0.0.1:8404`). phoenixd's
   HTTP API is on the compose network only; it is not published.

The example `origin` is `http://host.docker.internal:8080` (a process on
the Docker host). Point it at your real site, or add that site as another
Compose service and use its service name.

The fake Lightning backend is for local development without Docker (see
the README quick start). It refuses to listen on a non-localhost address,
so it is not used in this Compose file.

The image sets `GOMEMLIMIT=256MiB`, a soft heap target for the Go runtime
(it is not a hard cap). Override it when you run the container if the host
has more or less memory, for example `GOMEMLIMIT=512MiB` in Compose
`environment`.

The proxy keeps up to 256 idle connections to your origin and waits 15
seconds for origin response headers; if the origin hangs or cannot be
reached, the client gets a short 502.

## TLS in front

Do not expose port 8402 to the internet as plain HTTP. Put a TLS reverse
proxy in front, on the same host or the same Docker network, for example
[Caddy](https://caddyserver.com/) or nginx.

A minimal Caddyfile, if Caddy runs on the host:

```
example.com {
    reverse_proxy 127.0.0.1:8402
}
```

If Caddy runs in Compose, attach it to the `spikes402` network, proxy to
`spikes402:8402`, and do not publish 8402 on the host.

When Spikes402 is behind your proxy, set `client_ip_header` (for example
`X-Forwarded-For`) and `trusted_proxies` to that proxy's addresses, so rate
limits and bot checks see the visitor, not the proxy, and so the visitor's
address is forwarded to your website. Never set `trusted_proxies` to the
whole internet. If your origin needs the public `Host` header (name-based
virtual hosts), also set `preserve_host`.

Protected-path responses are sent with `Cache-Control: private, no-store`
(including 402 pages and origin answers after payment). Unprotected paths
keep the origin's cache headers.

## Config basics

- Mount a JSON file at `/etc/spikes402/config.json` (the image default).
  The process runs as uid 65532; the file must be readable by that user.
  `config.json` is never rewritten. Dashboard changes are saved under
  `state_dir` as `config.overrides.json` (mode `0600`). The last settings
  a person applied are also kept there as `config.confirmed.json`, so the
  AI cannot ratchet past confirmation limits across restarts.
- Spent tokens, withdrawal intents, and dashboard overrides are written
  under `state_dir` (in the example, `/var/lib/spikes402`). The directory
  is mode 0700, the files 0600, and spent/intent records are HMAC-sealed
  with `secret_key` (no secrets are stored in the files). The example
  Compose file mounts a named volume `spikes402-state` there; it must
  stay writable by uid 65532, including for the overrides file. If you
  bind-mount a host directory instead, create it first and
  `chown 65532:65532` it. A missing or unreadable `state_dir` prevents
  the process from starting. A tampered or unreadable spent store also
  refuses to start (so a restart cannot “forget” spent tokens). An
  unreadable withdrawal intent starts the process but blocks withdrawals
  until you check the node and resolve the intent in the dashboard. A
  leftover `config.overrides.json` next to `config.json` is still read
  if the `state_dir` copy does not exist yet; the next dashboard save
  writes to the volume.
- Set secrets with environment variables, not in the file:
  `SPIKES402_SECRET_KEY`, `SPIKES402_ADMIN_KEY`, `PHOENIXD_PASSWORD`.
- Leave `withdraw.enabled` false unless you are actively withdrawing.
  Withdrawals need phoenixd's *full-access* password, which can spend all
  funds. Prefer phoenixd's own tools (`phoenix-cli`) for that.
- `identify_bots` (on by default) fetches the crawlers' published IP lists
  over HTTPS, so the Spikes402 container needs outbound internet.
- Optional per-path prices (first matching rule wins; other protected
  paths use `price_sats`):

  ```json
  "price_sats": 5,
  "prices": [
    {"pattern": "/articles/**", "price_sats": 5},
    {"pattern": "/premium/**", "price_sats": 20}
  ]
  ```

## Backups

The Compose volume `phoenixd-data` is the Lightning node. It contains
**`seed.dat`**: anyone with that file can spend the funds, and if you lose
it the funds are gone.

- Back up `seed.dat` (and `phoenix.conf`) as soon as phoenixd has started,
  to offline storage you control. Restrict permissions (mode 600).
- Test that you can restore the volume before you put real money on the
  node.
- The `spikes402-state` volume holds spent tokens, withdrawal intents, and dashboard overrides.
  It is not a secret, but losing it lets old tokens be spent again until
  they expire, and an interrupted withdrawal may need a manual resolve.
  Changing `secret_key` makes existing state unreadable (the process
  fails safe: it will not start with an empty spent list, and withdrawals
  stay blocked until you resolve or remove the files).
- The Spikes402 `secret_key` signs visitor tokens and seals the state
  files. If you lose it, existing tokens stop working; the Lightning
  funds are unaffected. Keep a copy of
  `.env` with the same care as other server secrets (not next to `seed.dat`
  on a public disk).

To copy `seed.dat` out of the volume (example; store the result safely and
delete leftover copies on the server):

```sh
docker compose cp phoenixd:/phoenix/.phoenix/seed.dat ./seed.dat.bak
```

## Upgrading

1. Back up `seed.dat` and your `.env` / `config.json`.
2. Pull the new image tag (or rebuild from the git tag you want):

   ```sh
   # if compose uses the published image:
   docker compose pull spikes402
   docker compose up -d
   # if you still build locally:
   git fetch --tags && git checkout v0.1.0
   docker compose up --build -d
   ```

3. Refresh image digests in the `Dockerfile` and `docker-compose.yml` if
   you bump Go, the distroless runtime, or phoenixd (only when building
   locally).
4. Check the logs: `docker compose logs -f spikes402`.

phoenixd and Spikes402 can be upgraded independently. Read the phoenixd
release notes before bumping that image; keep the volume.

## Security checklist

- [ ] phoenixd has **no** `ports:` mapping and is not otherwise reachable
      from the public internet.
- [ ] The admin port is bound to `127.0.0.1` on the host (the example
      Compose file does this). Reach it via SSH if the host is remote:
      `ssh -L 8404:127.0.0.1:8404 you@server`.
- [ ] TLS terminates in front of the proxy. `trusted_proxies` lists only
      your reverse proxy.
- [ ] Secrets are in the environment (or a secret store), not in the image
      and not in git. `.env` and `config.json` are untracked.
- [ ] `PHOENIXD_PASSWORD` is the *limited-access* password, not the full
      one. Withdrawals stay off.
- [ ] `seed.dat` is backed up offline; you have tested a restore.
- [ ] The image runs as the distroless non-root user (uid 65532). Do not
      run it as root.
- [ ] Use tiny amounts until you have paid a real invoice end-to-end and
      restored a backup.
