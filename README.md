# TOTP Generator

A tiny web app that turns a Base32 2FA secret into a live six-digit code, and can hand out a
temporary link so someone else can see that code **without ever receiving the secret itself**.

It runs as a static page plus one small dependency-free Node service. No accounts, no database,
no third-party scripts, no analytics.

- Live instance: <https://ezlife.space/totp-gen/>
- Requirements: a modern browser for the page, Node.js 18+ for the server (Node 22 is what
  the production host runs).

## What it does

**1. Generate a code locally.** Type a Base32 secret (the string your authenticator app or
service gives you) and the page shows the current 6-digit code with a countdown bar. The code
is computed **entirely in the browser** using the Web Crypto API (`crypto.subtle`) — the secret
is never sent anywhere and nothing is stored. This works offline once the page has loaded.

**2. Share the code, not the secret.** Optionally, click *Generate share link* to mint a
temporary URL. Whoever opens that link sees the same rotating code, generated server-side, and
they never see the Base32 secret. Each link:

- expires after 48 hours (configurable),
- can be revoked at any time by its creator,
- is backed by a random bearer token, not by the secret.

The link is shown **once** at creation time; the browser keeps only the pieces needed to revoke
it (`localStorage`), not the URL.

## Why it was made

Sharing 2FA access normally means one of two bad options: hand over the underlying secret
(which grants permanent, silent access and can't be rotated by the recipient) or read out a
six-digit code that expires in under a minute.

This tool exists to make the middle ground easy and safe: a **time-boxed, revocable view of the
current code**. You can give a colleague or a trusted person access for a couple of days, watch
it expire, and revoke it early if needed — all without disclosing the secret that would let them
mint codes forever. The secret stays under your control, and the recipient only ever holds a
short-lived token.

It is deliberately boring: minimal surface area, standard primitives (RFC 4226 HOTP / RFC 6238
TOTP), and a client-first design so the common case (just check my code) never touches a server.

## How it works

### Local mode (no account, no network)

1. The input is normalized (spaces/dashes removed, uppercased, `=` padding stripped) and
   validated as Base32 (`A–Z`, `2–7`).
2. `app.js` decodes the secret to bytes and computes the TOTP in-browser: HMAC-SHA-1 over an
   8-byte big-endian time counter, dynamic truncation, mod 10^6.
3. A `requestAnimationFrame` loop redraws the countdown and recomputes at each period boundary
   (default 60 seconds).

Secrets shorter than 8 Base32 characters are rejected. Because it uses `crypto.subtle`, the page
only functions in a secure context (HTTPS or `localhost`).

### Shared mode (share links)

The creator POSTs the secret to the API, which stores it **encrypted at rest** and returns a
one-time-visible URL of the form `…/totp-gen/#t=<token>`. The recipient's browser picks the
token out of the URL fragment (stripping it from the address bar), exchanges it for a short-lived
signed session, and then polls for the current code. The secret is decrypted only inside the
service, held in memory for the moment of generation, and never returned to any client.

## Architecture

```
public/            Static front end (served directly by nginx)
  index.html       Markup: input, code output, countdown, share controls
  app.js           Base32 decode, Web Crypto TOTP, share/session/code logic
  styles.css       The whole look (small, monospace, dark)
  favicon.svg

server/            Node HTTP service (no framework, no dependencies)
  server.js        Routing, config, rate limiting, session signing, JSON I/O
  totp.js          Base32, HOTP/TOTP generation, parameter validation
  store.js         JSON-file persistence, AES-256-GCM secret encryption

deploy/
  totp-gen.service systemd unit (hardened, runs as the `totpgen` user)

.env.example       All configuration knobs with defaults
```

The front end and API are isolated: nginx serves `public/` as static files and proxies
`/totp-gen/api/` to the Node service on `127.0.0.1:8110`.

## API

Base path (as deployed): `https://ezlife.space/totp-gen/api/`. Bodies are JSON, capped at 4 KB.
All responses are `Cache-Control: no-store`.

| Method & path | Purpose | Auth |
| --- | --- | --- |
| `GET /healthz` | Liveness probe → `{"ok":true}` | none |
| `POST /links` | Create a share link from `{secret, period?, digits?, algorithm?}` → `{id, url, expiresAt, revokeToken}` | none |
| `POST /session` | Exchange `{token}` for a signed `session` and the current code | link token |
| `GET /code` | Fetch the current code for an existing session | `Bearer <session>` |
| `POST /links/:id/revoke` | Revoke a link permanently | `Bearer <revokeToken>` |

Parameters default to `period: 60`, `digits: 6`, `algorithm: SHA-1`. `period` may be 15–300
seconds, `digits` is 6 or 8, and `algorithm` is one of `SHA-1`, `SHA-256`, `SHA-512`.

Errors are plain JSON (`{"error": "…"}`); expired or revoked links return `410` with a `reason`,
unknown tokens return `404`, and rate-limited calls return `429` with `Retry-After`.

## Running locally

The page alone needs no build step — serve `public/` over HTTP and open it:

```sh
cd public && python3 -m http.server 8000   # then visit http://localhost:8000
```

To exercise the share links, run the API too:

```sh
cp .env.example .env
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"  # TOTP_ENC_KEY
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"  # SESSION_SECRET
# fill those two into .env, then:
set -a && . ./.env && set +a
node server/server.js
```

## Configuration

All settings come from the environment (see `.env.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOST` / `PORT` | `127.0.0.1` / `8110` | Bind address (kept on loopback; nginx fronts it) |
| `BASE_URL` | `https://ezlife.space/totp-gen` | Prefix used to build share URLs |
| `TOTP_ENC_KEY` | — | **Required.** 32 bytes, base64. Encrypts secrets at rest (AES-256-GCM) |
| `SESSION_SECRET` | — | **Required.** ≥32 bytes, base64. Signs session tokens (HMAC-SHA-256) |
| `DATA_FILE` | `/var/lib/totp-gen/links.json` | Persistence file (written `0600`) |
| `LINK_TTL_MS` | `172800000` (48 h) | Share-link lifetime |
| `RETENTION_DAYS` | `7` | How long expired/revoked records are kept before sweeping |
| `SESSION_TTL_MS` | `1800000` (30 min) | Session token lifetime (also capped by link expiry) |
| `MAX_LINKS` | `5000` | Cap on concurrently active links |

The service refuses to start unless `TOTP_ENC_KEY` is exactly 32 bytes and `SESSION_SECRET` is
at least 32 bytes of base64.

## Security notes

- **Encryption at rest.** Secrets are stored with AES-256-GCM under a random IV; the file holds
  ciphertext, never plaintext. The key lives only in the environment file (`chmod 600`).
- **Tokens are hashed.** Both the share token and the revoke token are stored only as SHA-256
  hashes and compared in constant time.
- **Signed, expiring sessions.** Session tokens are HMAC-signed and carry an expiry; the API
  verifies signature and expiry before serving a code.
- **Rate limiting** per client IP: 10 link creations/hour, 30 session exchanges per 5 min,
  120 code fetches/min, 10 revokes/hour.
- **Honest boundary.** Creating a share link *does* send the secret to the server (that's how
  the code gets generated for the recipient). If you never create a link, the secret never
  leaves your browser. Logs redact anything that looks like a token or key.
- **Hardened deployment.** The systemd unit runs as an unprivileged user with a strict
  filesystem/device sandbox and an empty capability set.

## Deployment

`deploy/totp-gen.service` is the systemd unit used in production (working directory
`/totp-gen/server`, env file `/etc/totp-gen/api.env`). A typical deploy is: pull the repo on the
host, install the unit if needed, and restart the service.

```sh
systemctl restart totp-gen
systemctl status totp-gen
curl -s https://ezlife.space/totp-gen/api/healthz   # {"ok":true}
```

The app persists to `DATA_FILE`, so restarts and reloads keep existing share links; a corrupt
data file is quarantined rather than crashed on.
