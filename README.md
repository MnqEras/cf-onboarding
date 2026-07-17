# cf-onboarding

One-command Cloudflare hardening for a new client domain. Idempotent — safe to re-run.

## What it does

Default:
- **Always Use HTTPS** — 301-redirects all `http://` to `https://`
- **SSL/TLS mode** → `full` (override with `--ssl`)
- **Automatic HTTPS Rewrites** → on
- **Minimum TLS** → 1.2, **TLS 1.3** → on, **Brotli** → on
- **Bot Fight Mode** → on (best-effort; plan-gated)

Opt-in flags:
- `--hsts` — enable HSTS (only after HTTPS is confirmed working everywhere)
- `--waf` — add a Managed-Challenge WAF rule for `/wp-admin`, `/wp-login`, `/xmlrpc.php`, `/administrator`
- `--ssl full|strict|flexible|off` — set the encryption mode (default `full`)

## Setup (once)

```bash
cp .env.example .env
# edit .env and paste your Cloudflare API token (see .env.example for permissions)
chmod +x cf-onboard.sh
```

The token is read **only** from `$CF_API_TOKEN` or the git-ignored `.env`. It is never
hard-coded and never committed.

## Use (per client)

```bash
./cf-onboard.sh clientdomain.co.za
./cf-onboard.sh clientdomain.co.za --waf --hsts --ssl strict
```

The domain must already be added to your Cloudflare account (nameservers pointed). The
script only configures settings; it does not create the zone.

## Security

- Rotate the token immediately if it is ever pasted into a chat, email, or file.
- `.env`, `*.token`, `*.key`, and `secrets*` are git-ignored — verify with `git status` before pushing.
