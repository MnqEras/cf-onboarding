# cf-onboarding

One-command Cloudflare **security baseline** for a new client domain. Free-plan only.
Idempotent — safe to re-run.

## The workflow (per client)

1. In the **client's** Cloudflare account, create a custom API token (see permissions below).
2. Run:
   ```bash
   CF_API_TOKEN=<client-token> ./cf-onboard.sh clientdomain.co.za
   ```
   (Or drop the token into a git-ignored `.env` and just run `./cf-onboard.sh clientdomain.co.za`.)
3. Do the 3 manual follow-ups the script prints (DNSSEC DS record at registrar, Bot Fight Mode toggle, optional `--ssl strict` later).

## What it applies (all Free-tier, all ON by default)

- **Always Use HTTPS** — 301 http → https
- **SSL/TLS** → `full` · **Automatic HTTPS Rewrites** · **Min TLS 1.2** · **TLS 1.3** · **Opportunistic Encryption** · **Brotli**
- **Browser Integrity Check** · **Email Obfuscation** · **Server-Side Excludes**
- **DNSSEC** — activated; prints the DS record to add at the registrar
- **Leaked-Credentials detection**
- **WAF custom rule** — Managed Challenge on `/wp-admin`, `/wp-login`, `/xmlrpc.php`, `/administrator`
- **Security headers** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-XSS-Protection: 0`
- **HSTS (smart)** — auto-enabled *only* if the site already answers over HTTPS, so it can never lock out a not-yet-live domain. Re-run once DNS is live to switch it on.

### Not scriptable on Free (script reminds you)
- **Bot Fight Mode** — dashboard toggle: Security → Bots.
- **DNSSEC DS record** — must be added at the domain registrar.
- **WAF Managed Ruleset** — paid feature; intentionally excluded.

## Flags
- `--ssl full|strict|flexible|off` (default `full`; use `strict` once origin has a valid cert)
- `--no-hsts` · `--no-waf` · `--no-headers` — skip a section

## Token permissions (in the client's account, Zone Resources → All zones)
- Zone → **Zone Settings** → Edit
- Zone → **Zone** → Read
- Zone → **Zone WAF** → Edit
- Zone → **DNS** → Edit  *(for DNSSEC)*

## Security
- Each client uses their own token — pass it inline (`CF_API_TOKEN=…`) or keep the current one in `.env`.
- `.env`, `*.token`, `*.key`, `secrets*` are git-ignored. Never commit a real token.
