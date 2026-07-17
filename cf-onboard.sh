#!/usr/bin/env bash
#
# cf-onboard.sh — Apply Boldpiq's full security baseline to a client domain on
# Cloudflare (Free plan). One command, idempotent, safe to re-run.
#
# Everything below is FREE-plan compatible and ON by default:
#   • Always Use HTTPS          → 301 redirect http:// → https://
#   • SSL/TLS mode              → full (override with --ssl)
#   • Automatic HTTPS Rewrites  → on   (kills mixed-content)
#   • Minimum TLS               → 1.2
#   • TLS 1.3                   → on
#   • Opportunistic Encryption  → on
#   • Brotli                    → on
#   • Browser Integrity Check   → on   (blocks malicious user-agents)
#   • Email Obfuscation         → on   (hides mailto from scrapers)
#   • Server-Side Excludes      → on
#   • DNSSEC                    → activated (prints DS record for the registrar)
#   • Leaked-Credentials check  → on   (best-effort)
#   • WAF custom rule           → Managed-Challenge on admin/login paths
#   • Security response headers → X-Content-Type-Options, X-Frame-Options,
#                                 Referrer-Policy, X-XSS-Protection
#   • HSTS                      → SMART: auto-enabled only if HTTPS is confirmed
#                                 live (never locks out a broken site)
#   • Bot Fight Mode            → attempted (Free plan is dashboard-only; noted)
#
# Per-client usage (each client has their own Cloudflare account + token):
#   CF_API_TOKEN=<client-token> ./cf-onboard.sh clientdomain.co.za
# or put the token in a local .env (git-ignored) and:
#   ./cf-onboard.sh clientdomain.co.za
#
# Flags: --ssl full|strict|flexible|off | --no-hsts | --no-waf | --no-headers
#
# Token permissions (create in the CLIENT's Cloudflare account, All zones):
#   Zone → Zone Settings → Edit   |   Zone → Zone → Read   |   Zone → Zone WAF → Edit
#   Zone → DNS → Edit  (for DNSSEC)
#
# The token is read ONLY from $CF_API_TOKEN or a git-ignored .env. Never hard-coded.

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -z "${CF_API_TOKEN:-}" ] && [ -f "$SCRIPT_DIR/.env" ]; then
  set -a; . "$SCRIPT_DIR/.env"; set +a
fi

API="https://api.cloudflare.com/client/v4"

# ---------- pretty output ----------
step() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; }
die()  { printf '\033[31mError:\033[0m %s\n' "$1" >&2; exit 1; }

# ---------- json helpers (python3, no jq dependency) ----------
_success() { python3 -c 'import sys,json
try: print("true" if json.load(sys.stdin).get("success") else "false")
except Exception: print("false")'; }

_errors() { python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); parts=[]
    for e in d.get("errors",[]): parts.append(str(e.get("code"))+": "+str(e.get("message")))
    print("; ".join(parts) if parts else "unknown error")
except Exception: print("unparseable response")'; }

_field() { python3 -c 'import sys,json
try: print(eval("json.load(sys.stdin)"+sys.argv[1]))
except Exception: print("")' "$1"; }

cf() { curl -sS --max-time 25 \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" "$@"; }

# Apply a scalar zone setting. $1=name $2=json-value $3=label
set_setting() {
  local name="$1" value="$2" label="$3" resp
  resp=$(cf -X PATCH "$API/zones/$ZONE_ID/settings/$name" --data "{\"value\":$value}")
  if [ "$(printf '%s' "$resp" | _success)" = "true" ]; then
    ok "$label"
  else
    warn "$label — $(printf '%s' "$resp" | _errors)"
  fi
}

# Additive ruleset PUT for a phase entrypoint. $1=phase $2=merge-script $3=label
put_ruleset() {
  local phase="$1" merger="$2" label="$3" ep body resp
  ep=$(cf "$API/zones/$ZONE_ID/rulesets/phases/$phase/entrypoint")
  body=$(printf '%s' "$ep" | python3 "$SCRIPT_DIR/$merger")
  resp=$(cf -X PUT "$API/zones/$ZONE_ID/rulesets/phases/$phase/entrypoint" --data "$body")
  if [ "$(printf '%s' "$resp" | _success)" = "true" ]; then
    ok "$label"
  else
    fail "$label — $(printf '%s' "$resp" | _errors)"
  fi
}

# ---------- args ----------
DOMAIN=""; SSL_MODE="full"; NO_HSTS=0; NO_WAF=0; NO_HEADERS=0
usage() { sed -n '2,42p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --ssl)        SSL_MODE="${2:-}"; shift 2;;
    --no-hsts)    NO_HSTS=1; shift;;
    --no-waf)     NO_WAF=1; shift;;
    --no-headers) NO_HEADERS=1; shift;;
    -h|--help)    usage; exit 0;;
    -*) die "unknown flag: $1";;
    *)  DOMAIN="$1"; shift;;
  esac
done

[ -n "${CF_API_TOKEN:-}" ] || die "CF_API_TOKEN not set (export it or put it in $SCRIPT_DIR/.env)"
[ -n "$DOMAIN" ] || die "no domain. Usage: CF_API_TOKEN=... ./cf-onboard.sh <domain> [--ssl ...] [--no-hsts] [--no-waf] [--no-headers]"
case "$SSL_MODE" in off|flexible|full|strict) ;; *) die "invalid --ssl '$SSL_MODE'";; esac

# ---------- 0. token (non-fatal verify; real gate is the zone lookup) ----------
step "Verifying API token"
V=$(cf "$API/user/tokens/verify")
if [ "$(printf '%s' "$V" | _success)" = "true" ]; then
  ok "token valid ($(printf '%s' "$V" | _field '["result"]["status"]'))"
else
  warn "user-scoped verify inconclusive — validating via zone access instead"
fi

# ---------- 1. resolve zone ----------
step "Looking up zone: $DOMAIN"
Z=$(cf "$API/zones?name=$DOMAIN")
[ "$(printf '%s' "$Z" | _success)" = "true" ] || die "zone lookup failed — $(printf '%s' "$Z" | _errors)"
ZONE_ID=$(printf '%s' "$Z" | python3 -c 'import sys,json
r=(json.load(sys.stdin).get("result") or [])
print(r[0]["id"] if r else "")')
[ -n "$ZONE_ID" ] || die "'$DOMAIN' not found on this account (or token lacks Zone:Read). Add the site to Cloudflare first."
PLAN=$(printf '%s' "$Z" | _field '["result"][0]["plan"]["name"]')
STATUS=$(printf '%s' "$Z" | _field '["result"][0]["status"]')
ok "zone $ZONE_ID  •  plan: $PLAN  •  status: $STATUS"
[ "$STATUS" = "active" ] || warn "zone not 'active' yet — settings apply but take effect once nameservers are live"

# ---------- 2. TLS / HTTPS ----------
step "TLS / HTTPS"
set_setting always_use_https         '"on"'          "Always Use HTTPS (http → https 301)"
set_setting ssl                      "\"$SSL_MODE\"" "SSL/TLS mode → $SSL_MODE"
set_setting automatic_https_rewrites '"on"'          "Automatic HTTPS Rewrites"
set_setting min_tls_version          '"1.2"'         "Minimum TLS → 1.2"
set_setting tls_1_3                  '"on"'          "TLS 1.3"
set_setting opportunistic_encryption '"on"'          "Opportunistic Encryption"
set_setting brotli                   '"on"'          "Brotli compression"

# ---------- 3. hardening toggles ----------
step "Hardening"
set_setting browser_check      '"on"' "Browser Integrity Check"
set_setting email_obfuscation  '"on"' "Email Obfuscation"
set_setting server_side_exclude '"on"' "Server-Side Excludes"

# ---------- 4. DNSSEC ----------
step "DNSSEC"
DS=$(cf -X PATCH "$API/zones/$ZONE_ID/dnssec" --data '{"status":"active"}')
if [ "$(printf '%s' "$DS" | _success)" = "true" ]; then
  ok "DNSSEC activated"
  REC=$(printf '%s' "$DS" | _field '["result"]["ds"]')
  [ -n "$REC" ] && printf '    \033[36m↳ Add this DS record at the domain registrar to finish DNSSEC:\033[0m\n    %s\n' "$REC"
else
  warn "DNSSEC — $(printf '%s' "$DS" | _errors)"
fi

# ---------- 5. Leaked-Credentials detection (best-effort) ----------
step "Leaked-Credentials detection"
LC=$(cf -X POST "$API/zones/$ZONE_ID/leaked-credential-checks" --data '{"enabled":true}')
if [ "$(printf '%s' "$LC" | _success)" = "true" ]; then
  ok "Leaked-Credentials detection"
else
  warn "Leaked-Credentials — $(printf '%s' "$LC" | _errors)"
fi

# ---------- 6. Bot Fight Mode (Free plan: usually dashboard-only) ----------
step "Bot Fight Mode"
BFM=$(cf -X PUT "$API/zones/$ZONE_ID/bot_management" --data '{"fight_mode":true}')
if [ "$(printf '%s' "$BFM" | _success)" = "true" ]; then
  ok "Bot Fight Mode"
else
  warn "not settable via API on Free — toggle ON in dashboard: Security → Bots → Bot Fight Mode"
fi

# ---------- 7. WAF custom rule ----------
if [ "$NO_WAF" = 0 ]; then
  step "WAF custom rule (challenge admin/login paths)"
  put_ruleset http_request_firewall_custom waf_merge.py \
    "WAF rule active (Managed Challenge on /wp-admin, /wp-login, /xmlrpc.php, /administrator)"
fi

# ---------- 8. Security response headers ----------
if [ "$NO_HEADERS" = 0 ]; then
  step "Security response headers"
  put_ruleset http_response_headers_transform headers_merge.py \
    "Headers set (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-XSS-Protection)"
fi

# ---------- 9. HSTS — smart: only if HTTPS is confirmed live ----------
if [ "$NO_HSTS" = 0 ]; then
  step "HSTS (smart)"
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 "https://$DOMAIN" 2>/dev/null); CODE=${CODE:-000}
  case "$CODE" in
    2*|3*)
      H=$(cf -X PATCH "$API/zones/$ZONE_ID/settings/security_header" \
            --data '{"value":{"strict_transport_security":{"enabled":true,"max_age":15552000,"include_subdomains":true,"nosniff":true,"preload":false}}}')
      if [ "$(printf '%s' "$H" | _success)" = "true" ]; then
        ok "HTTPS verified (HTTP $CODE) → HSTS enabled (max-age 180d, includeSubDomains)"
      else
        fail "HSTS — $(printf '%s' "$H" | _errors)"
      fi
      ;;
    *)
      warn "HTTPS not verifiable yet (got '$CODE' — DNS still propagating or origin down). HSTS skipped; re-run once the site loads over https to enable it safely."
      ;;
  esac
fi

# ---------- 10. verify live state ----------
step "Verifying live settings"
for s in always_use_https ssl automatic_https_rewrites min_tls_version tls_1_3 browser_check email_obfuscation; do
  R=$(cf "$API/zones/$ZONE_ID/settings/$s")
  printf '  %-26s %s\n' "$s" "$(printf '%s' "$R" | _field '["result"]["value"]')"
done

# ---------- manual reminders (Free-plan items not scriptable) ----------
printf '\n\033[1;32mDone.\033[0m %s hardened. Manual follow-ups:\n' "$DOMAIN"
printf '  • Add the DNSSEC \033[36mDS record\033[0m above at the domain registrar.\n'
printf '  • Toggle \033[36mBot Fight Mode\033[0m ON: Security → Bots.\n'
printf '  • Once the origin has a valid TLS cert, re-run with \033[36m--ssl strict\033[0m.\n'
