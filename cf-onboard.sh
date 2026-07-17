#!/usr/bin/env bash
#
# cf-onboard.sh — Harden a new client domain on Cloudflare in one command.
#
# Idempotent (safe to re-run). Applies, by default:
#   • Always Use HTTPS          → 301 redirect http:// → https://
#   • SSL/TLS mode              → full (override with --ssl)
#   • Automatic HTTPS Rewrites  → on
#   • Minimum TLS version       → 1.2
#   • TLS 1.3                   → on
#   • Brotli                    → on
#   • Bot Fight Mode            → on (best-effort; plan-gated)
# Opt-in:
#   --hsts   Enable HSTS (only after HTTPS is confirmed working everywhere)
#   --waf    Add a Managed-Challenge WAF custom rule for admin/login paths (additive)
#
# Usage:
#   export CF_API_TOKEN=xxxxx        # token with Zone:Edit + Zone Settings:Edit (+ Zone WAF:Edit for --waf)
#   ./cf-onboard.sh example.com
#   ./cf-onboard.sh example.com --ssl strict --hsts --waf
#
# The token is read ONLY from $CF_API_TOKEN (or a local .env). Never hard-code it.

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Load .env from the script dir if CF_API_TOKEN isn't already exported.
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

_field() { # _field '["a"]["b"]'  — extract a nested field from JSON on stdin
  python3 -c 'import sys,json
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
    fail "$label — $(printf '%s' "$resp" | _errors)"
  fi
}

# ---------- args ----------
DOMAIN=""; SSL_MODE="full"; DO_HSTS=0; DO_WAF=0
usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --ssl)  SSL_MODE="${2:-}"; shift 2;;
    --hsts) DO_HSTS=1; shift;;
    --waf)  DO_WAF=1; shift;;
    -h|--help) usage; exit 0;;
    -*) die "unknown flag: $1";;
    *)  DOMAIN="$1"; shift;;
  esac
done

[ -n "${CF_API_TOKEN:-}" ] || die "CF_API_TOKEN is not set (export it or put it in $SCRIPT_DIR/.env)"
[ -n "$DOMAIN" ] || die "no domain given. Usage: ./cf-onboard.sh <domain> [--ssl full|strict|flexible] [--hsts] [--waf]"
case "$SSL_MODE" in off|flexible|full|strict) ;; *) die "invalid --ssl '$SSL_MODE' (use off|flexible|full|strict)";; esac

# ---------- 0. verify token (non-fatal: some account-scoped tokens verify elsewhere) ----------
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
[ -n "$ZONE_ID" ] || die "domain '$DOMAIN' not found on this account (or token lacks Zone:Read). Add the site to Cloudflare first."
PLAN=$(printf '%s' "$Z" | _field '["result"][0]["plan"]["name"]')
STATUS=$(printf '%s' "$Z" | _field '["result"][0]["status"]')
ok "zone $ZONE_ID  •  plan: $PLAN  •  status: $STATUS"
[ "$STATUS" = "active" ] || warn "zone is not 'active' yet — settings apply but won't take effect until nameservers are live"

# ---------- 2. core TLS / HTTPS hardening ----------
step "Applying HTTPS + TLS settings"
set_setting always_use_https         '"on"'          "Always Use HTTPS (http → https 301)"
set_setting ssl                      "\"$SSL_MODE\"" "SSL/TLS mode → $SSL_MODE"
set_setting automatic_https_rewrites '"on"'          "Automatic HTTPS Rewrites"
set_setting min_tls_version          '"1.2"'         "Minimum TLS version → 1.2"
set_setting tls_1_3                  '"on"'          "TLS 1.3"
set_setting brotli                   '"on"'          "Brotli compression"

# ---------- 3. Bot Fight Mode (best-effort) ----------
step "Enabling Bot Fight Mode"
BFM=$(cf -X PUT "$API/zones/$ZONE_ID/bot_management" --data '{"fight_mode":true}')
if [ "$(printf '%s' "$BFM" | _success)" = "true" ]; then
  ok "Bot Fight Mode"
else
  warn "Bot Fight Mode not set via API ($(printf '%s' "$BFM" | _errors)) — toggle under Security → Bots if needed"
fi

# ---------- 4. HSTS (opt-in) ----------
if [ "$DO_HSTS" = 1 ]; then
  step "Enabling HSTS"
  H=$(cf -X PATCH "$API/zones/$ZONE_ID/settings/security_header" \
        --data '{"value":{"strict_transport_security":{"enabled":true,"max_age":15552000,"include_subdomains":true,"nosniff":true,"preload":false}}}')
  if [ "$(printf '%s' "$H" | _success)" = "true" ]; then
    ok "HSTS (max-age 180d, includeSubDomains)"
  else
    fail "HSTS — $(printf '%s' "$H" | _errors)"
  fi
fi

# ---------- 5. WAF custom rule (opt-in, additive) ----------
if [ "$DO_WAF" = 1 ]; then
  step "Adding WAF custom rule (challenge admin/login paths)"
  EP=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint")
  BODY=$(printf '%s' "$EP" | python3 "$SCRIPT_DIR/waf_merge.py")
  W=$(cf -X PUT "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" --data "$BODY")
  if [ "$(printf '%s' "$W" | _success)" = "true" ]; then
    ok "WAF rule active (Managed Challenge on /wp-admin, /wp-login, /xmlrpc.php, /administrator)"
  else
    fail "WAF rule — $(printf '%s' "$W" | _errors)"
  fi
fi

# ---------- 6. verify live state ----------
step "Verifying live settings"
for s in always_use_https ssl automatic_https_rewrites min_tls_version tls_1_3; do
  R=$(cf "$API/zones/$ZONE_ID/settings/$s")
  printf '  %-26s %s\n' "$s" "$(printf '%s' "$R" | _field '["result"]["value"]')"
done

printf '\n\033[1;32mDone.\033[0m %s is hardened. HTTP now 301-redirects to HTTPS.\n' "$DOMAIN"
