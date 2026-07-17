#!/usr/bin/env python3
"""Read a Cloudflare response-headers-transform entrypoint ruleset on stdin,
append our standard security-header rule (idempotently), print the PUT body."""
import sys, json

DESC = "cf-onboard: security response headers"
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "0",
}

try:
    rules = (json.load(sys.stdin).get("result") or {}).get("rules") or []
except Exception:
    rules = []

rules = [r for r in rules if r.get("description") != DESC]  # idempotent

clean = []
for r in rules:
    c = {"action": r.get("action"), "expression": r.get("expression")}
    for k in ("description", "enabled", "action_parameters", "ref"):
        if r.get(k) is not None:
            c[k] = r.get(k)
    clean.append(c)

clean.append({
    "action": "rewrite",
    "expression": "true",
    "description": DESC,
    "enabled": True,
    "action_parameters": {
        "headers": {h: {"operation": "set", "value": v} for h, v in HEADERS.items()}
    },
})
print(json.dumps({"rules": clean}))
