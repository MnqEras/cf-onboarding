#!/usr/bin/env python3
"""Read a Cloudflare custom-firewall entrypoint ruleset on stdin, append our
standard admin/login Managed-Challenge rule (idempotently), print the PUT body."""
import sys, json

DESC = "cf-onboard: challenge admin/login paths"
PATHS = ["/wp-admin", "/wp-login", "/xmlrpc.php", "/administrator"]
EXPR = " or ".join('(http.request.uri.path contains "%s")' % p for p in PATHS)

try:
    rules = (json.load(sys.stdin).get("result") or {}).get("rules") or []
except Exception:
    rules = []

# Drop any prior copy of our rule so re-runs don't duplicate it.
rules = [r for r in rules if r.get("description") != DESC]

clean = []
for r in rules:
    c = {"action": r.get("action"), "expression": r.get("expression")}
    for k in ("description", "enabled", "action_parameters", "ref"):
        if r.get(k) is not None:
            c[k] = r.get(k)
    clean.append(c)

clean.append({
    "action": "managed_challenge",
    "expression": EXPR,
    "description": DESC,
    "enabled": True,
})
print(json.dumps({"rules": clean}))
