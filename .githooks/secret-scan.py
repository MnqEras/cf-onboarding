#!/usr/bin/env python3
"""Block secrets from ever reaching git.

Reads unified diff text on stdin (or scans given files) and fails if an ADDED line looks like a
real credential. Deliberately tuned for high confidence over high recall: a false positive blocks
the automated vault sync, and this vault contains a security book that discusses passwords, tokens
and key material in prose. So it matches STRUCTURED secrets -- known vendor prefixes, key blocks,
and assignments carrying high-entropy values -- not the words "password" or "token".

Exit 0 = clean, 1 = secrets found (printed with the value REDACTED).
"""
import base64, math, re, sys

# ---- high-confidence vendor / format patterns -------------------------------
PATTERNS = [
    ("OpenAI/OpenRouter key",   re.compile(r'\bsk-(?:or-v1-|ant-|proj-|live-)?[A-Za-z0-9_-]{24,}')),
    ("GHL private token",       re.compile(r'\bpit-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')),
    ("GitHub token",            re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{40,}')),
    ("AWS access key id",       re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ("Slack token",             re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ("Telegram bot token",      re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')),
    ("Zammad API token",        re.compile(r'Token\s+token=[A-Za-z0-9_-]{20,}')),
    ("Private key block",       re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----')),
    ("Cloudflare API token",    re.compile(r'\b[A-Za-z0-9_-]{40}\b(?=.*(?i:cloudflare|cf[_-]?api))')),
    ("Google OAuth secret",     re.compile(r'\bGOCSPX-[A-Za-z0-9_-]{20,}')),
    ("JWT",                     re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
]

# ---- assignment of a high-entropy value to a credential-ish name ------------
ASSIGN = re.compile(
    r'(?i)\b([A-Za-z0-9_]*(?:passw(?:or)?d|passphrase|secret|api[_-]?key|token|credential)[A-Za-z0-9_]*)'
    r'\s*[:=]\s*["\']?([^\s"\'#,;]{12,})["\']?'
)

# Values that are obviously not real secrets.
SAFE = re.compile(r'(?i)^(?:<[^>]*>|\{\{.*\}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\.{3,}|x{4,}|\*{4,}|'
                  r'redacted|placeholder|changeme|example|your[_-]?\w+|none|null|true|false|'
                  r'[a-f0-9]{7,12}|paste|todo|tbd|see\b.*|in\s+the\b.*)$')
SAFE_CONTEXT = re.compile(r'(?i)\b(?:fp=|fingerprint|sha256|sha-256|md5|hash|len=|length|'
                          r'find-generic-password|security\s+add-generic|env\.|getenv|printenv)')


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((c := s.count(ch) / len(s)) and c * math.log2(c) for ch in set(s))


# Characters that never occur in machine-issued tokens/app passwords but are everywhere in
# regex, code and templating. Their presence means we are looking at source, not a credential.
CODEY = set('[]{}()|\\<>*?^$"\'`')

# SCREAMING_SNAKE_CASE is the shape of a variable NAME, not a value. This guard tells people to
# "reference it by NAME only", so notes legitimately contain lines like `token = GHL_PRIVATE_API_KEY`
# -- which ASSIGN reads as an assignment and looks_random() scored as high-entropy (19 chars, mixed
# classes). That false positive stalled the vault sync for 13 days. Machine-issued credentials are
# mixed-case/random and never take this shape.
ENV_VAR_NAME = re.compile(r'^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$')


def looks_random(v: str) -> bool:
    """High entropy AND mixed character classes -- filters out prose, paths and source code."""
    if len(v) < 12 or SAFE.match(v):
        return False
    if '/' in v or ' ' in v:            # paths and sentences
        return False
    if CODEY & set(v):                  # regex/code, e.g. token=[A-Za-z0-9_-]{20,}
        return False
    if ENV_VAR_NAME.match(v):           # an env var NAME being cited, not its value
        return False
    classes = sum(bool(re.search(p, v)) for p in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]'))
    return entropy(v) >= 3.2 and classes >= 2


def redact(v: str) -> str:
    return f"{v[:3]}…{v[-2:]} ({len(v)} chars)" if len(v) > 8 else "…"


# Embedded file payloads (images, fonts) are data, not credentials. A 2.6 MB base64 texture line
# matched the Cloudflare rule by chance ("cfapi" appears somewhere in random base64) on 2026-09-28.
DATA_URI = re.compile(r'data:[\w.+-]+/[\w.+-]+;base64,[A-Za-z0-9+/=]{64,}')


def scan_line(line: str):
    hits = []
    if SAFE_CONTEXT.search(line):
        return hits
    line = DATA_URI.sub('data:<payload>', line)
    for label, pat in PATTERNS:
        for m in pat.finditer(line):
            hits.append((label, redact(m.group(0))))
    for m in ASSIGN.finditer(line):
        name, val = m.group(1), m.group(2)
        if looks_random(val):
            hits.append((f"{name}=<high-entropy>", redact(val)))
    return hits


def main():
    findings, path = [], "(unknown)"
    for raw in sys.stdin.read().splitlines():
        if raw.startswith('+++ b/'):
            path = raw[6:]
            continue
        if not raw.startswith('+') or raw.startswith('+++'):
            continue
        line = raw[1:]
        for label, shown in scan_line(line):
            findings.append((path, label, shown, line.strip()[:60]))

    if not findings:
        return 0

    print("\n\033[1;31m🚫 SECRET GUARD: refusing to commit — credential-shaped content detected\033[0m\n")
    for path, label, shown, ctx in findings:
        print(f"  {path}")
        print(f"    {label}: {shown}")
        print(f"    context: {ctx}…\n")
    print("  Nothing was committed. Remove the value, or store it in the macOS keychain:")
    print("    security add-generic-password -U -a <name> -s '<desc>' -w '<value>'")
    print("  Reference it in notes by NAME only, never by value.")
    print("  If this is a genuine false positive:  git commit --no-verify   (then tell someone)\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
