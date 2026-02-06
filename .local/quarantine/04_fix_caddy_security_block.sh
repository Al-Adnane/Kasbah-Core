#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Patch Caddyfile: remove unsupported 'security' global option =="

cp -v Caddyfile "Caddyfile.bak.$(date +%Y%m%d_%H%M%S)"

python3 - <<'PY'
from pathlib import Path

p = Path("Caddyfile")
lines = p.read_text().splitlines()

out = []
i = 0
removed_block = False

# Remove the entire "security { ... }" block inside the global options block
while i < len(lines):
    line = lines[i]
    if line.strip().startswith("security") and line.strip().endswith("{"):
        removed_block = True
        # skip until matching closing brace of this block
        depth = 0
        # consume "security {"
        while i < len(lines):
            l = lines[i]
            if "{" in l:
                depth += l.count("{")
            if "}" in l:
                depth -= l.count("}")
                if depth <= 0:
                    i += 1
                    break
            i += 1
        continue
    out.append(line)
    i += 1

txt = "\n".join(out) + "\n"
p.write_text(txt)

print("OK: removed security block" if removed_block else "NOTE: no security block found")
PY

echo
echo "== Add built-in security headers to api.kasbahcore.com (if missing) =="
python3 - <<'PY'
from pathlib import Path
import re

p = Path("Caddyfile")
txt = p.read_text()

# If api block already has a header directive, do nothing
api_block = re.search(r"(?ms)^api\\.kasbahcore\\.com\\s*\\{(.*?)^\\}", txt)
if not api_block:
    print("WARN: api.kasbahcore.com block not found; skipping header injection")
    raise SystemExit(0)

block = api_block.group(0)
if re.search(r"(?m)^\\s*header\\s*\\{", block):
    print("OK: header block already present in api.kasbahcore.com")
    raise SystemExit(0)

header_block = r"""
    # Built-in security headers (no plugins)
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
"""

# Insert header block near top of api site block (after rate_limit if present, else after opening line)
lines = block.splitlines()
insert_at = 1
for idx, line in enumerate(lines):
    if "rate_limit" in line:
        # insert after the rate_limit block ends (find next line with just "}")
        # naive but good enough for our current file
        for j in range(idx+1, len(lines)):
            if lines[j].strip() == "}":
                insert_at = j+1
                break
        break

new_block = "\n".join(lines[:insert_at] + [header_block.rstrip("\n")] + lines[insert_at:]) + "\n"

txt2 = txt.replace(block, new_block)
p.write_text(txt2)
print("OK: injected header block into api.kasbahcore.com")
PY

echo
echo "== Show Caddyfile (1..70) =="
nl -ba Caddyfile | sed -n '1,70p'

echo
echo "== Restart caddy =="
docker compose restart caddy || true

echo
echo "== Logs (last 40) =="
docker logs --tail 40 kasbah-core-caddy-1 || true
