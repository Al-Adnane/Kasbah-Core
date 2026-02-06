#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Fix Caddy: remove Cloudflare DNS-01 config =="

test -f Caddyfile || { echo "FAIL: Caddyfile not found in repo root"; exit 1; }

cp -v Caddyfile "Caddyfile.bak.$(date +%Y%m%d_%H%M%S)"

# Remove any lines mentioning acme_dns or cloudflare dns provider blocks.
# This is intentionally blunt to stop the restart loop.
python3 - <<'PY'
from pathlib import Path
p = Path("Caddyfile")
lines = p.read_text().splitlines()

out = []
removed = 0
skip_block = False
brace_depth = 0

for line in lines:
    l = line.strip()

    # If line contains cloudflare/dns plugin directives, remove
    if "acme_dns" in l or "dns.providers.cloudflare" in l or ("dns" in l and "cloudflare" in l):
        removed += 1
        continue

    # If there is a tls block that might include dns config, keep it unless it includes cloudflare
    # (we already removed lines containing cloudflare)
    out.append(line)

p.write_text("\n".join(out) + "\n")
print(f"OK: patched Caddyfile (removed {removed} cloudflare-related line(s))")
PY

echo
echo "== Show patched Caddyfile =="
nl -ba Caddyfile | sed -n '1,140p'

echo
echo "== Restart caddy =="
docker compose restart caddy

echo
echo "== caddy status =="
docker compose ps caddy

echo
echo "== caddy logs (last 40) =="
docker logs --tail 40 kasbah-core-caddy-1 || true
