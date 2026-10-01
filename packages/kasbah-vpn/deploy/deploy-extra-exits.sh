#!/bin/bash
# Deploy additional Kasbah WireGuard exits on Fly with TCP:443 wstunnel.
# Usage: bash deploy-extra-exits.sh hkg bom syd
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export FLY_API_TOKEN="${FLY_API_TOKEN:-$(python3 -c "import yaml; print(yaml.safe_load(open('/Users/mac/.fly/config.yml'))['access_token'])")}"

REGIONS=("${@:-hkg bom}")
DEPLOY_DIR=/Users/mac/Desktop/KasbahFinal/packages/kasbah-vpn/deploy/fly-exit-node
WGQ=/opt/homebrew/bin/wg
LOC_DIR="$HOME/.kasbah-vpn/locations"

# existing client key (same peer on all exits for simplicity — matches current model)
CLIENT_PRIV=$(awk -F' = ' '/^PrivateKey/{print $2; exit}' "$LOC_DIR/sin/client.conf")
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | "$WGQ" pubkey)
# reuse same PSK as SIN for consistency
PSK=$(awk -F' = ' '/^PresharedKey/{print $2; exit}' "$LOC_DIR/sin/client.conf")

declare -A NAMES=(
  [hkg]="Hong Kong" [bom]="Mumbai" [syd]="Sydney" [lax]="Los Angeles"
  [nrt]="Tokyo" [sin]="Singapore" [ams]="Amsterdam"
)

for R in "${REGIONS[@]}"; do
  NAME="kasbah-vpn-$R"
  echo "=== $NAME ($R) ==="
  # keys
  SERVER_PRIV=$("$WGQ" genkey)
  SERVER_PUB=$(printf '%s' "$SERVER_PRIV" | "$WGQ" pubkey)
  # machine IP — allocate after app create
  if ! fly apps list 2>/dev/null | grep -q "$NAME"; then
    fly apps create "$NAME" --org personal 2>&1 | tail -3 || true
  fi
  # allocate IPv4 if missing
  fly ips list -a "$NAME" 2>/dev/null | grep -q 'v4' || fly ips allocate-v4 -a "$NAME" 2>&1 | tail -3 || true
  IP=$(fly ips list -a "$NAME" 2>/dev/null | awk '/v4/{print $2; exit}')
  echo "public ip: ${IP:-unknown}"
  # server conf (b64)
  WG_CONF=$(cat <<EOF
[Interface]
Address = 10.77.0.1/24, fd7a:6b1a:cafe::1/64
ListenPort = 51820
PrivateKey = ${SERVER_PRIV}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = ${CLIENT_PUB}
PresharedKey = ${PSK}
AllowedIPs = 10.77.0.2/32
EOF
)
  B64=$(printf '%s' "$WG_CONF" | base64 | tr -d '\n')
  # fly.toml
  cat > /tmp/fly.$R.toml <<TOML
app = "${NAME}"
primary_region = "${R}"
[build]
  dockerfile = "${DEPLOY_DIR}/Dockerfile"
  build-target = ""
[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
[experimental]
  min_machines_running = 1
[[services]]
  protocol = "udp"
  internal_port = 51820
  [[services.ports]]
    port = 51820
[[services]]
  protocol = "tcp"
  internal_port = 443
  auto_stop_machines = false
  auto_start_machines = false
  min_machines_running = 1
  [[services.ports]]
    port = 443
TOML
  fly secrets set "WG0_CONF=${B64}" -a "$NAME" 2>&1 | tail -2
  fly deploy --config /tmp/fly.$R.toml --ha=false --auto-confirm 2>&1 | tail -8
  # client conf
  mkdir -p "$LOC_DIR/$R"
  cat > "$LOC_DIR/$R/client.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.77.0.2/24
MTU = 1280

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${PSK}
AllowedIPs = 0.0.0.0/0
Endpoint = ${IP}:51820
PersistentKeepalive = 25
EOF
  chmod 600 "$LOC_DIR/$R/client.conf"
  echo "wrote $LOC_DIR/$R/client.conf"
done

# update manifest
python3 << PY
import json
from pathlib import Path
p = Path.home() / '.kasbah-vpn/locations/manifest.json'
data = json.loads(p.read_text())
have = {x['id'] for x in data}
NAMES = {'hkg':'Hong Kong','bom':'Mumbai','syd':'Sydney','lax':'Los Angeles'}
for r in """${REGIONS[*]}""".split():
    if r in have: continue
    conf = Path.home() / f'.kasbah-vpn/locations/{r}/client.conf'
    if not conf.exists(): continue
    ep = ''
    for line in conf.read_text().splitlines():
        if line.startswith('Endpoint'):
            ep = line.split('=')[1].strip()
    data.append({
        'id': r,
        'name': NAMES.get(r, r.upper()),
        'region': r,
        'continent': 'Asia' if r in ('hkg','bom') else ('Oceania' if r=='syd' else 'North America'),
        'flag': {'hkg':'🇭🇰','bom':'🇮🇳','syd':'🇦🇺','lax':'🇺🇸'}.get(r,'🌐'),
        'endpoint': ep,
        'confPath': str(conf),
        'addedAt': __import__('datetime').datetime.utcnow().isoformat()+'Z',
        'free': True,
        'obfs': 'tcp',
        'obfsHost': ep.split(':')[0] if ep else '',
        'obfsPort': 443,
        'obfsLocalPort': 51830 + len(data),
        'note': 'Extra exit · plain then TCP:443',
    })
p.write_text(json.dumps(data, indent=2)+'\\n')
print('manifest exits', [x['id'] for x in data])
PY
echo DEPLOY_DONE
