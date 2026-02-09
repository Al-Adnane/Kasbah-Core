# Kasbah Early Access — Shiplist (Source of Truth)

This file defines what is considered part of the public early-access release.

## Must ship
- apps/api/main.py
- apps/api/rtp/** (ticketing, verify/consume, audit, limits, authz)
- apps/kernel/** (governance kernel interface)
- apps/adapters/** (integration adapters)
- tests/** (minimal safety + contract tests)
- README.md, SECURITY.md, LICENSE
- docs/** (kernel + governance docs)
- docker-compose.yml, scripts/ (build/run)

## Must NOT ship
- any .env*
- any archives/dumps (Kasbah-CoreF_ARCHIVE, kasbah-core-7/8/9, kasbah_dist, *.tgz, *.zip)
- any “loose” root scripts that are experiments (keep under /scratch or /examples if needed)

## Early Access promise
- Fail-closed by default
- Short TTL tickets
- Replay protection
- Rate limits on decide/consume/verify
- Audit log append-only semantics
