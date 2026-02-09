# Kasbah Ship Profile (Early Access)

## Shipped runtime (authoritative)
- FastAPI service in: `apps/api/main.py`
- Docker entry: `docker-compose.yml` (service: `api`)

## Public API surface (must stay stable)
- `GET /health`
- `POST /api/rtp/decide`
- `POST /api/rtp/consume`
- `GET /api/rtp/audit`
- (admin) `GET/POST /api/system/*` (guarded by admin token)

## Non-shipping (must never be committed)
- `.env*`
- archives / bundles / dumps (`*.zip`, `*.tgz`, `kasbah_dist/`, `kasbah-core-*`, etc.)
- logs (`*.log`, `api*.log`, `server.log`, `kasbah.log`)
- scratch experiments

## Where experiments go
- `scratch/` for local-only work
- `examples/` for documentation-grade integration samples
