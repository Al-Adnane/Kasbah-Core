# Kasbah integrated runbook

## 1) Install deps
pip install 'fastapi[all]' uvicorn requests

Optional (for Redis):
pip install redis

## 2) Run the server
export KASBAH_JWT_SECRET="$(python - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
)"
python kasbah_app_integrated.py

## 3) Run the full test suite
python test_kasbah_integrated.py
