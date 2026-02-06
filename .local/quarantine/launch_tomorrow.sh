#!/bin/bash
set -e

echo "🚀 KASBAH CORE - PRODUCTION LAUNCH SCRIPT"
echo "Date: $(date)"
echo "==========================================="

# Configuration
PRODUCTION_DIR="/var/lib/kasbah"
BACKUP_DIR="/var/backup/kasbah"
DOCKER_IMAGE="kasbah-core:production"
REGISTRY="registry.yourcompany.com/kasbah"
ENV_FILE="$PRODUCTION_DIR/.env.production"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Step 1: Pre-flight checks
log "Step 1: Running pre-flight checks..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    warning "Running as root - consider using a dedicated user"
fi

# Check required tools
command -v docker >/dev/null 2>&1 || error "Docker not installed"
command -v docker-compose >/dev/null 2>&1 || error "Docker Compose not installed"
command -v curl >/dev/null 2>&1 || error "curl not installed"

# Check disk space
DISK_SPACE=$(df /var/lib | awk 'NR==2 {print $4}')
if [ $DISK_SPACE -lt 10485760 ]; then  # 10GB
    error "Insufficient disk space (need at least 10GB)"
fi

# Check memory
MEMORY=$(free -m | awk 'NR==2 {print $7}')
if [ $MEMORY -lt 1024 ]; then  # 1GB
    warning "Low memory available ($MEMORY MB)"
fi

success "Pre-flight checks passed"

# Step 2: Backup current state
log "Step 2: Backing up current production state..."
mkdir -p $BACKUP_DIR
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -f "$PRODUCTION_DIR/kasbah_production.db" ]; then
    cp "$PRODUCTION_DIR/kasbah_production.db" "$BACKUP_DIR/kasbah_production.db.$TIMESTAMP"
    success "Database backed up"
fi

if [ -d "$PRODUCTION_DIR/data" ]; then
    tar -czf "$BACKUP_DIR/data_$TIMESTAMP.tar.gz" -C "$PRODUCTION_DIR" data/
    success "Data directory backed up"
fi

# Step 3: Generate production secrets
log "Step 3: Generating production secrets..."
mkdir -p $PRODUCTION_DIR

cat > $ENV_FILE << ENV_EOF
# Kasbah Core Production Environment
# Generated: $(date)
# DO NOT SHARE OR COMMIT THIS FILE

KASBAH_JWT_SECRET=$(openssl rand -hex 64)
KASBAH_HMAC_KEY=$(openssl rand -hex 48)
KASBAH_AUDIT_DB=$PRODUCTION_DIR/kasbah_production.db
KASBAH_DATA_DIR=$PRODUCTION_DIR
KASBAH_STATE_DB=$PRODUCTION_DIR/agent_state.db
KASBAH_SYSTEM_STABLE=1
KASBAH_GEOMETRY_THRESHOLD=0.95
KASBAH_EMA_ALPHA=0.3
KASBAH_TICKET_TTL_SECONDS=300

# API Keys (for initial operators)
KASBAH_ADMIN_API_KEY=$(openssl rand -hex 32)
KASBAH_OPERATOR_API_KEY=$(openssl rand -hex 32)

# Redis (optional)
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=$(openssl rand -hex 24)

# Security
REQUIRE_HTTPS=1
CORS_ORIGINS=https://app.yourdomain.com,https://admin.yourdomain.com
MAX_REQUEST_SIZE=10485760

# Performance
UVICORN_WORKERS=4
UVICORN_LOG_LEVEL=info
UVICORN_TIMEOUT=120
ENV_EOF

chmod 600 $ENV_FILE
success "Environment file created: $ENV_FILE"

# Step 4: Initialize production database
log "Step 4: Initializing production database..."
python3 << 'PYEOF'
import os
import sqlite3
import time
import hashlib

# Load environment
from dotenv import load_dotenv
load_dotenv('/var/lib/kasbah/.env.production')

db_path = os.getenv('KASBAH_AUDIT_DB')
os.makedirs(os.path.dirname(db_path), exist_ok=True)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create operators table
cursor.execute('''
CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'observer')),
    api_key_hash TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL,
    last_login REAL,
    is_active BOOLEAN DEFAULT 1
)
''')

# Create agents table
cursor.execute('''
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    persona TEXT NOT NULL DEFAULT 'balanced',
    geometry_bias REAL NOT NULL DEFAULT 1.0,
    integrity_bias REAL NOT NULL DEFAULT 1.0,
    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    max_requests_per_minute INTEGER DEFAULT 60
)
''')

# Insert admin operator
admin_hash = hashlib.sha256(os.getenv('KASBAH_ADMIN_API_KEY').encode()).hexdigest()
operator_hash = hashlib.sha256(os.getenv('KASBAH_OPERATOR_API_KEY').encode()).hexdigest()

cursor.execute(
    "INSERT OR IGNORE INTO operators (name, role, api_key_hash, created_at) VALUES (?, ?, ?, ?)",
    ("System Administrator", "admin", admin_hash, time.time())
)

cursor.execute(
    "INSERT OR IGNORE INTO operators (name, role, api_key_hash, created_at) VALUES (?, ?, ?, ?)",
    ("Default Operator", "operator", operator_hash, time.time())
)

conn.commit()
conn.close()
print("Production database initialized successfully")
PYEOF

success "Database initialized"

# Step 5: Build Docker image
log "Step 5: Building Docker image..."
docker build -t $DOCKER_IMAGE -f Dockerfile.production .
success "Docker image built: $DOCKER_IMAGE"

# Step 6: Push to registry (if configured)
if [ ! -z "$REGISTRY" ]; then
    log "Step 6: Pushing to registry..."
    docker tag $DOCKER_IMAGE $REGISTRY:latest
    docker tag $DOCKER_IMAGE $REGISTRY:$TIMESTAMP
    docker push $REGISTRY:latest
    docker push $REGISTRY:$TIMESTAMP
    success "Image pushed to registry"
fi

# Step 7: Create production docker-compose
log "Step 7: Creating production deployment..."
cat > $PRODUCTION_DIR/docker-compose.yml << 'DOCKER_EOF'
version: '3.8'

services:
  kasbah-api:
    image: ${KASBAH_IMAGE:-kasbah-core:production}
    container_name: kasbah-api-prod
    restart: unless-stopped
    environment:
      - KASBAH_JWT_SECRET=${KASBAH_JWT_SECRET}
      - KASBAH_HMAC_KEY=${KASBAH_HMAC_KEY}
      - KASBAH_AUDIT_DB=${KASBAH_AUDIT_DB}
      - KASBAH_DATA_DIR=${KASBAH_DATA_DIR}
      - KASBAH_STATE_DB=${KASBAH_STATE_DB}
      - KASBAH_SYSTEM_STABLE=${KASBAH_SYSTEM_STABLE}
      - KASBAH_GEOMETRY_THRESHOLD=${KASBAH_GEOMETRY_THRESHOLD}
      - KASBAH_EMA_ALPHA=${KASBAH_EMA_ALPHA}
      - KASBAH_TICKET_TTL_SECONDS=${KASBAH_TICKET_TTL_SECONDS}
    ports:
      - "8002:8002"
    volumes:
      - ${KASBAH_DATA_DIR}:${KASBAH_DATA_DIR}
      - ./logs:/app/logs
    networks:
      - kasbah-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8002/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1'
        reservations:
          memory: 256M
          cpus: '0.5'

  kasbah-redis:
    image: redis:7-alpine
    container_name: kasbah-redis-prod
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - kasbah-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  kasbah-monitor:
    image: nginx:alpine
    container_name: kasbah-monitor
    restart: unless-stopped
    ports:
      - "8080:80"
    volumes:
      - ./monitoring/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - kasbah-api
    networks:
      - kasbah-network

volumes:
  redis_data:
    driver: local

networks:
  kasbah-network:
    driver: bridge
DOCKER_EOF

success "Docker Compose configuration created"

# Step 8: Deploy
log "Step 8: Deploying Kasbah Core..."
cd $PRODUCTION_DIR
docker-compose down --remove-orphans
docker-compose up -d

# Wait for services to start
log "Waiting for services to be ready..."
sleep 10

# Step 9: Verify deployment
log "Step 9: Verifying deployment..."
MAX_RETRIES=30
RETRY_INTERVAL=10

for i in $(seq 1 $MAX_RETRIES); do
    if curl -s -f http://localhost:8002/health > /dev/null; then
        success "API health check passed"
        break
    fi
    
    if [ $i -eq $MAX_RETRIES ]; then
        error "Health check failed after $MAX_RETRIES attempts"
    fi
    
    warning "Health check attempt $i/$MAX_RETRIES failed, retrying in $RETRY_INTERVAL seconds..."
    sleep $RETRY_INTERVAL
done

# Step 10: Run smoke tests
log "Step 10: Running smoke tests..."
python3 << 'SMOKE_EOF'
import requests
import json
import time

base_url = "http://localhost:8002"
tests = [
    ("GET /health", f"{base_url}/health"),
    ("GET /api/rtp/status", f"{base_url}/api/rtp/status"),
    ("GET /docs", f"{base_url}/docs"),
]

all_passed = True
for name, url in tests:
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            print(f"✅ {name}: PASSED")
        else:
            print(f"❌ {name}: FAILED (Status {resp.status_code})")
            all_passed = False
    except Exception as e:
        print(f"❌ {name}: FAILED ({e})")
        all_passed = False

if all_passed:
    print("\n✅ All smoke tests passed!")
else:
    print("\n⚠️  Some smoke tests failed")
    exit(1)
SMOKE_EOF

# Final success message
echo ""
echo "==========================================="
echo "🎉 KASBAH CORE PRODUCTION LAUNCH COMPLETE!"
echo "==========================================="
echo ""
echo "📊 Services deployed:"
echo "   - API: http://localhost:8002"
echo "   - Docs: http://localhost:8002/docs"
echo "   - Health: http://localhost:8002/health"
echo ""
echo "🔑 Initial API Keys (save these securely):"
echo "   Admin: $(grep KASBAH_ADMIN_API_KEY $ENV_FILE | cut -d= -f2)"
echo "   Operator: $(grep KASBAH_OPERATOR_API_KEY $ENV_FILE | cut -d= -f2)"
echo ""
echo "📝 Next steps:"
echo "   1. Configure DNS for your domain"
echo "   2. Set up SSL certificates"
echo "   3. Configure monitoring (Prometheus/Grafana)"
echo "   4. Set up log aggregation (ELK Stack)"
echo "   5. Configure backups for database"
echo "   6. Setup alerting and on-call rotation"
echo ""
echo "🔄 Rollback command:"
echo "   cd $PRODUCTION_DIR && docker-compose down && cp $BACKUP_DIR/kasbah_production.db.$TIMESTAMP $PRODUCTION_DIR/kasbah_production.db"
echo ""
echo "📞 Support:"
echo "   - Check logs: docker-compose logs -f"
echo "   - View metrics: http://localhost:8080/metrics"
echo "   - Restart service: docker-compose restart kasbah-api"
echo ""
echo "🚀 Kasbah Core is now LIVE and ready for production traffic!"
