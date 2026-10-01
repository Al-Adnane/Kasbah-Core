#!/bin/bash

# Kasbah Guard — Production Environment Setup Script
# Sets up complete production environment from scratch
# Usage: sudo ./setup-production.sh

set -e

echo "========================================"
echo "Kasbah Guard — Production Setup"
echo "Date: $(date)"
echo "========================================"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Configuration
KASBAH_USER="${KASBAH_USER:-kasbah}"
KASBAH_GROUP="${KASBAH_GROUP:-kasbah}"
KASBAH_HOME="${KASBAH_HOME:-/var/www/kasbah}"
KASBAH_LOG_DIR="${KASBAH_LOG_DIR:-/var/log/kasbah}"
KASBAH_BACKUP_DIR="${KASBAH_BACKUP_DIR:-/var/backups/kasbah}"
NODE_VERSION="${NODE_VERSION:-20}"
POSTGRES_VERSION="${POSTGRES_VERSION:-15}"
REDIS_VERSION="${REDIS_VERSION:-7}"

echo ""
echo "Configuration:"
echo "  User: ${KASBAH_USER}"
echo "  Group: ${KASBAH_GROUP}"
echo "  Home: ${KASBAH_HOME}"
echo "  Logs: ${KASBAH_LOG_DIR}"
echo "  Backups: ${KASBAH_BACKUP_DIR}"
echo ""

# Step 1: Create user and group
echo "Step 1: Creating user and group..."
if ! getent group ${KASBAH_GROUP} >/dev/null 2>&1; then
  sudo groupadd ${KASBAH_GROUP}
  log_success "Group created: ${KASBAH_GROUP}"
else
  log_warn "Group already exists: ${KASBAH_GROUP}"
fi

if ! id ${KASBAH_USER} >/dev/null 2>&1; then
  sudo useradd -r -g ${KASBAH_GROUP} -s /bin/bash -d ${KASBAH_HOME} ${KASBAH_USER}
  log_success "User created: ${KASBAH_USER}"
else
  log_warn "User already exists: ${KASBAH_USER}"
fi

# Step 2: Install dependencies
echo ""
echo "Step 2: Installing dependencies..."

# Update package list
sudo apt-get update -qq

# Install Node.js
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
  sudo apt-get install -y nodejs
  log_success "Node.js ${NODE_VERSION} installed"
else
  log_warn "Node.js already installed: $(node --version)"
fi

# Install PostgreSQL
if ! command -v psql >/dev/null 2>&1; then
  sudo apt-get install -y postgresql-${POSTGRES_VERSION} postgresql-contrib-${POSTGRES_VERSION}
  log_success "PostgreSQL ${POSTGRES_VERSION} installed"
else
  log_warn "PostgreSQL already installed: $(psql --version)"
fi

# Install Redis
if ! command -v redis-cli >/dev/null 2>&1; then
  sudo apt-get install -y redis-server
  log_success "Redis ${REDIS_VERSION} installed"
else
  log_warn "Redis already installed: $(redis-cli --version)"
fi

# Install other dependencies
sudo apt-get install -y \
  nginx \
  pm2 \
  git \
  curl \
  wget \
  awscli \
  jq \
  htop \
  iotop \
  fail2ban \
  ufw \
  logrotate

log_success "All dependencies installed"

# Step 3: Create directories
echo ""
echo "Step 3: Creating directories..."

sudo mkdir -p ${KASBAH_HOME}
sudo mkdir -p ${KASBAH_LOG_DIR}
sudo mkdir -p ${KASBAH_BACKUP_DIR}
sudo mkdir -p ${KASBAH_HOME}/logs
sudo mkdir -p ${KASBAH_HOME}/backups
sudo mkdir -p ${KASBAH_HOME}/data

sudo chown -R ${KASBAH_USER}:${KASBAH_GROUP} ${KASBAH_HOME}
sudo chown -R ${KASBAH_USER}:${KASBAH_GROUP} ${KASBAH_LOG_DIR}
sudo chown -R ${KASBAH_USER}:${KASBAH_GROUP} ${KASBAH_BACKUP_DIR}

log_success "Directories created"

# Step 4: Configure PostgreSQL
echo ""
echo "Step 4: Configuring PostgreSQL..."

sudo -u postgres psql -c "CREATE USER ${KASBAH_USER} WITH PASSWORD '${DB_PASSWORD:-kasbah_secure_password}';" 2>/dev/null || log_warn "Database user may already exist"
sudo -u postgres psql -c "CREATE DATABASE kasbah OWNER ${KASBAH_USER};" 2>/dev/null || log_warn "Database may already exist"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE kasbah TO ${KASBAH_USER};"

log_success "PostgreSQL configured"

# Step 5: Configure Redis
echo ""
echo "Step 5: Configuring Redis..."

sudo sed -i 's/bind 127.0.0.1/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
sudo systemctl restart redis-server

log_success "Redis configured"

# Step 6: Clone and install application
echo ""
echo "Step 6: Installing application..."

cd ${KASBAH_HOME}

if [ ! -d ".git" ]; then
  sudo -u ${KASBAH_USER} git clone https://github.com/kasbah-guard/kasbah.git .
  log_success "Repository cloned"
else
  log_warn "Repository already cloned"
fi

# Install Node dependencies
sudo -u ${KASBAH_USER} npm ci --production
log_success "Node dependencies installed"

# Step 7: Configure environment
echo ""
echo "Step 7: Configuring environment..."

cat > ${KASBAH_HOME}/.env <<EOF
# Kasbah Guard Production Environment
NODE_ENV=production
PORT=8000

# Database
DATABASE_URL=postgresql://${KASBAH_USER}:${DB_PASSWORD:-kasbah_secure_password}@localhost:5432/kasbah

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
API_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

# Monitoring
SENTRY_DSN=${SENTRY_DSN:-}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}

# Backup
BACKUP_S3_BUCKET=kasbah-backups
EOF

sudo chown ${KASBAH_USER}:${KASBAH_GROUP} ${KASBAH_HOME}/.env
sudo chmod 600 ${KASBAH_HOME}/.env

log_success "Environment configured"

# Step 8: Configure nginx
echo ""
echo "Step 8: Configuring nginx..."

sudo cat > /etc/nginx/sites-available/kasbah <<EOF
server {
    listen 80;
    server_name api.bekasbah.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    location /health {
        proxy_pass http://localhost:8000/health;
        access_log off;
    }

    location /metrics {
        proxy_pass http://localhost:8000/metrics;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/kasbah /etc/nginx/sites-enabled/kasbah
sudo nginx -t && sudo systemctl restart nginx

log_success "nginx configured"

# Step 9: Configure PM2
echo ""
echo "Step 9: Configuring PM2..."

sudo -u ${KASBAH_USER} pm2 start Kasbah-Core/apps/api/main.py --name kasbah-api --interpreter python3
sudo -u ${KASBAH_USER} pm2 save
sudo pm2 startup systemd -u ${KASBAH_USER} --hp ${KASBAH_HOME}

log_success "PM2 configured"

# Step 10: Configure firewall
echo ""
echo "Step 10: Configuring firewall..."

sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw --force enable

log_success "Firewall configured"

# Step 11: Configure log rotation
echo ""
echo "Step 11: Configuring log rotation..."

sudo cat > /etc/logrotate.d/kasbah <<EOF
${KASBAH_LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 ${KASBAH_USER} ${KASBAH_GROUP}
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}
EOF

log_success "Log rotation configured"

# Step 12: Install backup script
echo ""
echo "Step 12: Installing backup script..."

if [ -f "scripts/automated-backup.sh" ]; then
  sudo cp scripts/automated-backup.sh /usr/local/bin/kasbah-backup
  sudo chmod +x /usr/local/bin/kasbah-backup
  
  # Enable cron
  (crontab -l 2>/dev/null | grep -v kasbah-backup; echo '0 */6 * * * /usr/local/bin/kasbah-backup >> /var/log/kasbah/backup.log 2>&1') | crontab -
  
  log_success "Backup script installed"
else
  log_warn "Backup script not found"
fi

# Step 13: Run health checks
echo ""
echo "Step 13: Running health checks..."

# Check Node.js
node --version >/dev/null && log_success "Node.js running" || log_error "Node.js not working"

# Check PostgreSQL
pg_isready -h localhost >/dev/null && log_success "PostgreSQL running" || log_error "PostgreSQL not working"

# Check Redis
redis-cli ping >/dev/null && log_success "Redis running" || log_error "Redis not working"

# Check nginx
sudo nginx -t >/dev/null && log_success "nginx running" || log_error "nginx not working"

# Check PM2
sudo -u ${KASBAH_USER} pm2 list | grep kasbah-api >/dev/null && log_success "PM2 running" || log_error "PM2 not working"

# Step 14: Final verification
echo ""
echo "Step 14: Final verification..."

curl -s http://localhost:8000/health | jq -r '.status' >/dev/null && log_success "API health check passed" || log_error "API health check failed"

# Summary
echo ""
echo "========================================"
echo "Production Setup Complete!"
echo "========================================"
echo ""
echo "Application URL: https://api.bekasbah.com"
echo "Health Check: https://api.bekasbah.com/health"
echo "Logs: ${KASBAH_LOG_DIR}"
echo "Backups: ${KASBAH_BACKUP_DIR}"
echo ""
echo "Management Commands:"
echo "  Status:     sudo -u ${KASBAH_USER} pm2 status"
echo "  Logs:       sudo -u ${KASBAH_USER} pm2 logs kasbah-api"
echo "  Restart:    sudo -u ${KASBAH_USER} pm2 restart kasbah-api"
echo "  Stop:       sudo -u ${KASBAH_USER} pm2 stop kasbah-api"
echo ""
echo "Next Steps:"
echo "  1. Set up SSL certificate (Let's Encrypt)"
echo "  2. Configure GitHub secrets for CI/CD"
echo "  3. Run load tests"
echo "  4. Monitor for 24 hours"
echo ""
log_success "Production setup complete!"
echo "========================================"
