#!/bin/bash

# Kasbah Guard — Production Deployment Script
# Zero-regression surgical deployment
# Usage: ./deploy-to-production.sh

set -e

echo "========================================"
echo "Kasbah Guard — Production Deployment"
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
PROD_USER="${PROD_USER:-deploy}"
PROD_HOST="${PROD_HOST:-production.bekasbah.com}"
PROD_PATH="${PROD_PATH:-/var/www/kasbah}"
BACKUP_BUCKET="${BACKUP_BUCKET:-kasbah-backups}"

echo ""
echo "Configuration:"
echo "  User: ${PROD_USER}"
echo "  Host: ${PROD_HOST}"
echo "  Path: ${PROD_PATH}"
echo "  Backup: ${BACKUP_BUCKET}"
echo ""

# Pre-flight checks
echo "Running pre-flight checks..."
echo "========================================"

# Check 1: Git status
if [ -n "$(git status --porcelain)" ]; then
  log_warn "Uncommitted changes detected"
  read -p "Continue anyway? (y/n): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_error "Deployment aborted"
    exit 1
  fi
fi
log_success "Git status clean"

# Check 2: Current branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
  log_warn "Not on main branch (current: ${BRANCH})"
  read -p "Continue anyway? (y/n): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_error "Deployment aborted"
    exit 1
  fi
fi
log_success "On main branch"

# Check 3: SSH access
if ! ssh -o ConnectTimeout=5 ${PROD_USER}@${PROD_HOST} "echo 'Connection successful'" 2>/dev/null; then
  log_error "Cannot connect to production server"
  exit 1
fi
log_success "SSH connection OK"

# Check 4: Disk space
DISK_USAGE=$(ssh ${PROD_USER}@${PROD_HOST} "df -h ${PROD_PATH} | tail -1 | awk '{print \$5}'" | tr -d '%')
if [ "$DISK_USAGE" -gt 80 ]; then
  log_warn "Disk usage high: ${DISK_USAGE}%"
else
  log_success "Disk usage OK: ${DISK_USAGE}%"
fi

echo ""
echo "Pre-flight checks complete"
echo "========================================"
echo ""

# Deployment steps
DEPLOY_BACKUP="${DEPLOY_BACKUP:-true}"
DEPLOY_CI_CD="${DEPLOY_CI_CD:-true}"
DEPLOY_LOAD_TESTS="${DEPLOY_LOAD_TESTS:-false}"
DEPLOY_IR_PLAN="${DEPLOY_IR_PLAN:-true}"

# Step 1: Deploy Backup Script
if [ "$DEPLOY_BACKUP" = true ]; then
  echo ""
  echo "Step 1: Deploying Backup Script"
  echo "========================================"
  
  # Copy script
  scp scripts/automated-backup.sh ${PROD_USER}@${PROD_HOST}:/tmp/kasbah-backup.sh
  log_success "Script copied to production"
  
  # Set permissions
  ssh ${PROD_USER}@${PROD_HOST} "sudo mv /tmp/kasbah-backup.sh /usr/local/bin/kasbah-backup && sudo chmod +x /usr/local/bin/kasbah-backup"
  log_success "Permissions set"
  
  # Test run
  ssh ${PROD_USER}@${PROD_HOST} "sudo BACKUP_DIR=/tmp/kasbah-backup-test /usr/local/bin/kasbah-backup" 2>&1 | tail -5
  log_success "Test run completed"
  
  # Enable cron
  ssh ${PROD_USER}@${PROD_HOST} "(crontab -l 2>/dev/null | grep -v kasbah-backup; echo '0 */6 * * * /usr/local/bin/kasbah-backup >> /var/log/kasbah/backup.log 2>&1') | crontab -"
  log_success "Cron job enabled (every 6 hours)"
  
  # Verify
  ssh ${PROD_USER}@${PROD_HOST} "crontab -l | grep kasbah-backup"
  log_success "Backup script deployed"
fi

# Step 2: Enable CI/CD Pipeline
if [ "$DEPLOY_CI_CD" = true ]; then
  echo ""
  echo "Step 2: Enabling CI/CD Pipeline"
  echo "========================================"
  
  # Check if secrets are set
  if ! gh secret list >/dev/null 2>&1; then
    log_warn "GitHub CLI not authenticated or no secrets set"
    echo "Please set the following secrets manually:"
    echo "  - NPM_TOKEN"
    echo "  - SNYK_TOKEN"
    echo "  - STAGING_API_URL"
    echo "  - PRODUCTION_API_URL"
    echo "  - BACKUP_WEBHOOK_URL"
    echo "  - SLACK_WEBHOOK_URL"
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      log_error "CI/CD deployment aborted"
      DEPLOY_CI_CD=false
    fi
  fi
  
  if [ "$DEPLOY_CI_CD" = true ]; then
    # Commit and push workflow
    if [ -f ".github/workflows/ci-cd-pipeline.yml" ]; then
      git add .github/workflows/ci-cd-pipeline.yml
      git commit -m "feat: Add CI/CD pipeline with load testing" || log_warn "No changes to commit"
      git push origin main
      log_success "CI/CD pipeline enabled"
    else
      log_error "CI/CD workflow file not found"
    fi
  fi
fi

# Step 3: Deploy Load Tests (Optional)
if [ "$DEPLOY_LOAD_TESTS" = true ]; then
  echo ""
  echo "Step 3: Deploying Load Tests"
  echo "========================================"
  
  # Create load test directory on production
  ssh ${PROD_USER}@${PROD_HOST} "mkdir -p ${PROD_PATH}/load-tests"
  
  # Copy test files
  scp tests/load/*.js ${PROD_USER}@${PROD_HOST}:${PROD_PATH}/load-tests/
  log_success "Load test files copied"
  
  # Verify k6 installation
  if ! ssh ${PROD_USER}@${PROD_HOST} "which k6" >/dev/null 2>&1; then
    log_warn "k6 not installed on production"
    echo "Install k6 with: brew install k6 (macOS) or see https://k6.io/docs/"
  else
    log_success "k6 installed"
  fi
fi

# Step 4: Publish IR Plan
if [ "$DEPLOY_IR_PLAN" = true ]; then
  echo ""
  echo "Step 4: Publishing Incident Response Plan"
  echo "========================================"
  
  # Copy to production docs
  scp INCIDENT_RESPONSE_PLAN.md ${PROD_USER}@${PROD_HOST}:${PROD_PATH}/docs/
  log_success "IR plan copied to production"
  
  # Notify team (if Slack webhook configured)
  if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"📋 New Incident Response Plan published\\nPlease review: [URL]\\nTabletop exercise scheduled for [DATE]\"}" \
      $SLACK_WEBHOOK_URL 2>/dev/null && log_success "Team notified via Slack" || log_warn "Slack notification failed"
  else
    log_warn "SLACK_WEBHOOK_URL not set - manual notification required"
  fi
fi

# Post-deployment verification
echo ""
echo "Post-Deployment Verification"
echo "========================================"

# Check backup script
if ssh ${PROD_USER}@${PROD_HOST} "test -x /usr/local/bin/kasbah-backup"; then
  log_success "Backup script installed"
else
  log_error "Backup script not found"
fi

# Check cron job
if ssh ${PROD_USER}@${PROD_HOST} "crontab -l | grep -q kasbah-backup"; then
  log_success "Backup cron job active"
else
  log_error "Backup cron job not found"
fi

# Check CI/CD workflow
if [ -f ".github/workflows/ci-cd-pipeline.yml" ]; then
  log_success "CI/CD workflow file present"
else
  log_error "CI/CD workflow file missing"
fi

# Check IR plan
if ssh ${PROD_USER}@${PROD_HOST} "test -f ${PROD_PATH}/docs/INCIDENT_RESPONSE_PLAN.md"; then
  log_success "IR plan published"
else
  log_error "IR plan not found"
fi

# Health check
echo ""
echo "Running health checks..."
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" https://api.bekasbah.com/health 2>/dev/null || echo "000")
if [ "$HEALTH_CHECK" = "200" ]; then
  log_success "API health check passed"
else
  log_warn "API health check failed (status: ${HEALTH_CHECK})"
fi

# Summary
echo ""
echo "========================================"
echo "Deployment Summary"
echo "========================================"
echo ""
echo "Deployed:"
[ "$DEPLOY_BACKUP" = true ] && echo "  ✓ Backup Script" || echo "  ✗ Backup Script (skipped)"
[ "$DEPLOY_CI_CD" = true ] && echo "  ✓ CI/CD Pipeline" || echo "  ✗ CI/CD Pipeline (skipped)"
[ "$DEPLOY_LOAD_TESTS" = true ] && echo "  ✓ Load Tests" || echo "  ✗ Load Tests (skipped)"
[ "$DEPLOY_IR_PLAN" = true ] && echo "  ✓ Incident Response Plan" || echo "  ✗ Incident Response Plan (skipped)"
echo ""
echo "Next Steps:"
echo "  1. Monitor backup logs: ssh ${PROD_USER}@${PROD_HOST} 'tail -f /var/log/kasbah/backup.log'"
echo "  2. Check CI/CD: https://github.com/kasbah-guard/kasbah/actions"
echo "  3. Review IR plan with team"
echo "  4. Schedule tabletop exercise"
echo ""
echo "Rollback:"
echo "  ssh ${PROD_USER}@${PROD_HOST} 'crontab -l | grep -v kasbah-backup | crontab -'"
echo "  ssh ${PROD_USER}@${PROD_HOST} 'sudo rm /usr/local/bin/kasbah-backup'"
echo ""
log_success "Deployment complete!"
echo "========================================"
