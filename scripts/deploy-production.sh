#!/bin/bash

# Kasbah Guard — Production Deployment Script
# Usage: ./deploy-production.sh [environment]
# Environments: staging, production

set -e

ENVIRONMENT=${1:-staging}
DATE=$(date +%Y%m%d-%H%M%S)

echo "========================================"
echo "Kasbah Guard Production Deployment"
echo "Environment: $ENVIRONMENT"
echo "Date: $DATE"
echo "========================================"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js not found"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        log_error "npm not found"
        exit 1
    fi
    
    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        log_info "Docker found: $(docker --version)"
    else
        log_warn "Docker not found - some deployments will be unavailable"
    fi
    
    log_info "Prerequisites check passed"
}

run_tests() {
    log_info "Running tests..."
    
    # Phase 1 tests
    cd Kasbah-site/api/src/moats
    npm test -- phase1-complete.test.js || exit 1
    
    # Phase 2 tests
    npm test -- phase2-complete.test.js || exit 1
    
    # Phase 3 tests
    npm test -- phase3-complete.test.js || exit 1
    
    # Phase 4 tests
    npm test -- phase4-complete.test.js || exit 1
    
    # Phase 5 tests
    cd ../../kasbah-guard-dist/apps
    npm test -- __tests__/phase5-products.test.js || exit 1
    
    log_info "All tests passed"
}

deploy_slack_guard() {
    log_info "Deploying Slack Guard..."
    
    cd Kasbah-site/kasbah-guard-dist/apps/slack-guard
    
    # Install dependencies
    npm install --production
    
    # Set environment
    export SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN
    export SLACK_APP_TOKEN=$SLACK_APP_TOKEN
    export SENTRY_DSN=$SENTRY_DSN
    export NODE_ENV=$ENVIRONMENT
    
    # Start service (using pm2 in production)
    if [ "$ENVIRONMENT" = "production" ]; then
        pm2 start src/slack-guard-complete.js --name slack-guard
        pm2 save
    else
        npm start &
    fi
    
    # Health check
    sleep 5
    curl -f http://localhost:3000/health || exit 1
    
    log_info "Slack Guard deployed"
}

deploy_discord_guardian() {
    log_info "Deploying Discord Guardian..."
    
    cd Kasbah-site/kasbah-guard-dist/apps/discord-guard
    
    # Install dependencies
    npm install --production
    
    # Set environment
    export DISCORD_BOT_TOKEN=$DISCORD_BOT_TOKEN
    export SENTRY_DSN=$SENTRY_DSN
    export NODE_ENV=$ENVIRONMENT
    
    # Start service
    if [ "$ENVIRONMENT" = "production" ]; then
        pm2 start src/discord-guardian-complete.js --name discord-guardian
        pm2 save
    else
        npm start &
    fi
    
    # Health check
    sleep 5
    curl -f http://localhost:3001/health || exit 1
    
    log_info "Discord Guardian deployed"
}

deploy_hospital_guardian() {
    log_info "Deploying Hospital Guardian..."
    
    cd Kasbah-site/kasbah-guard-dist/apps/hospital-guard
    
    # Install dependencies
    npm install --production
    
    # Set environment
    export HIPAA_MODE=true
    export AUDIT_RETENTION_YEARS=6
    export SENTRY_DSN=$SENTRY_DSN
    export NODE_ENV=$ENVIRONMENT
    
    # Start service
    if [ "$ENVIRONMENT" = "production" ]; then
        pm2 start src/hospital-guardian-complete.js --name hospital-guardian
        pm2 save
    else
        npm start &
    fi
    
    # Health check
    sleep 5
    curl -f http://localhost:3002/health || exit 1
    
    log_info "Hospital Guardian deployed"
}

deploy_legal_shield() {
    log_info "Deploying Legal Shield..."
    
    cd Kasbah-site/kasbah-guard-dist/apps/legal-shield
    
    # Install dependencies
    npm install --production
    
    # Set environment
    export LAW_FIRM_DOMAIN=$LAW_FIRM_DOMAIN
    export ABA_COMPLIANCE=true
    export SENTRY_DSN=$SENTRY_DSN
    export NODE_ENV=$ENVIRONMENT
    
    # Start service
    if [ "$ENVIRONMENT" = "production" ]; then
        pm2 start src/legal-shield-complete.js --name legal-shield
        pm2 save
    else
        npm start &
    fi
    
    # Health check
    sleep 5
    curl -f http://localhost:3003/health || exit 1
    
    log_info "Legal Shield deployed"
}

publish_npm_packages() {
    log_info "Publishing npm packages..."
    
    if [ "$ENVIRONMENT" != "production" ]; then
        log_warn "Skipping npm publish for non-production environment"
        return
    fi
    
    # Detector Kernel
    cd Kasbah-site/kasbah-guard-dist/packages/detector
    npm publish --access public
    
    # API Guard
    cd ../../apps/api-guard
    npm publish --access public
    
    # Slack Guard
    cd ../slack-guard
    npm publish --access public
    
    # Discord Guardian
    cd ../discord-guard
    npm publish --access public
    
    log_info "npm packages published"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check all health endpoints
    endpoints=(
        "http://localhost:3000/health"  # Slack Guard
        "http://localhost:3001/health"  # Discord Guardian
        "http://localhost:3002/health"  # Hospital Guardian
        "http://localhost:3003/health"  # Legal Shield
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f "$endpoint" > /dev/null 2>&1; then
            log_info "✓ $endpoint"
        else
            log_error "✗ $endpoint"
            exit 1
        fi
    done
    
    log_info "Deployment verified"
}

cleanup() {
    log_info "Cleaning up..."
    
    # Remove old npm packages
    find . -name "*.tgz" -mtime +7 -delete
    
    # Clear npm cache
    npm cache clean --force
    
    log_info "Cleanup complete"
}

# Main deployment flow
main() {
    check_prerequisites
    run_tests
    deploy_slack_guard
    deploy_discord_guardian
    deploy_hospital_guardian
    deploy_legal_shield
    publish_npm_packages
    verify_deployment
    cleanup
    
    echo ""
    echo "========================================"
    echo -e "${GREEN}Deployment Complete!${NC}"
    echo "Environment: $ENVIRONMENT"
    echo "Date: $(date)"
    echo ""
    echo "Services running:"
    echo "  - Slack Guard: http://localhost:3000"
    echo "  - Discord Guardian: http://localhost:3001"
    echo "  - Hospital Guardian: http://localhost:3002"
    echo "  - Legal Shield: http://localhost:3003"
    echo "========================================"
}

# Run main function
main
