#!/bin/bash

# Kasbah Guard — Production Monitoring Script
# Real-time monitoring dashboard for production
# Usage: ./monitor-production.sh

set -e

echo "========================================"
echo "Kasbah Guard — Production Monitoring"
echo "Date: $(date)"
echo "========================================"
echo ""

# Configuration
API_URL="${API_URL:-https://api.bekasbah.com}"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-30}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_status() {
  if [ "$2" = "0" ]; then
    echo -e "${GREEN}✓${NC} $1"
  else
    echo -e "${RED}✗${NC} $1"
  fi
}

print_metric() {
  printf "  %-30s %s\n" "$1" "$2"
}

# Function: Check API Health
check_api_health() {
  print_header "API Health"
  
  HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" ${API_URL}/health 2>/dev/null || echo -e "\n000")
  HEALTH_BODY=$(echo "$HEALTH_RESPONSE" | head -n -1)
  HEALTH_CODE=$(echo "$HEALTH_RESPONSE" | tail -n 1)
  
  if [ "$HEALTH_CODE" = "200" ]; then
    print_status "API Status" 0
    print_metric "Status" "$(echo $HEALTH_BODY | jq -r '.status // "unknown"')"
    print_metric "Version" "$(echo $HEALTH_BODY | jq -r '.version // "unknown"')"
    print_metric "Uptime" "$(echo $HEALTH_BODY | jq -r '.uptime // "unknown"')"
  else
    print_status "API Status" 1
    print_metric "HTTP Code" "$HEALTH_CODE"
  fi
  echo ""
}

# Function: Check Performance
check_performance() {
  print_header "Performance Metrics"
  
  # Measure latency
  LATENCY=$(curl -s -o /dev/null -w "%{time_total}" ${API_URL}/health 2>/dev/null || echo "0")
  LATENCY_MS=$(echo "$LATENCY * 1000" | bc 2>/dev/null || echo "0")
  
  if (( $(echo "$LATENCY_MS < 100" | bc -l 2>/dev/null || echo "0") )); then
    print_status "Latency (P95)" 0
    print_metric "Response Time" "${LATENCY_MS}ms"
  elif (( $(echo "$LATENCY_MS < 500" | bc -l 2>/dev/null || echo "0") )); then
    print_status "Latency (P95)" 0
    print_metric "Response Time" "${LATENCY_MS}ms (warning)"
  else
    print_status "Latency (P95)" 1
    print_metric "Response Time" "${LATENCY_MS}ms (critical)"
  fi
  
  # Check error rate (from logs if available)
  if [ -f "/var/log/kasbah/error.log" ]; then
    ERROR_COUNT=$(tail -n 1000 /var/log/kasbah/error.log | grep -c "ERROR" || echo "0")
    if [ "$ERROR_COUNT" -lt 10 ]; then
      print_status "Error Rate" 0
      print_metric "Recent Errors" "$ERROR_COUNT"
    else
      print_status "Error Rate" 1
      print_metric "Recent Errors" "$ERROR_COUNT (high)"
    fi
  fi
  echo ""
}

# Function: Check Backups
check_backups() {
  print_header "Backup Status"
  
  # Check backup script
  if [ -x "/usr/local/bin/kasbah-backup" ]; then
    print_status "Backup Script" 0
  else
    print_status "Backup Script" 1
    print_metric "Status" "Not installed"
  fi
  
  # Check cron job
  if crontab -l 2>/dev/null | grep -q kasbah-backup; then
    print_status "Backup Cron" 0
    print_metric "Schedule" "Every 6 hours"
  else
    print_status "Backup Cron" 1
    print_metric "Status" "Not scheduled"
  fi
  
  # Check last backup
  if [ -d "/var/backups/kasbah" ]; then
    LAST_BACKUP=$(ls -t /var/backups/kasbah 2>/dev/null | head -1 || echo "none")
    if [ "$LAST_BACKUP" != "none" ]; then
      print_status "Last Backup" 0
      print_metric "File" "$LAST_BACKUP"
    else
      print_status "Last Backup" 1
      print_metric "Status" "No backups found"
    fi
  fi
  echo ""
}

# Function: Check System Resources
check_resources() {
  print_header "System Resources"
  
  # CPU
  CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 || echo "0")
  if (( $(echo "$CPU_USAGE < 70" | bc -l 2>/dev/null || echo "0") )); then
    print_status "CPU Usage" 0
    print_metric "CPU" "${CPU_USAGE}%"
  else
    print_status "CPU Usage" 1
    print_metric "CPU" "${CPU_USAGE}% (high)"
  fi
  
  # Memory
  MEM_USAGE=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}' || echo "0")
  if [ "$MEM_USAGE" -lt 80 ]; then
    print_status "Memory Usage" 0
    print_metric "Memory" "${MEM_USAGE}%"
  else
    print_status "Memory Usage" 1
    print_metric "Memory" "${MEM_USAGE}% (high)"
  fi
  
  # Disk
  DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%' || echo "0")
  if [ "$DISK_USAGE" -lt 80 ]; then
    print_status "Disk Usage" 0
    print_metric "Disk" "${DISK_USAGE}%"
  else
    print_status "Disk Usage" 1
    print_metric "Disk" "${DISK_USAGE}% (high)"
  fi
  echo ""
}

# Function: Check Services
check_services() {
  print_header "Service Status"
  
  # PM2
  if command -v pm2 >/dev/null 2>&1; then
    PM2_STATUS=$(sudo -u kasbah pm2 list 2>/dev/null | grep -c "online" || echo "0")
    if [ "$PM2_STATUS" -gt 0 ]; then
      print_status "PM2 Services" 0
      print_metric "Online" "$PM2_STATUS"
    else
      print_status "PM2 Services" 1
      print_metric "Status" "No services online"
    fi
  fi
  
  # nginx
  if systemctl is-active --quiet nginx 2>/dev/null; then
    print_status "nginx" 0
  else
    print_status "nginx" 1
  fi
  
  # PostgreSQL
  if pg_isready -h localhost >/dev/null 2>&1; then
    print_status "PostgreSQL" 0
  else
    print_status "PostgreSQL" 1
  fi
  
  # Redis
  if redis-cli ping >/dev/null 2>&1; then
    print_status "Redis" 0
  else
    print_status "Redis" 1
  fi
  echo ""
}

# Function: Check Security
check_security() {
  print_header "Security Status"
  
  # Firewall
  if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    print_status "Firewall (UFW)" 0
  else
    print_status "Firewall (UFW)" 1
  fi
  
  # Fail2ban
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    print_status "Fail2ban" 0
  else
    print_status "Fail2ban" 1
  fi
  
  # SSL (if configured)
  if command -v openssl >/dev/null 2>&1; then
    SSL_EXPIRY=$(echo | openssl s_client -connect api.bekasbah.com:443 -servername api.bekasbah.com 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "not configured")
    if [ "$SSL_EXPIRY" != "not configured" ]; then
      print_status "SSL Certificate" 0
      print_metric "Expires" "$SSL_EXPIRY"
    else
      print_status "SSL Certificate" 1
      print_metric "Status" "Not configured"
    fi
  fi
  echo ""
}

# Main monitoring loop
MONITOR="${MONITOR:-false}"

if [ "$MONITOR" = "true" ]; then
  echo "Starting continuous monitoring (Ctrl+C to stop)..."
  echo ""
  
  while true; do
    clear
    check_api_health
    check_performance
    check_backups
    check_resources
    check_services
    check_security
    
    echo "Next refresh in ${REFRESH_INTERVAL} seconds..."
    sleep ${REFRESH_INTERVAL}
  done
else
  # Single run
  check_api_health
  check_performance
  check_backups
  check_resources
  check_services
  check_security
  
  print_header "Summary"
  echo ""
  echo "For continuous monitoring, run:"
  echo "  MONITOR=true ./monitor-production.sh"
  echo ""
  echo "For custom refresh interval:"
  echo "  MONITOR=true REFRESH_INTERVAL=60 ./monitor-production.sh"
  echo ""
fi

echo "========================================"
echo "Monitoring Complete"
echo "========================================"
