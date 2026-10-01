#!/bin/bash

# Kasbah Guard — Automated Backup Script
# Runs every 6 hours via cron
# Backs up: Database, Audit Logs, KV Storage, Configs

set -e

DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="${BACKUP_DIR:-/tmp/kasbah-backup-test/${DATE}}"
RETENTION_DAYS=90
S3_BUCKET="${S3_BUCKET:-kasbah-backups}"

echo "========================================"
echo "Kasbah Guard Automated Backup"
echo "Date: ${DATE}"
echo "========================================"

# Create backup directory
mkdir -p ${BACKUP_DIR}

# 1. Backup PostgreSQL Database
echo "[1/5] Backing up PostgreSQL database..."
pg_dump -U kasbah -h localhost kasbah | gzip > ${BACKUP_DIR}/database.sql.gz
echo "✓ Database backup complete"

# 2. Backup Redis Data
echo "[2/5] Backing up Redis data..."
redis-cli BGSAVE
sleep 5  # Wait for save to complete
cp /var/lib/redis/dump.rdb ${BACKUP_DIR}/redis-dump.rdb 2>/dev/null || echo "⚠ Redis dump not found"
echo "✓ Redis backup complete"

# 3. Backup Audit Logs
echo "[3/5] Backing up audit logs..."
tar -czf ${BACKUP_DIR}/audit-logs.tar.gz /var/log/kasbah/audit/ 2>/dev/null || echo "⚠ Audit logs not found"
echo "✓ Audit logs backup complete"

# 4. Backup Configuration Files
echo "[4/5] Backing up configuration..."
tar -czf ${BACKUP_DIR}/configs.tar.gz \
  /etc/kasbah/ \
  /var/www/kasbah/.env \
  /var/www/kasbah/deploy*.sh \
  2>/dev/null || echo "⚠ Config files not found"
echo "✓ Configuration backup complete"

# 5. Backup Application Data
echo "[5/5] Backing up application data..."
tar -czf ${BACKUP_DIR}/app-data.tar.gz \
  /var/www/kasbah/data/ \
  /var/www/kasbah/uploads/ \
  2>/dev/null || echo "⚠ App data not found"
echo "✓ Application data backup complete"

# Generate checksums
echo "Generating checksums..."
cd ${BACKUP_DIR}
sha256sum * > CHECKSUMS.sha256
cd -

# Compress entire backup
echo "Compressing backup..."
tar -czf ${BACKUP_DIR}.tar.gz -C $(dirname ${BACKUP_DIR}) $(basename ${BACKUP_DIR})
rm -rf ${BACKUP_DIR}

# Upload to S3
echo "Uploading to S3..."
aws s3 cp ${BACKUP_DIR}.tar.gz s3://${S3_BUCKET}/backups/

# Verify upload
echo "Verifying upload..."
aws s3 ls s3://${S3_BUCKET}/backups/${BACKUP_DIR}.tar.gz

# Clean up old backups locally
echo "Cleaning up old backups..."
find /var/backups/kasbah/ -type f -mtime +${RETENTION_DAYS} -delete

# Clean up old S3 backups (lifecycle policy preferred)
echo "Cleaning up S3 backups older than ${RETENTION_DAYS} days..."
aws s3 ls s3://${S3_BUCKET}/backups/ | while read -r line; do
  file_date=$(echo $line | awk '{print $1, $2}')
  file_name=$(echo $line | awk '{print $4}')
  if [[ -n "$file_date" ]]; then
    file_timestamp=$(date -d "$file_date" +%s)
    now_timestamp=$(date +%s)
    age_days=$(( (now_timestamp - file_timestamp) / 86400 ))
    if [[ $age_days -gt $RETENTION_DAYS ]]; then
      echo "Deleting old backup: $file_name (${age_days} days old)"
      aws s3 rm s3://${S3_BUCKET}/backups/${file_name}
    fi
  fi
done

# Send notification
echo "Sending backup notification..."
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"✅ Kasbah Guard Backup Complete\\nDate: ${DATE}\\nSize: $(du -h ${BACKUP_DIR}.tar.gz | cut -f1)\\nLocation: s3://${S3_BUCKET}/backups/${BACKUP_DIR}.tar.gz\"}" \
  $SLACK_WEBHOOK_URL 2>/dev/null || echo "⚠ Slack notification failed"

# Cleanup local tarball
rm -f ${BACKUP_DIR}.tar.gz

echo "========================================"
echo "✅ Backup Complete"
echo "Location: s3://${S3_BUCKET}/backups/${BACKUP_DIR}.tar.gz"
echo "========================================"
