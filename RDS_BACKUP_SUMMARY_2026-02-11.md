# RDS Database Backup Summary
**Date**: February 11, 2026
**Timestamp**: 20260211-191809

---

## ✅ Backup Status: **SUCCESSFUL**

All 14 databases from the RDS instance `postgres-vulnerability-db` have been successfully backed up and uploaded to S3.

---

## 📊 Backup Statistics

| Metric | Value |
|--------|-------|
| **Total Databases** | 14 |
| **Successful Backups** | 14 |
| **Failed Backups** | 0 |
| **Total Compressed Size** | 313.9 MiB (329,175,980 bytes) |
| **S3 Bucket** | anup-backup |
| **S3 Path** | s3://anup-backup/rds-backups/2026-02-11/ |
| **Region** | ap-south-1 (Mumbai) |

---

## 📁 Backed Up Databases

| Database Name | Compressed Size | Status |
|--------------|----------------|--------|
| cspm | 28.3 KiB | ✅ |
| postgres | 1.1 KiB | ✅ |
| threat_engine_check | 11.3 MiB | ✅ |
| threat_engine_compliance | 5.5 MiB | ✅ |
| threat_engine_datasec | 141.0 KiB | ✅ |
| threat_engine_discoveries | 15.8 MiB | ✅ |
| threat_engine_iam | 1.0 MiB | ✅ |
| threat_engine_inventory | 175.9 KiB | ✅ |
| threat_engine_onboarding | 5.1 KiB | ✅ |
| threat_engine_pythonsdk | 7.2 MiB | ✅ |
| threat_engine_secops | 1.7 MiB | ✅ |
| threat_engine_shared | 4.9 KiB | ✅ |
| threat_engine_threat | 2.1 MiB | ✅ |
| **vulnerability_db** | **268.9 MiB** | ✅ |

---

## 🗂️ S3 Files

All backup files are stored with timestamp `20260211-191809`:

```
s3://anup-backup/rds-backups/2026-02-11/
├── backup-manifest-20260211-191809.json (3.9 KiB)
├── cspm-20260211-191809.sql.gz (28.3 KiB)
├── postgres-20260211-191809.sql.gz (1.1 KiB)
├── threat_engine_check-20260211-191809.sql.gz (11.3 MiB)
├── threat_engine_compliance-20260211-191809.sql.gz (5.5 MiB)
├── threat_engine_datasec-20260211-191809.sql.gz (141.0 KiB)
├── threat_engine_discoveries-20260211-191809.sql.gz (15.8 MiB)
├── threat_engine_iam-20260211-191809.sql.gz (1.0 MiB)
├── threat_engine_inventory-20260211-191809.sql.gz (175.9 KiB)
├── threat_engine_onboarding-20260211-191809.sql.gz (5.1 KiB)
├── threat_engine_pythonsdk-20260211-191809.sql.gz (7.2 MiB)
├── threat_engine_secops-20260211-191809.sql.gz (1.7 MiB)
├── threat_engine_shared-20260211-191809.sql.gz (4.9 KiB)
├── threat_engine_threat-20260211-191809.sql.gz (2.1 MiB)
└── vulnerability_db-20260211-191809.sql.gz (268.9 MiB)
```

---

## 🔍 Backup Manifest

A JSON manifest file has been created with complete backup metadata:
```
s3://anup-backup/rds-backups/2026-02-11/backup-manifest-20260211-191809.json
```

---

## 💾 Local Backup Location

Local backup files are stored at:
```
/tmp/rds-backups-20260211-191809/
```

---

## 🔐 RDS Instance Details

| Parameter | Value |
|-----------|-------|
| **Instance ID** | postgres-vulnerability-db |
| **Endpoint** | postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com |
| **Engine** | PostgreSQL 15.12 |
| **Region** | ap-south-1 (Mumbai) |
| **Status** | Available |

---

## 📝 Backup Method

- **Tool**: Docker with PostgreSQL 15 client (matching server version)
- **Command**: `pg_dump` with `--no-owner`, `--no-acl`, `--clean`, `--if-exists` flags
- **Compression**: gzip
- **Upload**: AWS S3 (ap-south-1 region)

---

## 🔄 Restore Instructions

To restore a specific database from backup:

### Download from S3
```bash
aws s3 cp s3://anup-backup/rds-backups/2026-02-11/<database>-20260211-191809.sql.gz . --region ap-south-1
```

### Decompress
```bash
gunzip <database>-20260211-191809.sql.gz
```

### Restore to PostgreSQL
```bash
psql -h <rds-endpoint> -U postgres -d <database-name> -f <database>-20260211-191809.sql
```

### Example: Restore vulnerability_db
```bash
# Download
aws s3 cp s3://anup-backup/rds-backups/2026-02-11/vulnerability_db-20260211-191809.sql.gz . --region ap-south-1

# Decompress
gunzip vulnerability_db-20260211-191809.sql.gz

# Restore
PGPASSWORD='jtv2BkJF8qoFtAKP' psql \
  -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  -U postgres \
  -d vulnerability_db \
  -f vulnerability_db-20260211-191809.sql
```

---

## 🔄 Automated Backup Script

The backup script is available at:
```
/Users/apple/Desktop/threat-engine/scripts/backup-all-rds-databases.sh
```

### Run Manual Backup
```bash
cd /Users/apple/Desktop/threat-engine
bash scripts/backup-all-rds-databases.sh
```

### Schedule with Cron (Example)
```bash
# Daily backup at 2 AM
0 2 * * * /Users/apple/Desktop/threat-engine/scripts/backup-all-rds-databases.sh
```

---

## 📧 Notes

1. **Security**: Database credentials are embedded in the script. Consider using AWS Secrets Manager for production.
2. **Retention**: Configure S3 lifecycle policies to manage backup retention automatically.
3. **Verification**: Periodically test restore procedures to ensure backup integrity.
4. **Monitoring**: Set up CloudWatch alarms for backup success/failure notifications.

---

## ✅ Verification

List all backups in S3:
```bash
aws s3 ls s3://anup-backup/rds-backups/2026-02-11/ --region ap-south-1 --human-readable
```

Download manifest:
```bash
aws s3 cp s3://anup-backup/rds-backups/2026-02-11/backup-manifest-20260211-191809.json . --region ap-south-1
```

---

**Backup completed successfully on**: 2026-02-11 19:22:39 IST
