# Database Upload Guide

## Overview

The discovery scan now follows a **two-phase approach**:

1. **Scan Phase**: Runs discoveries and writes to NDJSON files only (fast, no DB overhead)
2. **Upload Phase**: Uploads NDJSON files to database (separate, can be retried)

This approach provides:
- ✅ **Faster scans** (no database overhead during scan)
- ✅ **Atomic operations** (all or nothing database updates)
- ✅ **Better error handling** (can retry upload without re-scanning)
- ✅ **Data validation** (inspect files before database commit)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Discovery Scan (Fast, Files Only)                │
├─────────────────────────────────────────────────────────────┤
│  1. Run all discoveries (API calls)                        │
│  2. Write to NDJSON files                                    │
│  3. Track progress in progress.json                          │
│  4. NO database writes                                       │
│  Duration: ~60-70 minutes                                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Database Upload (After Scan Completes)           │
├─────────────────────────────────────────────────────────────┤
│  1. Read all NDJSON files                                     │
│  2. Batch insert to database                                 │
│  3. Single transaction                                       │
│  4. Drift detection                                          │
│  Duration: ~1-2 minutes                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Usage

### Step 1: Run Discovery Scan

```bash
cd /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine
python3 run_full_discovery_all_services.py --confirm
```

**Output:**
- NDJSON files in `engines-output/aws-configScan-engine/output/discovery/{scan_id}/`
- Progress tracking in `progress.json`
- Summary in `summary.json`

**Note:** No database writes during scan - much faster!

---

### Step 2: Upload to Database

After scan completes, upload results to database:

```bash
python3 upload_scan_to_database.py \
  --scan-id discovery_20260121_211958 \
  --hierarchy-id 588989875114 \
  --customer-id default-customer \
  --tenant-id default-tenant \
  --provider aws \
  --hierarchy-type account
```

**Options:**
- `--scan-id`: Scan ID from discovery scan
- `--hierarchy-id`: Account ID or hierarchy identifier
- `--customer-id`: Customer ID (default: default-customer)
- `--tenant-id`: Tenant ID (default: default-tenant)
- `--provider`: Provider name (default: aws)
- `--hierarchy-type`: Hierarchy type (default: account)
- `--output-dir`: Base output directory (optional)

---

## Examples

### Example 1: Upload Latest Scan

```bash
# Find latest scan
ls -t engines-output/aws-configScan-engine/output/discovery/ | head -1

# Upload it
python3 upload_scan_to_database.py \
  --scan-id discovery_20260121_211958 \
  --hierarchy-id 588989875114
```

### Example 2: Upload Specific Scan

```bash
python3 upload_scan_to_database.py \
  --scan-id discovery_20260121_211958 \
  --hierarchy-id 588989875114 \
  --customer-id my-customer \
  --tenant-id my-tenant
```

### Example 3: Retry Failed Upload

If upload fails, simply retry (no need to re-scan):

```bash
# Same command - will retry upload
python3 upload_scan_to_database.py \
  --scan-id discovery_20260121_211958 \
  --hierarchy-id 588989875114
```

---

## Benefits

### 1. Faster Scans
- **Before**: ~85 minutes (with DB writes)
- **After**: ~70 minutes (files only)
- **Speedup**: ~15-20% faster

### 2. Atomic Operations
- All data uploaded in single transaction
- No partial data if upload fails
- Can retry without re-scanning

### 3. Better Error Handling
- Scan failures don't affect database
- Upload failures can be retried
- Clear separation of concerns

### 4. Data Validation
- Inspect NDJSON files before upload
- Validate data structure
- Check for errors

---

## File Structure

```
engines-output/aws-configScan-engine/output/
└── discovery/
    └── discovery_20260121_211958/
        ├── progress.json          # Scan progress
        ├── summary.json            # Scan summary
        ├── errors.json             # Errors (if any)
        ├── iam_discoveries.ndjson  # IAM discoveries
        ├── s3_discoveries.ndjson   # S3 discoveries
        ├── ec2_discoveries.ndjson  # EC2 discoveries
        └── ...                     # Other services
```

---

## Database Upload Process

1. **Read NDJSON Files**: Loads all discovery records from files
2. **Group by Discovery**: Groups records by `discovery_id` for batch processing
3. **Batch Insert**: Uses `store_discoveries_batch()` for efficient inserts
4. **Drift Detection**: Automatically detects configuration changes
5. **Update Scan Status**: Marks scan as `database_uploaded`

---

## Performance

### Upload Performance
- **Files**: ~100 NDJSON files
- **Records**: ~11,000 records
- **Duration**: ~1-2 minutes
- **Rate**: ~5,000-10,000 records/minute

### Parallel Processing
- Configurable via `MAX_UPLOAD_WORKERS` environment variable
- Default: 5 parallel workers
- Can be increased for faster uploads

```bash
export MAX_UPLOAD_WORKERS=10
python3 upload_scan_to_database.py ...
```

---

## Troubleshooting

### Issue: "No scan directory found"

**Solution**: Check scan ID and output directory:
```bash
ls engines-output/aws-configScan-engine/output/discovery/
```

### Issue: "Database connection failed"

**Solution**: Check database configuration:
```bash
# Check database is running
psql -d cspm_db -c "SELECT 1"

# Check environment variables
echo $CSPM_DB_HOST
echo $CSPM_DB_NAME
```

### Issue: "Upload errors"

**Solution**: Check error details in output:
```bash
# Errors are logged to console
# Check specific file for issues
cat engines-output/.../errors.json
```

---

## Integration with Workflow

### Automated Workflow

```python
# 1. Run discovery scan
discovery_scan_id = discovery_engine.run_discovery_for_all_services(...)

# 2. Upload to database
upload_engine = DatabaseUploadEngine(db_manager)
stats = upload_engine.upload_scan_to_database(
    scan_id=discovery_scan_id,
    output_dir=output_dir,
    ...
)
```

### Manual Workflow

1. Run discovery scan (files only)
2. Review NDJSON files
3. Upload to database when ready
4. Can retry upload if needed

---

## Best Practices

1. **Always validate files** before upload
2. **Keep NDJSON files** as backup/audit trail
3. **Upload after scan completes** (not during)
4. **Retry failed uploads** (no need to re-scan)
5. **Monitor upload progress** via logs

---

**Last Updated**: 2026-01-21

