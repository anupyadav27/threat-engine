# Hybrid Check Engine Implementation

## Overview

The check engine now supports **hybrid mode** - it can run checks using either:
- **NDJSON files** (local testing, no database required)
- **PostgreSQL database** (production, multi-tenant SaaS)

## Features

✅ **Auto-detection**: Automatically chooses mode based on environment  
✅ **Backward compatible**: Existing database code still works  
✅ **Local testing**: No database setup required for development  
✅ **Production ready**: Uses database with tenant isolation  
✅ **Same evaluation logic**: `extract_value` handles nested paths in both modes  

---

## Usage

### 1. NDJSON Mode (Local Testing)

```python
from engine.check_engine import CheckEngine

# No database needed
check_engine = CheckEngine(use_ndjson=True)

results = check_engine.run_check_scan(
    scan_id="discovery_20260122_080533",
    customer_id="test_customer",
    tenant_id="test_tenant",
    provider="aws",
    hierarchy_id="039612851381",
    hierarchy_type="account",
    services=["s3", "ec2"]
)
```

### 2. Database Mode (Production)

```python
from engine.database_manager import DatabaseManager
from engine.check_engine import CheckEngine

db = DatabaseManager()
check_engine = CheckEngine(db_manager=db, use_ndjson=False)

results = check_engine.run_check_scan(
    scan_id="discovery_20260122_080533",
    customer_id="prod_customer",
    tenant_id="prod_tenant",
    provider="aws",
    hierarchy_id="039612851381",
    hierarchy_type="account",
    services=["s3", "ec2"]
)
```

### 3. Auto-Detect Mode

```python
from engine.database_manager import DatabaseManager
from engine.check_engine import CheckEngine

# Try database first, fallback to NDJSON
db = DatabaseManager()  # May fail if not configured
check_engine = CheckEngine(db_manager=db)  # Auto-detects mode

# Or use environment variable
import os
os.environ['CHECK_MODE'] = 'ndjson'  # or 'database'
check_engine = CheckEngine(db_manager=db)
```

---

## Environment Configuration

Set environment variables to control mode:

```bash
# Use NDJSON mode
export CHECK_MODE=ndjson

# Use Database mode
export CHECK_MODE=database

# Or in .env file
CHECK_MODE=ndjson
```

---

## How It Works

### NDJSON Mode

1. **Load Discoveries**: Reads from NDJSON files in `engines-output/aws-configScan-engine/output/discoveries/{scan_id}/discovery/`
2. **Filter by Discovery ID**: Matches `discovery_id` and `hierarchy_id` from NDJSON records
3. **Evaluate Checks**: Uses same `extract_value` and `evaluate_condition` logic
4. **Store Results**: Saves to memory, then exports to NDJSON files

### Database Mode

1. **Load Discoveries**: Queries PostgreSQL database with tenant isolation
2. **Filter by Discovery ID**: Uses SQL WHERE clauses
3. **Evaluate Checks**: Uses same `extract_value` and `evaluate_condition` logic
4. **Store Results**: Saves to database AND exports to NDJSON files

---

## Nested Path Support

Both modes support nested paths in check conditions:

```yaml
# Example: Check S3 bucket encryption
- rule_id: aws.s3.bucket.encryption_enabled
  for_each: aws.s3.list_buckets
  conditions:
    var: item._dependent_data.get_bucket_encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
    op: exists
    value: null

# Example: Check public access block
- rule_id: aws.s3.bucket.public_access_blocked
  for_each: aws.s3.list_buckets
  conditions:
    all:
    - var: item._dependent_data.get_public_access_block.PublicAccessBlockConfiguration.BlockPublicAcls
      op: equals
      value: true
```

The `extract_value()` function handles:
- Dot notation: `item.field.subfield`
- Array indices: `item.array[0]`
- Nested dependent data: `item._dependent_data.discovery_name.field`

---

## Testing

Run the test script:

```bash
cd configScan_engines/aws-configScan-engine
python3 test_hybrid_checks.py
```

This will:
1. Test auto-detect mode
2. Test NDJSON mode (local)
3. Test database mode (if database is configured)

---

## Integration with Scan Controller

The `ScanController` now supports hybrid mode:

```python
from engine.scan_controller import ScanController
from engine.database_manager import DatabaseManager

# NDJSON mode
controller = ScanController(db_manager=None, use_ndjson=True)

# Database mode
db = DatabaseManager()
controller = ScanController(db_manager=db, use_ndjson=False)

# Run checks
results = controller.run_scan(
    customer_id="test",
    tenant_id="test",
    provider="aws",
    hierarchy_id="039612851381",
    hierarchy_type="account",
    scan_mode="check_only",
    discovery_scan_id="discovery_20260122_080533",
    services=["s3"],
    use_ndjson=True  # Override mode
)
```

---

## Output Structure

Both modes produce the same output structure:

```
engines-output/aws-configScan-engine/output/checks/
└── check_{check_scan_id}_{timestamp}/
    ├── findings.ndjson      # All check results
    └── summary.json         # Summary statistics
```

---

## Best Practices

1. **Local Development**: Use NDJSON mode (no database setup)
2. **Production**: Use database mode (multi-tenant isolation)
3. **CI/CD**: Use NDJSON mode for faster tests
4. **Staging**: Use database mode to test production-like environment

---

## Migration Guide

### From Database-Only to Hybrid

No changes needed! The existing code will continue to work:

```python
# Old code (still works)
db = DatabaseManager()
check_engine = CheckEngine(db_manager=db)
results = check_engine.run_check_scan(...)

# New code (explicit mode)
check_engine = CheckEngine(db_manager=db, use_ndjson=False)  # Same as above
```

### Adding NDJSON Support

Simply initialize without database:

```python
# New: NDJSON mode
check_engine = CheckEngine(use_ndjson=True)
results = check_engine.run_check_scan(...)
```

---

## Troubleshooting

### NDJSON Mode Issues

**Problem**: "No discoveries found"  
**Solution**: Check that NDJSON files exist in `engines-output/aws-configScan-engine/output/discoveries/{scan_id}/discovery/`

**Problem**: "Discoveries directory not found"  
**Solution**: Ensure discovery scan completed and files were generated

### Database Mode Issues

**Problem**: "DatabaseManager required"  
**Solution**: Initialize with `db_manager=DatabaseManager()`

**Problem**: "Database connection failed"  
**Solution**: Check database configuration in environment variables or `database/secrets/db_config.json`

---

## Summary

✅ **Hybrid mode implemented**  
✅ **Backward compatible**  
✅ **Ready for local testing and production**  
✅ **Same evaluation logic for both modes**  
✅ **Nested path support works in both modes**

---

**Last Updated**: 2026-01-22
