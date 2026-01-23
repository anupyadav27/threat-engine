# Check Results API - Quick Start Guide

## Overview

The threat-engine now includes a complete API for viewing configScan check results.

## Architecture

```
ConfigScan Engine → PostgreSQL → Threat Engine API → UI
                    (check_results table)
```

## Quick Start

### 1. Start API Server

```bash
cd /Users/apple/Desktop/threat-engine/threat-engine

# Start server
python3 -m uvicorn threat_engine.api_server:app --reload --port 8000
```

Server will be available at: `http://localhost:8000`

### 2. View API Documentation

Open in browser: `http://localhost:8000/docs`

This shows all available endpoints with:
- Request/response schemas
- Try-it-out functionality
- Example payloads

### 3. Test Endpoints

**Dashboard:**
```bash
curl "http://localhost:8000/api/v1/checks/dashboard?tenant_id=test_tenant" | jq
```

**List Scans:**
```bash
curl "http://localhost:8000/api/v1/checks/scans?tenant_id=test_tenant&page=1&page_size=5" | jq
```

**Search Findings:**
```bash
curl "http://localhost:8000/api/v1/checks/findings/search?query=s3&tenant_id=test_tenant" | jq
```

**Resource Findings:**
```bash
curl "http://localhost:8000/api/v1/checks/resources/arn%3Aaws%3As3%3A%3A%3Abucket?tenant_id=test_tenant" | jq
```

## Loading Data into Database

Currently, the check engine runs in NDJSON mode (outputs to files). To populate the database:

### Option 1: Run Check Scan in Database Mode

```bash
cd /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine

# Set database mode
export CHECK_MODE=database

# Run check scan
python run_rule_check_latest.py
```

### Option 2: Upload Existing NDJSON to Database

```bash
cd /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine

# Create upload script
python << 'EOF'
import sys
import json
from pathlib import Path
from engine.database_manager import DatabaseManager

# Initialize database
db = DatabaseManager()

# Read NDJSON findings
findings_file = Path("../../engines-output/aws-configScan-engine/output/configscan/rule_check/rule_check_check_20260122_210506_20260122_210506/findings.ndjson")

print(f"📂 Loading findings from: {findings_file}")

# Create scan record
scan_id = "check_20260122_210506"
db.create_scan(
    scan_id=scan_id,
    customer_id="test_customer",
    tenant_id="test_tenant",
    provider="aws",
    hierarchy_id="039612851381",
    scan_type="check",
    status="completed"
)

# Upload findings
count = 0
with open(findings_file, 'r') as f:
    for line in f:
        record = json.loads(line)
        
        db.store_check_result(
            scan_id=record['scan_id'],
            customer_id=record['customer_id'],
            tenant_id=record['tenant_id'],
            provider=record['provider'],
            hierarchy_id=record['hierarchy_id'],
            hierarchy_type=record['hierarchy_type'],
            rule_id=record['rule_id'],
            resource_arn=record.get('resource_arn'),
            resource_id=record.get('resource_id'),
            resource_type=record['resource_type'],
            status=record['status'],
            checked_fields=record.get('checked_fields'),
            finding_data=record.get('finding_data')
        )
        
        count += 1
        if count % 1000 == 0:
            print(f"   Uploaded {count} findings...")

print(f"✅ Uploaded {count} findings to database")
EOF
```

## API Usage Examples

### Python
```python
import requests

BASE_URL = "http://localhost:8000"
TENANT_ID = "test_tenant"

# Get dashboard
dashboard = requests.get(
    f"{BASE_URL}/api/v1/checks/dashboard?tenant_id={TENANT_ID}"
).json()

print(f"Total Checks: {dashboard['total_checks']:,}")
print(f"Pass Rate: {dashboard['pass_rate']}%")

# Search for S3 findings
findings = requests.get(
    f"{BASE_URL}/api/v1/checks/findings/search",
    params={"query": "s3", "tenant_id": TENANT_ID, "page": 1, "page_size": 10}
).json()

print(f"S3 Findings: {findings['total']:,}")
```

### JavaScript/TypeScript
```typescript
const BASE_URL = 'http://localhost:8000';
const TENANT_ID = 'test_tenant';

// Fetch dashboard
const dashboard = await fetch(
  `${BASE_URL}/api/v1/checks/dashboard?tenant_id=${TENANT_ID}`
).then(r => r.json());

console.log(`Total Checks: ${dashboard.total_checks.toLocaleString()}`);
console.log(`Pass Rate: ${dashboard.pass_rate}%`);

// Fetch scan findings with filters
const findings = await fetch(
  `${BASE_URL}/api/v1/checks/scans/${scanId}/findings?` + 
  new URLSearchParams({
    tenant_id: TENANT_ID,
    service: 's3',
    status: 'FAIL',
    page: '1',
    page_size: '50'
  })
).then(r => r.json());

console.log(`Findings: ${findings.total}`);
```

## Configuration

### Database Connection

Set environment variables:
```bash
export CSPM_DB_HOST=localhost
export CSPM_DB_PORT=5432
export CSPM_DB_NAME=cspm_db
export CSPM_DB_USER=postgres
export CSPM_DB_PASSWORD=your_password
```

Or create: `configScan_engines/aws-configScan-engine/database/secrets/db_config.json`

## Troubleshooting

### API Returns Empty Results

**Cause**: No data in database

**Solution**: Load data using Option 1 or 2 above

### Database Connection Error

**Cause**: Database not running or connection config incorrect

**Solution**: 
```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Verify database exists
psql -l | grep cspm_db

# Create database if needed
createdb cspm_db
psql -d cspm_db -f configScan_engines/aws-configScan-engine/database/schema.sql
```

### Import Errors

**Cause**: Python path not set correctly

**Solution**: The API automatically adds configScan engine to path. If issues persist, check:
```bash
ls -la /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/engine/database_manager.py
```

## Next Steps

1. **Load Data**: Use one of the upload methods above
2. **Test API**: `curl "http://localhost:8000/api/v1/checks/dashboard?tenant_id=test_tenant"`
3. **Build Frontend**: Use UI_CHECKS_MOCKUP.md as reference
4. **Deploy**: Docker or Kubernetes deployment

## Port Information

- **API Server**: Port 8000 (threat-engine)
- **Database**: Port 5432 (PostgreSQL)

## Documentation

- API Docs: `http://localhost:8000/docs`
- UI Mockups: [`UI_CHECKS_MOCKUP.md`](UI_CHECKS_MOCKUP.md)
- Full README: [`CHECK_API_README.md`](CHECK_API_README.md)
- Implementation Summary: [`IMPLEMENTATION_COMPLETE.md`](IMPLEMENTATION_COMPLETE.md)
