# Complete Implementation Guide

## Overview
This guide covers the complete implementation of the two-phase CSPM architecture:
1. **Discovery Phase**: Run discoveries, store in PostgreSQL
2. **Check Phase**: Run checks against database, store results

## Prerequisites

### 1. PostgreSQL Setup
```bash
# Install PostgreSQL (if not already installed)
brew install postgresql  # macOS
# or
sudo apt-get install postgresql  # Linux

# Start PostgreSQL
brew services start postgresql  # macOS
# or
sudo systemctl start postgresql  # Linux

# Create database
createdb cspm_db

# Run schema
psql -d cspm_db -f database/schema.sql
```

### 2. Install Python Dependencies
```bash
pip install -r requirements_db.txt
```

### 3. Configure Database Connection
Create `database/secrets/db_config.json`:
```json
{
  "host": "localhost",
  "port": 5432,
  "database": "cspm_db",
  "user": "postgres",
  "password": "your_password"
}
```

Or set environment variables:
```bash
export CSPM_DB_HOST=localhost
export CSPM_DB_PORT=5432
export CSPM_DB_NAME=cspm_db
export CSPM_DB_USER=postgres
export CSPM_DB_PASSWORD=your_password
```

## Step-by-Step Implementation

### Step 1: Enrich All Services YAML
```bash
cd /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine
python3 enrich_all_services.py
```

This will:
- Enrich all service YAML files with explicit emit fields
- Create backups of original files
- Process all services in `services/` directory

### Step 2: Split Discoveries and Checks
```bash
python3 split_discoveries_checks.py
```

This will:
- Split combined YAML files into:
  - `services/{service}/discoveries/{service}.discoveries.yaml`
  - `services/{service}/checks/default/{service}.checks.yaml`

### Step 3: Run Complete Scan Workflow

#### Option A: All Services, All Regions, Single Account
```bash
python3 run_complete_scan_workflow.py \
  --customer-id cust_001 \
  --tenant-id aws_tenant_001 \
  --provider aws \
  --hierarchy-id 588989875114 \
  --hierarchy-type account \
  --all-services \
  --all-regions
```

#### Option B: Specific Services and Regions
```bash
python3 run_complete_scan_workflow.py \
  --customer-id cust_001 \
  --tenant-id aws_tenant_001 \
  --provider aws \
  --hierarchy-id 588989875114 \
  --hierarchy-type account \
  --services s3 iam ec2 \
  --regions ap-south-1 us-east-1
```

#### Option C: Discovery Only (for testing)
```python
from engine.database_manager import DatabaseManager
from engine.discovery_engine import DiscoveryEngine

db = DatabaseManager()
db.create_customer("cust_001", "Test Customer")
db.create_tenant("aws_tenant_001", "cust_001", "aws")

discovery_engine = DiscoveryEngine(db)
scan_id = discovery_engine.run_discovery_for_all_services(
    customer_id="cust_001",
    tenant_id="aws_tenant_001",
    provider="aws",
    hierarchy_id="588989875114",
    hierarchy_type="account",
    regions=["ap-south-1", "us-east-1"]
)
```

## Architecture Components

### 1. Database Schema (`database/schema.sql`)
- Multi-tenant structure: customers → tenants → hierarchies
- Discovery storage with drift detection
- Check results storage
- Historical tracking

### 2. Database Manager (`engine/database_manager.py`)
- PostgreSQL connection management
- CRUD operations for all tables
- Drift detection logic
- Query methods

### 3. Discovery Engine (`engine/discovery_engine.py`)
- Runs discoveries only (no checks)
- Stores results in database
- Supports all services, all regions

### 4. Check Engine (`engine/check_engine.py`)
- Queries discoveries from database
- Evaluates checks against database data
- Stores results in database

### 5. Main Workflow (`run_complete_scan_workflow.py`)
- Orchestrates discovery + check phases
- Command-line interface
- Results export

## Testing

### Test Discovery Phase
```bash
# Set to skip checks
export MAX_CHECK_WORKERS=0

# Run discovery for one service
python3 -c "
from engine.database_manager import DatabaseManager
from engine.discovery_engine import DiscoveryEngine

db = DatabaseManager()
db.create_customer('test_cust', 'Test Customer')
db.create_tenant('test_tenant', 'test_cust', 'aws')

engine = DiscoveryEngine(db)
scan_id = engine.run_discovery_scan(
    customer_id='test_cust',
    tenant_id='test_tenant',
    provider='aws',
    hierarchy_id='588989875114',
    hierarchy_type='account',
    services=['s3'],
    regions=['ap-south-1']
)
print(f'Discovery scan ID: {scan_id}')
"
```

### Test Check Phase
```bash
python3 -c "
from engine.database_manager import DatabaseManager
from engine.check_engine import CheckEngine

db = DatabaseManager()
check_engine = CheckEngine(db)

results = check_engine.run_check_scan(
    scan_id='discovery_20260121_120000',  # Use actual scan ID
    customer_id='test_cust',
    tenant_id='test_tenant',
    provider='aws',
    hierarchy_id='588989875114',
    hierarchy_type='account',
    services=['s3'],
    check_source='default'
)
print(f'Check results: {results}')
"
```

## Querying Results

### Query Discoveries
```python
from engine.database_manager import DatabaseManager

db = DatabaseManager()

# Query by discovery ID
discoveries = db.query_discovery(
    discovery_id='aws.s3.get_bucket_encryption',
    tenant_id='aws_tenant_001',
    hierarchy_id='588989875114'
)

for disc in discoveries:
    print(f"Resource: {disc['resource_arn']}")
    print(f"Data: {disc['emitted_fields']}")
```

### Query Check Results
```python
# Export check results
results = db.export_check_results('check_20260121_130000')

for result in results:
    print(f"Rule: {result['rule_id']}, Status: {result['status']}")
    print(f"Resource: {result['resource_arn']}")
```

## Next Steps

1. **Run enrichment** for all services
2. **Split** discoveries and checks
3. **Test discovery phase** with a few services
4. **Test check phase** against discovery data
5. **Run full scan** for all services, all regions, all accounts

## Troubleshooting

### Database Connection Issues
- Check PostgreSQL is running: `pg_isready`
- Verify credentials in `database/secrets/db_config.json`
- Check firewall/network settings

### Discovery Issues
- Verify service YAML files exist in `services/{service}/discoveries/`
- Check AWS credentials are configured
- Review logs for API errors

### Check Issues
- Verify check YAML files exist in `services/{service}/checks/default/`
- Ensure discovery scan completed successfully
- Check database has discovery data for the scan_id

