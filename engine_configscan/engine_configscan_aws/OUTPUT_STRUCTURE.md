# ConfigScan Engine Output Structure

## Final Implemented Structure

```
engine_output/engine_configscan_aws/output/
├── discoveries/                          # Discovery phase output
│   └── {discovery_scan_id}/              # e.g., discovery_20260125_120530
│       ├── discoveries.ndjson            # ✅ Renamed from inventory.ndjson
│       │   └── Discovered AWS resources (S3 buckets, EC2 instances, etc.)
│       │       Schema: cspm_asset.v1
│       │       Format: One JSON object per line (NDJSON)
│       │
│       ├── summary.json                 # Scan metadata and statistics
│       │   └── Total discoveries, duration, etc.
│       │
│       └── logs/                         # Execution logs
│           └── scan.log, errors.log
│
└── checks/                               # Check phase output (separate)
    └── {check_scan_id}/                  # e.g., check_20260125_120530
        ├── checks.ndjson                 # ✅ Renamed from findings.ndjson
        │   └── Detailed compliance check results
        │       Format: One check result per line (NDJSON)
        │       Includes: discovery_scan_id, checked_fields, finding_data
        │
        ├── summary.json                  # Check scan metadata
        │   └── Total checks, passed/failed, checks_file path
        │
        └── logs/                         # Check execution logs
            └── checks.log
```

---

## File Naming Convention

### Discovery Phase Files:
- **`discoveries.ndjson`** (renamed from `inventory.ndjson`)
  - Contains: Discovered AWS resources/assets
  - Example: S3 buckets, EC2 instances, IAM roles, etc.
  - Schema: `cspm_asset.v1`

- **`summary.json`**
  - Contains: Scan metadata, statistics, file paths

### Check Phase Files:
- **`checks.ndjson`** (renamed from `findings.ndjson`)
  - Contains: Detailed compliance check results
  - Format: Extended finding records with metadata
  - Includes: `discovery_scan_id`, `checked_fields`, `finding_data`

- **`summary.json`**
  - Contains: Check scan metadata, statistics, `checks_file` path

---

## API Endpoints

### 1. Discovery Endpoint
**`POST /api/v1/discovery`**
- Runs discovery phase only
- Discovers AWS resources using discovery YAML files
- Output: `output/discoveries/{discovery_scan_id}/discoveries.ndjson`
- Returns: `discovery_scan_id`

### 2. Check Endpoint
**`POST /api/v1/check`**
- Runs check phase only (requires `discovery_scan_id`)
- Runs compliance checks on discovered resources
- Reads from: `output/discoveries/{discovery_scan_id}/discoveries.ndjson`
- Output: `output/checks/{check_scan_id}/checks.ndjson`
- Returns: `check_scan_id`

### 3. Combined Scan Endpoint (Legacy)
**`POST /api/v1/scan`**
- Runs discovery + checks together (legacy mode)
- Output: `output/discoveries/{scan_id}/discoveries.ndjson`
- Note: Check results should use separate `POST /api/v1/check` endpoint

---

## Path Resolution

### Local Development:
```
{project_root}/engine_output/engine_configscan_aws/output/
├── discoveries/
└── checks/
```

### Kubernetes (via OUTPUT_DIR env var):
```
OUTPUT_DIR="/app/engine_output/engine_configscan_aws/output/discoveries"
→ Base: /app/engine_output/engine_configscan_aws/output/
→ Discoveries: {OUTPUT_DIR}/{scan_id}/
→ Checks: {OUTPUT_DIR}/../checks/{check_scan_id}/
```

### Host Path (Local K8s):
```
/Users/apple/Desktop/threat-engine/engine_output/engine_configscan_aws/output/
├── discoveries/
└── checks/
```

---

## Key Changes Implemented

1. ✅ **Renamed Files:**
   - `inventory.ndjson` → `discoveries.ndjson`
   - `findings.ndjson` → `checks.ndjson`

2. ✅ **Removed `configscan/` Level:**
   - Old: `output/configscan/discoveries/`
   - New: `output/discoveries/`
   - Old: `output/configscan/rule_check/`
   - New: `output/checks/`

3. ✅ **Separated Endpoints:**
   - Discovery: `POST /api/v1/discovery`
   - Checks: `POST /api/v1/check`

4. ✅ **Updated Variable Names:**
   - `inventory_path` → `discoveries_path`
   - `inventory_ndjson_path` → `discoveries_ndjson_path`
   - `findings_file` → `checks_file`
   - `consolidated_inventory` → `consolidated_discoveries`

---

## Workflow Examples

### Example 1: Separate Discovery + Check
```bash
# Step 1: Run Discovery
POST /api/v1/discovery
→ Creates: output/discoveries/discovery_20260125_120530/discoveries.ndjson
→ Returns: discovery_scan_id = "discovery_20260125_120530"

# Step 2: Run Checks on Discoveries
POST /api/v1/check
  { "discovery_scan_id": "discovery_20260125_120530", ... }
→ Reads: output/discoveries/discovery_20260125_120530/discoveries.ndjson
→ Creates: output/checks/check_20260125_121000/checks.ndjson
→ Returns: check_scan_id = "check_20260125_121000"
```

### Example 2: Combined Scan (Legacy - Not Recommended)
```bash
# Run Discovery + Checks Together (Legacy)
POST /api/v1/scan
→ Creates: output/discoveries/{scan_id}/
  ├── discoveries.ndjson
  └── summary.json
→ Note: Use separate discovery and check endpoints for better separation
```

---

## File Content Differences

### `discoveries.ndjson` (Discovery Output)
```json
{
  "schema_version": "cspm_asset.v1",
  "tenant_id": "default-tenant",
  "scan_run_id": "discovery_20260125_120530",
  "provider": "aws",
  "service": "s3",
  "account_id": "588989875114",
  "region": "global",
  "resource_type": "s3:bucket",
  "resource_id": "my-bucket",
  "resource_arn": "arn:aws:s3:::my-bucket",
  "name": "my-bucket",
  "tags": {},
  "metadata": { ... },
  "_dependent_data": { ... }
}
```

### `checks.ndjson` (Check Phase Results)
```json
{
  "scan_id": "check_20260125_121000",
  "discovery_scan_id": "discovery_20260125_120530",
  "customer_id": "test_customer",
  "tenant_id": "test_tenant",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "hierarchy_type": "account",
  "rule_id": "aws.s3.bucket.access_logging_enabled",
  "resource_arn": "arn:aws:s3:::my-bucket",
  "resource_id": "my-bucket",
  "resource_type": "s3",
  "status": "FAIL",
  "checked_fields": ["LoggingEnabled"],
  "finding_data": {
    "rule_id": "aws.s3.bucket.access_logging_enabled",
    "service": "s3",
    "discovery_id": "aws.s3.list_buckets",
    "resource_arn": "arn:aws:s3:::my-bucket",
    "status": "FAIL",
    "checked_fields": ["LoggingEnabled"]
  },
  "scan_timestamp": "2026-01-25T12:10:00.995652"
}
```

---

## Summary

**Final Structure:**
- ✅ `output/discoveries/{scan_id}/discoveries.ndjson` - Discovered resources
- ✅ `output/checks/{check_scan_id}/checks.ndjson` - Detailed check results
- ✅ All files directly under `output/` (no `configscan/` level)
- ✅ Clear separation between discovery and check phases
- ✅ Consistent naming: `discoveries.ndjson` and `checks.ndjson`
- ✅ No `results.ndjson` in discoveries folder (checks go to separate `checks/` folder)
