# ConfigScan Database Storage

## Current Implementation Status

### ✅ Check Results - **STORED IN DATABASE**

**When:** Check results are stored in the `check_results` table when:
- `use_ndjson=False` is explicitly set, OR
- `use_ndjson=None` (auto-detect) and database connection is available

**Database Table:** `check_results`
- Columns: `scan_id`, `customer_id`, `tenant_id`, `provider`, `hierarchy_id`, `rule_id`, `resource_arn`, `resource_id`, `resource_type`, `status`, `checked_fields`, `finding_data`

**Code Location:**
- `engine/check_engine.py`: `_store_check_result()` method
- `engine/database_manager.py`: `store_check_result()` method

**Current Behavior:**
- ✅ **Kubernetes deployment**: Has `DATABASE_URL` configured → Auto-detects DATABASE mode → **Stores check results to DB**
- ✅ **Local development**: If `DATABASE_URL` is set → Stores to DB
- ⚠️ **If no DB connection**: Falls back to NDJSON file mode

---

### ✅ Discovery Results - **STORED IN DATABASE** (When Enabled)

**When:** Discovery results are stored in the `discoveries` table when:
- `use_database=True` is explicitly set, OR
- `use_database=None` (auto-detect) and database connection is available

**Database Table:** `discoveries`
- Columns: `scan_id`, `customer_id`, `tenant_id`, `provider`, `discovery_id`, `resource_arn`, `resource_id`, `emitted_fields`, `raw_response`, `config_hash`, `version`, `scan_timestamp`, `region`, `service`

**Code Location:**
- `engine/discovery_engine.py`: Writes to files AND database (when enabled)
- `engine/database_manager.py`: `store_discoveries_batch()` method

**Current Behavior:**
- ✅ **Kubernetes deployment**: Has `DATABASE_URL` configured → Auto-detects DATABASE mode → **Stores discoveries to DB**
- ✅ **Local development**: If `DATABASE_URL` is set → Stores to DB
- ⚠️ **If no DB connection**: Falls back to file-only mode

**Storage Process:**
1. Discovery results are written to files (`discoveries.ndjson`) first
2. Then stored to database in batches (grouped by `discovery_id`)
3. Includes drift detection (tracks changes between scans)

---

## Summary Table

| Scan Type | File Storage | Database Storage | Notes |
|-----------|--------------|-----------------|-------|
| **Discovery** (`POST /api/v1/discovery`) | ✅ `discoveries.ndjson` | ✅ **YES** (if DB available) | Auto-detects mode |
| **Check** (`POST /api/v1/check`) | ✅ `checks.ndjson` (if `use_ndjson=True`) | ✅ **YES** (if DB available) | Auto-detects mode |
| **Legacy Scan** (`POST /api/v1/scan`) | ✅ Both files | ✅ **YES** (via `_sync_ingest_to_db()`) | Uploads discoveries to DB |

---

## How to Control Database Storage

### For Check Results:

**Option 1: Force Database Mode**
```python
# In API request
{
    "use_ndjson": false  # Explicitly use database
}
```

**Option 2: Force File Mode**
```python
# In API request
{
    "use_ndjson": true  # Explicitly use files only
}
```

**Option 3: Auto-Detect (Current Default)**
```python
# In API request
{
    "use_ndjson": null  # or omit the field
}
# Behavior:
# - If DATABASE_URL exists → Database mode
# - If no DATABASE_URL → File mode
```

### For Discovery Results:

**Option 1: Force Database Mode**
```python
# In API request
{
    "use_database": true  # Explicitly use database
}
```

**Option 2: Force File Mode**
```python
# In API request
{
    "use_database": false  # Explicitly use files only
}
```

**Option 3: Auto-Detect (Current Default)**
```python
# In API request
{
    "use_database": null  # or omit the field
}
# Behavior:
# - If DATABASE_URL exists → Database mode
# - If no DATABASE_URL → File mode
```

---

## Database Schema

### `check_results` Table
```sql
CREATE TABLE check_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,  -- Primary identifier (ARN for AWS, Resource ID for Azure/GCP)
    resource_arn TEXT,  -- AWS-specific (for backward compatibility)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    status VARCHAR(50),  -- PASS, FAIL, ERROR
    checked_fields JSONB,
    finding_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_check_results_resource_uid ON check_results(resource_uid);
CREATE INDEX idx_check_results_tenant_uid ON check_results(tenant_id, resource_uid);
```

### `discoveries` Table
```sql
CREATE TABLE discoveries (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,  -- Primary identifier (ARN for AWS, Resource ID for Azure/GCP)
    resource_arn TEXT,  -- AWS-specific (for backward compatibility)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    service VARCHAR(100),
    region VARCHAR(50),
    emitted_fields JSONB,
    raw_response JSONB,
    config_hash VARCHAR(64),
    version INTEGER,
    scan_timestamp TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_discoveries_resource_uid ON discoveries(resource_uid);
CREATE INDEX idx_discoveries_tenant_uid ON discoveries(tenant_id, resource_uid);
```

---

## Summary

**Current State:**
- ✅ **Discovery results**: Stored in DB (when DB available) + Files
- ✅ **Check results**: Stored in DB (when DB available) + Files (if `use_ndjson=True`)

**Both discovery and check results are now stored in the database when:**
- Database connection is available (`DATABASE_URL` is set)
- Auto-detection mode is used (default)
- Or explicitly enabled via `use_database=true` / `use_ndjson=false`
