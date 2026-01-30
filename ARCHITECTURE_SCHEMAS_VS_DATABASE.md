# Architecture: Schemas vs Database - Clarification

## Quick Answer

**YES, we use BOTH** - but for completely different purposes:

1. **`/engine_threat/threat_engine/schemas/`** = **Pydantic Models** (Python data validation)
2. **`/consolidated_services/database/schemas/`** = **SQL Schemas** (PostgreSQL database structure)

They serve different layers of the application architecture.

## Architecture Breakdown

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│  /engine_threat/threat_engine/schemas/ (Pydantic Models)        │
│                                                                   │
│  Purpose: Python data validation, API contracts, type safety     │
│  Files:                                                           │
│  ├─ threat_report_schema.py    → ThreatReport, Severity, etc.   │
│  ├─ misconfig_normalizer.py    → normalize findings             │
│  ├─ check_models.py             → CheckResult models            │
│  └─ discovery_models.py         → Discovery models              │
└─────────────────────────────────────────────────────────────────┘
                              ↓↑ (validates/transforms)
┌─────────────────────────────────────────────────────────────────┐
│                       DATABASE LAYER                             │
│  /consolidated_services/database/schemas/ (SQL Schemas)          │
│                                                                   │
│  Purpose: PostgreSQL table definitions, constraints, indexes     │
│  Files:                                                           │
│  ├─ configscan_schema.sql      → check_results, discoveries     │
│  ├─ threat_schema.sql           → threats, vulnerabilities      │
│  ├─ inventory_schema.sql        → assets, resources             │
│  ├─ compliance_schema.sql       → compliance_results            │
│  └─ shared_schema.sql           → customers, tenants            │
└─────────────────────────────────────────────────────────────────┘
```

## Detailed Comparison

### 1. Pydantic Schemas (`/engine_threat/threat_engine/schemas/`)

**Purpose:** Python runtime validation and API contracts

**Example - threat_report_schema.py:**
```python
from pydantic import BaseModel
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class MisconfigFinding(BaseModel):
    rule_id: str
    severity: Severity
    resource_uid: str
    # ... validation rules
```

**Used for:**
- ✅ FastAPI request/response validation
- ✅ Python type checking
- ✅ JSON serialization/deserialization
- ✅ Data transformation (NDJSON → Python objects)
- ✅ API documentation (auto-generated from models)

**Example usage:**
```python
# API endpoint uses Pydantic schema
@app.post("/api/v1/threat/generate")
async def generate_threat_report(request: ThreatReportRequest):
    # request is validated against Pydantic schema
    report = ThreatReport(
        scan_run_id=request.scan_run_id,
        severity=Severity.HIGH  # Type-safe!
    )
```

### 2. SQL Schemas (`/consolidated_services/database/schemas/`)

**Purpose:** PostgreSQL database structure

**Example - configscan_schema.sql:**
```sql
CREATE TABLE IF NOT EXISTS check_results (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(20),
    status VARCHAR(50),
    -- ... constraints, indexes
);

CREATE TABLE IF NOT EXISTS rule_metadata (
    rule_id VARCHAR(255) PRIMARY KEY,
    severity VARCHAR(20),
    -- ... database constraints
);
```

**Used for:**
- ✅ Database table creation
- ✅ Foreign key constraints
- ✅ Indexes for performance
- ✅ Data persistence
- ✅ SQL migrations

**Example usage:**
```bash
# Create database schema
psql -U postgres -d threat_engine < consolidated_services/database/schemas/configscan_schema.sql
```

## How They Work Together

### Flow: Threat Report Generation

```
1. HTTP Request (JSON)
   ↓
2. FastAPI validates with Pydantic schema
   request: ThreatReportRequest  ← /engine_threat/schemas/
   ↓
3. Query database
   SELECT * FROM check_results    ← /consolidated_services/database/schemas/
   ↓
4. Transform to Pydantic models
   findings: List[MisconfigFinding] ← /engine_threat/schemas/
   ↓
5. Generate report
   report: ThreatReport           ← /engine_threat/schemas/
   ↓
6. Return JSON response
   (Pydantic auto-serializes)
```

### Example Code

```python
# 1. Pydantic schema validates request
from threat_engine.schemas.threat_report_schema import ThreatReportRequest

@app.post("/api/v1/threat/generate")
async def generate(request: ThreatReportRequest):
    
    # 2. Query database (SQL schema)
    check_results = get_enriched_check_results(
        scan_id=request.scan_run_id
    )
    # Returns: [{rule_id: '...', severity: 'high', ...}]
    
    # 3. Transform to Pydantic models
    findings = normalize_db_check_results_to_findings(
        check_results,
        cloud=request.cloud
    )
    # Returns: [MisconfigFinding(rule_id='...', severity=Severity.HIGH, ...)]
    
    # 4. Create report (Pydantic schema)
    report = ThreatReport(
        scan_run_id=request.scan_run_id,
        findings=findings,
        severity=Severity.HIGH
    )
    
    # 5. Pydantic auto-serializes to JSON
    return report
```

## Metadata Enrichment - Both Schemas Work Together

### Database Schema (SQL)
```sql
-- /consolidated_services/database/migrations/002_add_rule_metadata.sql
CREATE TABLE rule_metadata (
    rule_id VARCHAR(255) PRIMARY KEY,
    severity VARCHAR(20),           -- Stored in database
    title TEXT,
    description TEXT
);
```

### Pydantic Schema (Python)
```python
# /engine_threat/threat_engine/schemas/threat_report_schema.py
class MisconfigFinding(BaseModel):
    rule_id: str
    severity: Severity              # Validated by Pydantic
    title: Optional[str]
    description: Optional[str]
```

### The Connection
```python
# 1. Query database (SQL schema)
results = db.execute("""
    SELECT cr.*, rm.severity, rm.title, rm.description
    FROM check_results cr
    JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
""")
# Returns: [{rule_id: '...', severity: 'high', title: '...'}]

# 2. Transform to Pydantic models (validates data)
finding = MisconfigFinding(
    rule_id=result['rule_id'],
    severity=Severity(result['severity']),  # Validates: must be valid Severity enum
    title=result['title']
)
# Pydantic ensures data integrity
```

## File Purposes Summary

### `/engine_threat/threat_engine/schemas/` (Pydantic)

| File | Purpose |
|------|---------|
| `threat_report_schema.py` | ThreatReport, Severity, Cloud enums, API contracts |
| `misconfig_normalizer.py` | Transform NDJSON/DB data to MisconfigFinding models |
| `check_models.py` | CheckResult Pydantic models |
| `discovery_models.py` | Discovery Pydantic models |

**Technology:** Python, Pydantic
**Layer:** Application logic, API
**Runs:** In Python process (FastAPI)

### `/consolidated_services/database/schemas/` (SQL)

| File | Purpose |
|------|---------|
| `configscan_schema.sql` | check_results, discoveries tables |
| `threat_schema.sql` | threat-specific tables |
| `inventory_schema.sql` | asset/resource tables |
| `compliance_schema.sql` | compliance results tables |
| `shared_schema.sql` | customers, tenants tables |

**Technology:** PostgreSQL SQL
**Layer:** Data persistence
**Runs:** In PostgreSQL database

## Why We Need Both

### Scenario: User submits invalid data

**Without Pydantic Schema:**
```python
# ❌ No validation
severity = request_data.get('severity')  # Could be anything!
# severity = "SUPER_CRITICAL"  → Invalid! Crashes later
# severity = 123                → Invalid! Type error
```

**With Pydantic Schema:**
```python
# ✅ Validated
class Request(BaseModel):
    severity: Severity  # Must be valid enum

severity = request.severity  # Guaranteed to be valid!
# severity = Severity.HIGH  → Type-safe!
```

### Scenario: Database stores invalid data

**Without SQL Schema:**
```sql
-- ❌ No constraints
INSERT INTO check_results (severity) VALUES ('INVALID');  -- Accepted!
INSERT INTO check_results (severity) VALUES (NULL);       -- Accepted!
```

**With SQL Schema:**
```sql
-- ✅ Constrained
CREATE TABLE check_results (
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low'))
);

INSERT INTO check_results (severity) VALUES ('INVALID');  -- REJECTED!
```

## Best Practices

### 1. Keep Schemas in Sync

When adding a new field:

**Step 1: Update SQL schema**
```sql
ALTER TABLE check_results ADD COLUMN new_field VARCHAR(100);
```

**Step 2: Update Pydantic schema**
```python
class CheckResult(BaseModel):
    new_field: Optional[str] = None
```

### 2. Pydantic for Validation, SQL for Persistence

```python
# ✅ Good: Validate with Pydantic first
finding = MisconfigFinding(**data)  # Validates

# Then store to database (SQL schema)
db.execute("""
    INSERT INTO check_results (rule_id, severity)
    VALUES (%s, %s)
""", (finding.rule_id, finding.severity.value))
```

### 3. Don't Duplicate Business Logic

**❌ Bad:**
```python
# Pydantic schema
class Finding(BaseModel):
    severity: Severity
    
    @validator('severity')
    def validate_severity(cls, v):
        if v == Severity.CRITICAL:
            # Do something...
            pass

# SQL schema
CREATE TRIGGER check_severity BEFORE INSERT ON check_results ...
```

**✅ Good:**
```python
# Pydantic schema (validation only)
class Finding(BaseModel):
    severity: Severity  # Type validation

# Business logic (separate)
def process_finding(finding: Finding):
    if finding.severity == Severity.CRITICAL:
        # Business logic here
        pass
```

## Summary

| Aspect | Pydantic Schemas | SQL Schemas |
|--------|------------------|-------------|
| **Location** | `/engine_threat/schemas/` | `/consolidated_services/database/schemas/` |
| **Technology** | Python, Pydantic | PostgreSQL SQL |
| **Purpose** | API validation, type safety | Data persistence, constraints |
| **Layer** | Application | Database |
| **Validates** | Runtime Python objects | Stored database data |
| **Used by** | FastAPI, Python code | PostgreSQL |
| **Examples** | `ThreatReport`, `Severity` | `CREATE TABLE check_results` |

**Both are essential** - they work together to provide end-to-end data integrity:
- **Pydantic** = Validates data entering/leaving Python
- **SQL** = Validates data stored in PostgreSQL

You need both to ensure data quality at every layer! ✅
