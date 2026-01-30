# Threat Engine - Database Architecture Guide

## Quick Start

All threat engine data is now in **4 PostgreSQL databases** with normalized schemas.

---

## Databases & Connections

| Database | Username | Password | Purpose |
|----------|----------|----------|---------|
| **threat_engine_check** | check_user | check_password | Check results & rule metadata (INPUT) |
| **threat_engine_threat** | threat_user | threat_password | Threat analysis (OUTPUT) |
| **threat_engine_compliance** | compliance_user | compliance_password | Compliance frameworks (OUTPUT) |
| **threat_engine_inventory** | inventory_user | inventory_password | Asset inventory (OUTPUT) |

**All on**: `localhost:5432`

---

## What's in Each Database

### 1. threat_engine_check (INPUT - Source Data)

**Tables:**
- `check_results` (6,457 rows) - All security check results
- `rule_metadata` (1,918 rows) - Rules with threat_category, compliance_frameworks, data_security

**Views:**
- `iam_security_posture` - IAM checks (2,512 rows)
- `iam_resource_summary` - IAM resources (214 resources, 2.15% score)
- `data_security_posture` - DataSec checks (4,556 rows)
- `datasec_by_module` - DataSec by module (8.08% score)
- `datasec_resource_summary` - DataSec resources
- `security_posture_summary` - Overall IAM+DataSec scores

**Use For**: IAM Security, Data Security, detailed check analysis

---

### 2. threat_engine_threat (THREAT ANALYSIS)

**Tables:**
- `threats` (489 rows) - Individual threats ⭐
- `threat_resources` (489 rows) - Threat-resource mappings
- `threat_scans` (1 row) - Scan summaries
- `drift_records` (0 rows) - Drift tracking

**Categories:**
- Identity: 240 threats (IAM-related)
- Misconfiguration: 134 threats
- Exposure: 94 threats
- Data Exfiltration: 21 threats (DataSec-related)

**Use For**: Threat dashboards, risk analysis, remediation priorities

---

### 3. threat_engine_compliance (COMPLIANCE MAPPING)

**Tables:**
- `compliance_control_mappings` (960 rows) - Framework control definitions
- `resource_compliance_status` (23,998 rows) - Resource-level compliance

**Views:**
- `compliance_control_detail` (362 controls) - Complete control analysis ⭐

**Frameworks**: CIS, PCI-DSS, ISO27001, SOC2, NIST, FedRAMP, HIPAA (13 total)

**Use For**: Compliance reporting, framework mapping, audit dashboards

---

### 4. threat_engine_inventory (ASSET INVENTORY)

**Tables:**
- `asset_index_latest` (287 rows) - Asset inventory
- `relationship_index_latest` (97 rows) - Asset relationships
- `inventory_run_index` - Scan summaries

**Use For**: Asset management, relationship graphs, inventory reports

---

## Virtual Engines (No Separate DBs)

### IAM Security Engine
**Data Location**: `threat_engine_check` database (views)

**Use**:
```sql
SELECT * FROM iam_resource_summary;  -- Check DB
SELECT * FROM threats WHERE category='identity';  -- Threat DB
```

### Data Security Engine
**Data Location**: `threat_engine_check` database (views)

**Use**:
```sql
SELECT * FROM datasec_by_module;  -- Check DB
SELECT * FROM threats WHERE category='data_exfiltration';  -- Threat DB
```

---

## DBeaver Setup (Copy-Paste)

### Connection 1: Check DB
```
Name: Check & Rules
Host: localhost
Port: 5432
Database: threat_engine_check
Username: check_user
Password: check_password
```

### Connection 2: Threat DB
```
Name: Threats
Host: localhost
Port: 5432
Database: threat_engine_threat
Username: threat_user
Password: threat_password
```

### Connection 3: Compliance DB
```
Name: Compliance
Host: localhost
Port: 5432
Database: threat_engine_compliance
Username: compliance_user
Password: compliance_password
```

### Connection 4: Inventory DB
```
Name: Inventory
Host: localhost
Port: 5432
Database: threat_engine_inventory
Username: inventory_user
Password: inventory_password
```

---

## Common Queries

### See All Threats:
```sql
-- Connect to: threat_engine_threat
SELECT * FROM threats ORDER BY severity;
```

### See IAM Security:
```sql
-- Connect to: threat_engine_check
SELECT * FROM iam_resource_summary
WHERE scan_id = 'check_20260129_162625';
```

### See Data Security:
```sql
-- Connect to: threat_engine_check
SELECT * FROM datasec_by_module
WHERE scan_id = 'check_20260129_162625';
```

### See Compliance:
```sql
-- Connect to: threat_engine_compliance
SELECT * FROM compliance_control_detail
WHERE compliance_framework = 'CIS';
```

### See Assets:
```sql
-- Connect to: threat_engine_inventory
SELECT * FROM asset_index_latest;
```

---

## Documentation Files

**Main Guides:**
- `README_DATABASES.md` (this file) - Quick start
- `DBEAVER_CONNECTIONS.md` - Detailed connection guide
- `FINAL_ARCHITECTURE.md` - Complete architecture
- `IMPLEMENTATION_COMPLETE.md` - What was built

**Engine-Specific:**
- `engine_threat/UI_API_MAPPING.md` - Threat APIs
- `engine_compliance/UI_API_MAPPING.md` - Compliance APIs
- `engine_inventory/UI_API_MAPPING.md` - Inventory APIs
- `engine_iam/UI_API_MAPPING.md` - IAM (view-based)
- `engine_datasec/UI_API_MAPPING.md` - DataSec (view-based)

**Database Guides:**
- `THREAT_DATABASE_GUIDE.md` - Threat queries
- `COMPLIANCE_DBEAVER_FINAL.md` - Compliance queries
- `IAM_DATASEC_USAGE_GUIDE.md` - IAM/DataSec usage

---

## Quick Reference

| What You Want | Database | Table/View |
|---------------|----------|------------|
| **All Threats** | threat_engine_threat | `threats` |
| **IAM Security** | threat_engine_check | `iam_resource_summary` (VIEW) |
| **Data Security** | threat_engine_check | `datasec_by_module` (VIEW) |
| **Compliance** | threat_engine_compliance | `compliance_control_detail` (VIEW) |
| **Assets** | threat_engine_inventory | `asset_index_latest` |
| **Relationships** | threat_engine_inventory | `relationship_index_latest` |
| **Check Results** | threat_engine_check | `check_results` |
| **Rule Metadata** | threat_engine_check | `rule_metadata` |

---

## Summary

✅ **4 databases** (no IAM/DataSec databases needed)  
✅ **489 threats** in normalized tables  
✅ **23,998 compliance records**  
✅ **287 assets** with 97 relationships  
✅ **IAM & DataSec** use views (no duplication)  

**All data is queryable in DBeaver!**
