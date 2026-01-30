# DBeaver Database Connections Guide

## Overview

You need to connect to **4 databases** to see the complete threat-engine data:

1. **Check DB** - Check results & rule metadata (input)
2. **Threat DB** - Threat analysis (output)
3. **Compliance DB** - Compliance framework scores (output)
4. **Inventory DB** - Asset inventory (output)

---

## Connection Settings

### 1. Check Database (Input Data)

| Setting | Value |
|---------|-------|
| **Connection Name** | `Threat Engine - Check DB` |
| **Host** | `localhost` |
| **Port** | `5432` |
| **Database** | `threat_engine_check` |
| **Username** | `check_user` |
| **Password** | `check_password` |

**What to View:**
- `check_results` table (6,457 rows) - All check results
- `rule_metadata` table (1,918 rows) - Rules with threat categories and compliance frameworks
- `scans` table - Scan metadata

**Sample Query:**
```sql
-- Check results with metadata
SELECT 
    cr.rule_id,
    cr.status,
    cr.resource_uid,
    rm.severity,
    rm.threat_category,
    rm.compliance_frameworks
FROM check_results cr
LEFT JOIN rule_metadata rm ON cr.rule_id = rm.rule_id
WHERE cr.scan_id = 'check_20260129_162625'
LIMIT 100;
```

---

### 2. Threat Database (Threat Analysis)

| Setting | Value |
|---------|-------|
| **Connection Name** | `Threat Engine - Threat DB` |
| **Host** | `localhost` |
| **Port** | `5432` |
| **Database** | `threat_engine_threat` |
| **Username** | `threat_user` |
| **Password** | `threat_password` |

**What to View:**
- `threat_scans` table (1 row) - Scan summary (489 threats total)
- `threats` table (489 rows) - **Individual threats** ⭐
- `threat_resources` table (489 rows) - Threat-resource mappings
- `drift_records` table (0 rows) - Drift tracking (empty on first run)

**Sample Query:**
```sql
-- High severity threats
SELECT 
    threat_id,
    category,
    severity,
    title,
    misconfig_count,
    primary_rule_id
FROM threats
WHERE severity IN ('critical', 'high')
ORDER BY 
    CASE severity WHEN 'critical' THEN 1 ELSE 2 END,
    misconfig_count DESC
LIMIT 50;
```

**Resource Analysis:**
```sql
-- Resources with most threats
SELECT 
    tr.resource_uid,
    tr.resource_type,
    COUNT(DISTINCT t.threat_id) as threat_count,
    string_agg(DISTINCT t.category, ', ') as threat_categories
FROM threat_resources tr
JOIN threats t ON tr.threat_id = tr.threat_id
GROUP BY tr.resource_uid, tr.resource_type
ORDER BY threat_count DESC
LIMIT 20;
```

---

### 3. Compliance Database (Framework Scores)

| Setting | Value |
|---------|-------|
| **Connection Name** | `Threat Engine - Compliance DB` |
| **Host** | `localhost` |
| **Port** | `5432` |
| **Database** | `threat_engine_compliance` |
| **Username** | `compliance_user` |
| **Password** | `compliance_password` |

**What to View:**
- `compliance_scans` table - Compliance scan summaries
- `framework_scores` table - Per-framework compliance scores (CIS, PCI-DSS, etc.)
- `control_results` table - Individual control pass/fail
- `compliance_frameworks` table - Framework definitions
- `compliance_controls` table - Control definitions

**Sample Query:**
```sql
-- View all framework scores for a scan
SELECT 
    framework_name,
    compliance_score,
    total_controls,
    controls_passed,
    controls_failed
FROM framework_scores
WHERE compliance_scan_id = 'check_20260129_162625'
ORDER BY compliance_score DESC;
```

---

### 4. Inventory Database (Asset Inventory)

| Setting | Value |
|---------|-------|
| **Connection Name** | `Threat Engine - Inventory DB` |
| **Host** | `localhost` |
| **Port** | `5432` |
| **Database** | `threat_engine_inventory` |
| **Username** | `inventory_user` |
| **Password** | `inventory_password` |

**What to View:**
- `asset_index_latest` table (287 rows) - Asset inventory
- `relationship_index_latest` table (97 rows) - Asset relationships
- `inventory_run_index` table - Inventory scan summaries

**Sample Query:**
```sql
-- Assets by type
SELECT 
    resource_type,
    COUNT(*) as count
FROM asset_index_latest
WHERE tenant_id = 'test-tenant'
GROUP BY resource_type
ORDER BY count DESC;
```

---

## Quick Setup in DBeaver

### Step-by-Step:

1. **Open DBeaver**
2. Click **Database** → **New Database Connection**
3. Select **PostgreSQL**
4. Click **Next**
5. Enter connection settings (see tables above)
6. Click **Test Connection** (should show "Connected")
7. Click **Finish**
8. **Repeat** for all 4 databases

### After Connecting:

**For each database**, expand:
```
DatabaseName
  └─ Schemas
      └─ public
          └─ Tables
              ├─ (click table to view data)
              └─ (right-click → View Data)
```

---

## Current Data Summary

### Check DB
- **6,457 check results** (6,089 FAIL)
- **284 unique rules**
- **444 rules** with compliance framework mappings

### Threat DB
- **489 threats** (6 critical, 347 high, 136 medium)
- **Categories**: Identity (240), Misconfiguration (134), Exposure (94), Data Exfil (21)
- **347 unique resources** affected

### Compliance DB
- **Tables created** (ready for compliance scan data)
- **Report generated**: Report ID `68971bcf-821a-47fc-a465-8d31c9dda2f9`
- **Frameworks**: CIS, PCI-DSS, ISO27001, SOC2 mapped

### Inventory DB
- **287 assets** indexed
- **97 relationships** mapped
- **Resource types**: IAM (136), S3 (21), EC2 (18), etc.

---

## Visual Diagram

```
┌─────────────────────────────────────────────────────┐
│  DBeaver Connections                                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. threat_engine_check (check_user)                │
│     └─ check_results (6,457 rows)                   │
│     └─ rule_metadata (1,918 rows)                   │
│        ├─ compliance_frameworks (444 mapped)        │
│        └─ threat_category (all categorized)         │
│                                                     │
│  2. threat_engine_threat (threat_user)              │
│     └─ threats (489 rows) ⭐                        │
│     └─ threat_resources (489 mappings)              │
│     └─ threat_scans (1 summary)                     │
│                                                     │
│  3. threat_engine_compliance (compliance_user)      │
│     └─ compliance_scans (ready)                     │
│     └─ framework_scores (ready)                     │
│     └─ control_results (ready)                      │
│                                                     │
│  4. threat_engine_inventory (inventory_user)        │
│     └─ asset_index_latest (287 assets)              │
│     └─ relationship_index_latest (97 relations)     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**All 4 databases are now set up and populated!**
