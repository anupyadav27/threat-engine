# 🔗 DBeaver Connection Guide - RDS Databases

**Complete setup instructions for all 3 main databases**

---

## 📝 **Quick Setup (Copy-Paste)**

### **Common Settings for ALL Connections:**
```
Host:     postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
Port:     5432
Username: postgres
Password: apXuHV%2OSyRWK62
SSL Mode: require
```

**Only change:** Database name for each connection

---

## 🔧 **Connection 1: Discoveries Engine**

### **Settings:**
| Field | Value |
|-------|-------|
| Connection Name | `RDS - Discoveries Engine` |
| Host | `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |
| Port | `5432` |
| Database | **`threat_engine_discoveries`** |
| Username | `postgres` |
| Password | `apXuHV%2OSyRWK62` |
| SSL | `require` |
| Show all databases | ☑ Yes |

### **Data You'll See:**

**`rule_definitions` table: 2,501 rows**
- 211 rule files (`rules/*.yaml`)
- 1,918 metadata files (`metadata/*.yaml`)
- 372 other files

**Verification Query:**
```sql
-- Total rules
SELECT COUNT(*) FROM rule_definitions;

-- Breakdown
SELECT 
  CASE 
    WHEN file_path LIKE 'rules/%' THEN 'Rules YAML'
    WHEN file_path LIKE 'metadata/%' THEN 'Metadata YAML'
    WHEN file_path LIKE 'backup%' THEN 'Backup'
    ELSE 'Other'
  END as type,
  COUNT(*) as count
FROM rule_definitions
GROUP BY type
ORDER BY count DESC;

-- Sample IAM discovery rule
SELECT content_yaml 
FROM rule_definitions 
WHERE service = 'iam' AND file_path = 'rules/iam.yaml';
```

**Empty Tables (waiting for scans):**
- `discoveries` - 0 rows (will populate when discovery scan runs)
- `discovery_history` - 0 rows (resource version tracking)
- `scans` - 0 rows (scan metadata)

---

## 🔧 **Connection 2: Check Engine**

### **Settings:**
| Field | Value |
|-------|-------|
| Connection Name | `RDS - Check Engine` |
| Host | `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |
| Port | `5432` |
| Database | **`threat_engine_check`** |
| Username | `postgres` |
| Password | `apXuHV%2OSyRWK62` |
| SSL | `require` |
| Show all databases | ☑ Yes |

### **Data You'll See:**

**`rule_metadata` table: 1,918 rows**

**Verification Query:**
```sql
-- Total metadata
SELECT COUNT(*) FROM rule_metadata;

-- Sample records
SELECT 
  rule_id,
  service,
  severity,
  title,
  domain
FROM rule_metadata
LIMIT 10;

-- Severity breakdown
SELECT 
  severity,
  COUNT(*) as count
FROM rule_metadata
GROUP BY severity
ORDER BY 
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    ELSE 5
  END;

-- IAM security rules
SELECT 
  rule_id,
  title,
  severity,
  remediation
FROM rule_metadata
WHERE service = 'iam'
  AND severity IN ('high', 'critical')
LIMIT 5;
```

**Empty Tables (waiting for scans):**
- `check_results` - 0 rows (will populate when check scan runs)
- `scans` - 0 rows

---

## 🔧 **Connection 3: Compliance Engine**

### **Settings:**
| Field | Value |
|-------|-------|
| Connection Name | `RDS - Compliance Engine` |
| Host | `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |
| Port | `5432` |
| Database | **`threat_engine_compliance`** |
| Username | `postgres` |
| Password | `apXuHV%2OSyRWK62` |
| SSL | `require` |
| Show all databases | ☑ Yes |

### **Data You'll See:**

**`compliance_control_mappings` table: 960 rows**

**Verification Query:**
```sql
-- Total mappings
SELECT COUNT(*) FROM compliance_control_mappings;

-- Frameworks
SELECT 
  compliance_framework,
  framework_version,
  COUNT(*) as total_controls
FROM compliance_control_mappings
GROUP BY compliance_framework, framework_version
ORDER BY total_controls DESC;

-- CIS AWS IAM controls
SELECT 
  requirement_id,
  requirement_name,
  service,
  rule_ids
FROM compliance_control_mappings
WHERE compliance_framework = 'CIS'
  AND service = 'IAM'
LIMIT 10;

-- Controls mapped to specific rule
SELECT 
  requirement_id,
  requirement_name,
  compliance_framework
FROM compliance_control_mappings
WHERE 'aws.iam.user.mfa_required' = ANY(rule_ids)
LIMIT 10;
```

---

## ⚠️ **Why You See Only Rule Data, No Scan Data**

**Current State:**
- ✅ **Rules uploaded** to databases
- ❌ **No scans run yet**

**To get scan data:**
1. Run a discovery scan → populates `discoveries` table
2. Run a check scan → populates `check_results` table
3. Run compliance analysis → populates compliance reports

**Engines are deployed but waiting for scan requests!**

---

## 🎯 **All 6 Databases on Same Connection**

**Pro Tip:** In any of the connections above, expand the connection tree in DBeaver:

```
📁 postgres-vulnerability-db.cbm92xowvx2t...
├─ 📁 Databases
│  ├─ 📁 threat_engine_check          ⭐ 1,918 rule_metadata
│  ├─ 📁 threat_engine_compliance     ⭐ 960 compliance_control_mappings
│  ├─ 📁 threat_engine_discoveries    ⭐ 2,501 rule_definitions
│  ├─ 📁 threat_engine_inventory
│  ├─ 📁 threat_engine_shared
│  └─ 📁 threat_engine_threat
```

You can browse all 6 databases from a single connection!

---

**Create these 3 connections in DBeaver and you'll see all your data!** The scan data tables are empty because no scans have run yet - that's normal.