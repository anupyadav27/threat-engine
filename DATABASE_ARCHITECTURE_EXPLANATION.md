# Database Architecture - Tables Explained

**Current Issue:** Duplicate tables across databases, rule data split

---

## 📊 **Current State - What's Where**

### **threat_engine_discoveries DB**

**Tables:**
```
✅ rule_definitions (2,501 rows)
   - 211 rules YAML files (rules/s3.yaml, rules/iam.yaml, etc.)
   - 1,918 metadata YAML files (metadata/aws.s3.bucket.encryption.yaml, etc.)
   - 372 other files (backups, etc.)
   - Content: Full YAML text

✅ discoveries (169 rows) - Discovered resources
✅ discovery_history (0 rows) - Resource version history
✅ scans (5 rows) - Scan metadata
❌ customers, tenants, check_results, etc. - Duplicates (shouldn't be here)
```

### **threat_engine_check DB**

**Tables:**
```
✅ rule_metadata (1,918 rows)
   - Parsed metadata from those 1,918 YAML files
   - Columns: rule_id, title, severity, remediation, compliance_frameworks
   - Used for: Enriching check findings

✅ check_results (0 rows) - Security check findings
✅ scans (2 rows) - Scan metadata
❌ discoveries, discovery_history, etc. - Duplicates (shouldn't be here)
```

---

## ⚠️ **Problems with Current Design**

### **1. Duplicate Tables**
Both databases have: scans, discoveries, check_results, customers, tenants

**Why:** We used the same base schema (originally configscan_schema.sql) for both

### **2. Rule Data Split Across 2 Databases**
- **rule_definitions** (2,501 YAML files) in `threat_engine_discoveries`
- **rule_metadata** (1,918 parsed records) in `threat_engine_check`

**Why:** 
- Discoveries engine needs full YAML to load discovery definitions
- Check engine needs parsed metadata to enrich findings

### **3. Missing Data**
- rule_metadata (1,918) < rule_definitions metadata files (1,918)
- They should be the same count!

---

## 🔧 **Recommended Fix**

### **Option 1: Consolidate Rule Tables (Recommended)**

**Create single `rules` table in shared database:**

```sql
-- In threat_engine_shared:
CREATE TABLE rules (
    rule_id VARCHAR(255) PRIMARY KEY,
    service VARCHAR(100),
    
    -- Full YAML content (for discoveries engine)
    rule_yaml TEXT,
    metadata_yaml TEXT,
    
    -- Parsed metadata (for check/compliance/threat engines)
    title TEXT,
    severity VARCHAR(20),
    description TEXT,
    remediation TEXT,
    compliance_frameworks JSONB,
    threat_category VARCHAR(50),
    risk_score INTEGER,
    
    -- Both engines read from here
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Benefits:**
- ✅ Single source of truth
- ✅ No duplication
- ✅ All engines read from shared DB

---

### **Option 2: Keep Separate but Clean Up**

**threat_engine_discoveries:**
- Keep: rule_definitions, discoveries, discovery_history, scans
- Remove: check_results (not used)

**threat_engine_check:**
- Keep: rule_metadata, check_results, scans
- Remove: discoveries, discovery_history (not used)

**Benefits:**
- ✅ Each engine owns its data
- ✅ No cross-contamination
- ❌ Still have 2 rule tables

---

## 🎯 **What You Should Do**

**For now (to see all data in DBeaver):**

1. **Connect to `threat_engine_discoveries`:**
   - View `rule_definitions` table (2,501 rows - full YAMLs)
   - View `discoveries` table (169 rows - S3 buckets)

2. **Connect to `threat_engine_check`:**
   - View `rule_metadata` table (1,918 rows - parsed metadata)
   - View `check_results` table (will have data after successful checks)

3. **Ignore duplicate tables** - they're empty anyway

---

## 📋 **Quick Check - What Has Data**

```sql
-- In threat_engine_discoveries:
SELECT COUNT(*) FROM rule_definitions;  -- 2501 ✅
SELECT COUNT(*) FROM discoveries;      -- 169 ✅

-- In threat_engine_check:
SELECT COUNT(*) FROM rule_metadata;    -- 1918 ✅
SELECT COUNT(*) FROM check_results;    -- 0 (no checks run successfully yet)
```

---

**The data is there! Just in 2 different tables across 2 databases. Want me to consolidate into a single rules table?**
