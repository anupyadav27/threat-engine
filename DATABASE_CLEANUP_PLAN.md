# Database Cleanup Plan - Remove Duplicate Tables

**Issue:** Both databases have the same tables (came from using configscan_schema.sql for both)

---

## ❌ **Current Problem**

### **threat_engine_discoveries has:**
```
✅ rule_definitions (2,501) - SHOULD BE HERE
✅ discoveries (169) - SHOULD BE HERE
✅ discovery_history - SHOULD BE HERE
✅ scans (5) - SHOULD BE HERE
✅ customers, tenants - SHOULD BE HERE

❌ check_results - SHOULDN'T BE HERE (belongs in check DB)
❌ rule_metadata - SHOULDN'T BE HERE (belongs in check DB)
❌ checks - SHOULDN'T BE HERE
❌ drift_detections - SHOULDN'T BE HERE
❌ csp_hierarchies - SHOULDN'T BE HERE
```

### **threat_engine_check has:**
```
✅ rule_metadata (1,918) - SHOULD BE HERE
✅ check_results - SHOULD BE HERE  
✅ scans (2) - SHOULD BE HERE
✅ customers, tenants - SHOULD BE HERE

❌ discoveries - SHOULDN'T BE HERE (belongs in discoveries DB)
❌ discovery_history - SHOULDN'T BE HERE
❌ rule_definitions - SHOULDN'T BE HERE (belongs in discoveries DB)
❌ drift_detections - SHOULDN'T BE HERE
❌ csp_hierarchies - SHOULDN'T BE HERE
```

---

## 🎯 **Correct Architecture**

### **threat_engine_discoveries (Discovery Engine)**
**Purpose:** Store discovered AWS resources

**Tables:**
- ✅ `rule_definitions` - Full YAML rules for loading discovery definitions
- ✅ `discoveries` - Discovered resources (current state)
- ✅ `discovery_history` - Resource version history & drift
- ✅ `scans` - Discovery scan metadata
- ✅ `customers`, `tenants` - FK references

### **threat_engine_check (Check Engine)**  
**Purpose:** Store security check results

**Tables:**
- ✅ `rule_metadata` - Parsed metadata for enriching findings
- ✅ `check_results` - Security check findings
- ✅ `scans` - Check scan metadata
- ✅ `customers`, `tenants` - FK references

---

## 🗑️ **Cleanup SQL**

### **Clean threat_engine_discoveries (keep discovery-related only):**

```sql
-- Drop check-related tables
DROP TABLE IF EXISTS check_results CASCADE;
DROP TABLE IF EXISTS checks CASCADE;
DROP TABLE IF EXISTS rule_metadata CASCADE;
DROP TABLE IF EXISTS drift_detections CASCADE;
DROP TABLE IF EXISTS csp_hierarchies CASCADE;
```

### **Clean threat_engine_check (keep check-related only):**

```sql
-- Drop discovery-related tables
DROP TABLE IF EXISTS discoveries CASCADE;
DROP TABLE IF EXISTS discovery_history CASCADE;
DROP TABLE IF EXISTS rule_definitions CASCADE;
DROP TABLE IF EXISTS drift_detections CASCADE;
DROP TABLE IF EXISTS csp_hierarchies CASCADE;
```

---

## 📦 **Rule Data Consolidation**

**Current:**
- `rule_definitions` (2,501 YAMLs) in discoveries DB
- `rule_metadata` (1,918 parsed) in check DB

**Options:**

### **Option A: Keep Separate (Current)**
**Pros:** Each engine owns its data  
**Cons:** Duplication, must sync both

### **Option B: Consolidate in Shared DB**
Move both to `threat_engine_shared`:
- `rule_definitions` - Full YAMLs
- `rule_metadata` - Parsed metadata

**Pros:** Single source of truth  
**Cons:** All engines depend on shared DB

### **Option C: Merge Tables**
Create single `rules` table with both YAML and parsed columns:
```sql
CREATE TABLE rules (
    rule_id PRIMARY KEY,
    service VARCHAR(100),
    
    -- Full YAML
    rule_yaml TEXT,
    metadata_yaml TEXT,
    
    -- Parsed fields
    title TEXT,
    severity VARCHAR(20),
    remediation TEXT,
    compliance_frameworks JSONB,
    ...
);
```

**Pros:** Everything in one place  
**Cons:** Larger table, complex schema

---

## ✅ **Recommended Action**

**Short-term:** Keep current structure but drop unused tables

**Long-term:** Move all rules to `threat_engine_shared` database

---

**Want me to clean up the duplicate tables now?**
