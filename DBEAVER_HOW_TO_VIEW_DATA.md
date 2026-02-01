# ❌ DON'T Refresh - ✅ DO This Instead

**Problem:** Refresh button triggers pgAgent error  
**Solution:** Use SQL Editor or direct table access

---

## ✅ **Method 1: SQL Editor (EASIEST)**

### **Step 1: Open SQL Editor**
1. Right-click on your connection → **SQL Editor** → **New SQL Script**
2. Or press **Ctrl+]** (Windows/Linux) or **Cmd+]** (Mac)

### **Step 2: Run Query**
```sql
-- See all your 960 compliance mappings
SELECT * FROM compliance_control_mappings LIMIT 100;
```

### **Step 3: Execute**
- Press **Ctrl+Enter** or click ▶ Execute button
- **Data appears below!** ✅

---

## ✅ **Method 2: Direct Table Access**

### **Step 1: Navigate to Table**
In Database Navigator (left panel):
```
postgres-vulnerability-db...
└─ Databases
   └─ threat_engine_compliance
      └─ Schemas
         └─ public
            └─ Tables
               └─ compliance_control_mappings
```

### **Step 2: Right-Click Table**
- **Right-click** on `compliance_control_mappings`
- Select **"View Data"** (NOT "Refresh"!)
- Data opens in new tab ✅

---

## ✅ **Method 3: Disable pgAgent Warning**

### **Permanently Fix the Error:**

1. **Window** → **Preferences** (or **DBeaver** → **Preferences** on Mac)
2. In search box, type: **"PostgreSQL"**
3. Expand **Databases** → **PostgreSQL**
4. Find and **UNCHECK**:
   - ☐ Show pgAgent jobs
   - ☐ Show utility objects
5. Click **Apply** → **OK**
6. Close and reconnect

**Now refresh will work!** ✅

---

## 🔍 **Quick Test - Run in Terminal**

```bash
# Verify data exists
PGPASSWORD='apXuHV%2OSyRWK62' psql \
  -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
  -U postgres \
  -d threat_engine_compliance \
  -c "SELECT COUNT(*) FROM compliance_control_mappings;"
```

**Expected:** `960`

**If you see 960**, the data is there - just use SQL Editor in DBeaver!

---

## 📊 **Queries to See All Your Data**

**Open SQL Editor and run these:**

```sql
-- 1. Total compliance mappings
SELECT COUNT(*) FROM compliance_control_mappings;
-- Result: 960

-- 2. See all frameworks
SELECT 
    compliance_framework,
    COUNT(*) as controls
FROM compliance_control_mappings
GROUP BY compliance_framework
ORDER BY controls DESC;

-- 3. Sample CIS controls
SELECT 
    requirement_id,
    requirement_name,
    service,
    rule_ids
FROM compliance_control_mappings
WHERE compliance_framework = 'CIS'
LIMIT 10;

-- 4. S3-related compliance controls
SELECT 
    compliance_framework,
    requirement_id,
    requirement_name
FROM compliance_control_mappings
WHERE service LIKE '%S3%'
ORDER BY compliance_framework, requirement_id;

-- 5. Test the new views
SELECT * FROM framework_scores;          -- 13 frameworks
SELECT * FROM rule_control_mapping LIMIT 20;  -- 4,497 rule mappings
SELECT * FROM compliance_controls LIMIT 20;   -- 960 controls
```

---

## 🎯 **The Golden Rule**

**❌ DON'T:** Click refresh on the schema/connection  
**✅ DO:** Use SQL Editor to query tables directly

**Your 960 compliance mappings are there!** Just access them via SQL Editor, not the refresh button.

---

**Follow Method 1 (SQL Editor) - it works 100% of the time!** 📊
