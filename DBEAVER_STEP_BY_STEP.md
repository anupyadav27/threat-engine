# DBeaver - Step by Step Guide to See Your Data

**Problem:** Can't see data in RDS  
**Solution:** Follow these EXACT steps

---

## 📋 **Step 1: Create New PostgreSQL Connection**

1. Open **DBeaver**
2. Click **Database** menu → **New Database Connection**
3. Select **PostgreSQL** → Click **Next**

---

## 📋 **Step 2: Fill in Connection Details**

**COPY AND PASTE EXACTLY:**

```
Host:     postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
Port:     5432
Database: threat_engine_discoveries
Username: postgres
Password: apXuHV%2OSyRWK62
```

**Important Settings:**
- ☑ **Check** "Show all databases"
- ☐ **Uncheck** "Show all schemas" (or leave default)

---

## 📋 **Step 3: Configure SSL**

Click the **SSL** tab:
- **SSL mode:** Select **`require`** from dropdown
- Leave everything else as default

---

## 📋 **Step 4: Test Connection**

1. Click **"Test Connection"** button (bottom left)
2. If prompted to download driver, click **Download**
3. You should see: **"Connected"** message ✅

**If you get an error:**
- Check password is exactly: `apXuHV%2OSyRWK62` (with the percent sign)
- Ensure SSL mode is set to `require`
- Check you're on a network that can reach AWS (not blocked by firewall)

---

## 📋 **Step 5: Navigate to Data**

After connection succeeds, in the **Database Navigator** (left panel):

```
1. Expand: postgres-vulnerability-db... (the connection)
2. Expand: Databases
3. Expand: threat_engine_discoveries
4. Expand: Schemas
5. Expand: public
6. Expand: Tables
7. Click: discoveries ← THIS IS WHERE YOUR DATA IS!
```

---

## 📋 **Step 6: View the Data**

**Right-click** on `discoveries` table → **View Data**

**You should see 169 rows with:**
- id, scan_id, service, discovery_id
- resource_uid (like `arn:aws:s3:::cspm-lgtech`)
- emitted_fields (JSON with bucket details)
- raw_response (full AWS API response)

---

## 📊 **What's in the Database RIGHT NOW**

| Table | Row Count | Description |
|-------|-----------|-------------|
| **discoveries** | **169** | ✅ S3 bucket discoveries |
| **scans** | **5** | ✅ Scan metadata |
| **rule_definitions** | **2,501** | ✅ Rule YAMLs |
| **customers** | **1** | ✅ dbeaver-demo |
| **tenants** | **1** | ✅ dbeaver-demo |

---

## 🔍 **Test Queries in DBeaver**

**After connecting, open SQL Editor and run:**

```sql
-- Total discoveries
SELECT COUNT(*) FROM discoveries;
-- Result: 169

-- Discoveries by type
SELECT 
  service,
  discovery_id,
  COUNT(*) as count
FROM discoveries
GROUP BY service, discovery_id
ORDER BY count DESC;

-- Sample S3 buckets
SELECT 
  resource_uid as bucket_arn,
  emitted_fields->>'Name' as bucket_name,
  emitted_fields->>'CreationDate' as created
FROM discoveries
WHERE discovery_id = 'aws.s3.list_buckets'
LIMIT 10;

-- Bucket encryption status
SELECT 
  resource_uid,
  emitted_fields->>'ServerSideEncryptionConfiguration' as encryption
FROM discoveries
WHERE discovery_id = 'aws.s3.get_bucket_encryption'
LIMIT 5;
```

---

## ⚠️ **Troubleshooting**

### **Can't connect:**
- Verify you can ping the host from your machine
- Check firewall/VPN settings
- Ensure RDS security group allows your IP on port 5432

### **Connected but see 0 rows:**
- Make sure you're looking at `threat_engine_discoveries` database
- Check you're viewing the `discoveries` table (not `discovery_history`)
- Click **Refresh** button in DBeaver
- Run: `SELECT COUNT(*) FROM discoveries;` in SQL Editor

### **See wrong database:**
- You might be connected to old `threat_engine_configscan` (doesn't exist)
- Delete that connection and create new one

---

## ✅ **Expected Data Structure**

**Sample discovery record:**

```json
{
  "id": 1,
  "scan_id": "discovery_20260201_035020",
  "service": "s3",
  "discovery_id": "aws.s3.list_buckets",
  "resource_uid": "arn:aws:s3:::cspm-lgtech",
  "emitted_fields": {
    "Name": "cspm-lgtech",
    "BucketArn": "arn:aws:s3:::cspm-lgtech",
    "CreationDate": "2024-12-15T10:30:00Z",
    "BucketRegion": "ap-south-1"
  }
}
```

---

**Follow these steps and you WILL see 169 discoveries!** The data is definitely there. 🎯
