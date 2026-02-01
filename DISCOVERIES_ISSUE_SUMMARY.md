# Discoveries Engine Issue - Resolution Summary

**Date:** February 1, 2026  
**Status:** IN PROGRESS - Database configured, AWS credentials needed

---

## ✅ **Issues FIXED**

1. ✅ **DatabaseManager creation** - Fixed, now initializes successfully
2. ✅ **RDS connection** - Working, health shows "database":"connected"
3. ✅ **Missing resource_uid column** - Added to discoveries table
4. ✅ **Scans table** - Writing scan records successfully (4 scans recorded)
5. ✅ **Service account** - Changed to aws-compliance-engine-sa (has IAM role)

---

## ⚠️ **Remaining Issue: AWS API Calls Return Empty**

### **Current Behavior:**
```
✅ Scan starts successfully
✅ Loads 28 S3 discovery definitions
✅ Executes 4 discoveries
❌ Returns 0 items (no S3 buckets found)
❌ 0 discoveries written to RDS
```

### **Root Cause:**
AWS API calls (like `list_buckets`) are returning **empty responses**.

**Possible reasons:**
1. **No AWS credentials** - Container can't authenticate to AWS
2. **Wrong credentials** - Using node role which may not have S3 permissions
3. **No resources** - Account actually has no S3 buckets (unlikely)

---

## 🔧 **Solution: Pass AWS Credentials in API Request**

### **API Accepts Credentials:**

```json
{
  "customer_id": "test",
  "tenant_id": "test",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "include_services": ["s3"],
  "include_regions": ["us-east-1"],
  "use_database": true,
  "credentials": {
    "credential_type": "aws_access_key",
    "access_key_id": "AKIAEXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

---

## 📊 **What's in RDS Now (DBeaver)**

### **threat_engine_discoveries:**

**Tables with data:**
```sql
SELECT COUNT(*) FROM rule_definitions;  -- 2501 ✅
SELECT COUNT(*) FROM scans;              -- 4 ✅ (scans recorded!)
SELECT COUNT(*) FROM customers;          -- 1 ✅ (dbeaver-demo)
SELECT COUNT(*) FROM tenants;            -- 1 ✅ (dbeaver-demo)
SELECT COUNT(*) FROM discoveries;        -- 0 (waiting for successful scan)
```

**Scans table:**
```sql
SELECT scan_id, service, status, metadata->>'services' as services
FROM scans
ORDER BY scan_timestamp DESC;
```

**Result:**
```
scan_id                   | service | status    | services
discovery_20260201_034654 |         | completed | ["s3"]
discovery_20260201_034159 |         | completed | ["s3"]
discovery_20260201_033914 |         | completed | ["s3"]
discovery_20260201_033755 |         | completed | ["iam"]
```

---

## 🎯 **Next Steps to See Data in DBeaver**

### **Option 1: Use Valid AWS Credentials (Recommended)**

Test with actual AWS access keys:

```bash
curl -X POST http://localhost:9001/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "dbeaver-demo",
    "tenant_id": "dbeaver-demo",
    "provider": "aws",
    "hierarchy_id": "588989875114",
    "include_services": ["s3"],
    "include_regions": ["us-east-1"],
    "use_database": true,
    "credentials": {
      "credential_type": "aws_access_key",
      "access_key_id": "YOUR_ACTUAL_KEY",
      "secret_access_key": "YOUR_ACTUAL_SECRET"
    }
  }'
```

### **Option 2: Fix IRSA (IAM Roles for Service Accounts)**

Ensure `aws-compliance-engine-sa` role has permissions:
- s3:ListAllMyBuckets
- s3:GetBucketLocation
- s3:ListBucket
- iam:List*
- iam:Get*

---

## ✅ **Summary**

**Database-first architecture:** ✅ **WORKING**
- RDS databases created
- Rules/metadata uploaded
- Engines connected to RDS
- Scans being recorded

**Missing:** Valid AWS credentials to actually discover resources

**For DBeaver:** You can see scans table populated, but discoveries table is empty until a scan runs with valid AWS credentials.

---

**Provide AWS credentials in the API request to populate the discoveries table!**
