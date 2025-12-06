# GCP Compliance Engine - Testing Guide

## Overview

This guide explains how to comprehensively test the GCP compliance engine against actual GCP resources.

---

## 🚀 Quick Start - Comprehensive Testing

### **Option 1: Automated Test (Provisions → Tests → Reports)**

```bash
# Run full test with auto-provisioned resources
./run_comprehensive_test.sh <project_id> <region>

# Example:
./run_comprehensive_test.sh test-2277 us-central1
```

This will:
1. ✅ Provision test resources (GCS, Compute, Pub/Sub, BigQuery, KMS, IAM, Secrets)
2. ✅ Run compliance scan across all services
3. ✅ Generate detailed report
4. ✅ Provide cleanup command

**Time**: ~5-10 minutes  
**Cost**: ~$1-2 (cleanup immediately to minimize)

---

### **Option 2: Manual Step-by-Step**

#### **Step 1: Provision Resources**
```bash
./provision_test_resources.sh test-2277 us-central1
```

Resources created:
- 2 GCS buckets (with/without versioning)
- 1 Compute instance (e2-micro)
- 1 Compute disk
- 1 Firewall rule (insecure for testing)
- 1 Pub/Sub topic + subscription
- 1 BigQuery dataset
- 1 KMS keyring + key
- 1 IAM service account
- 1 Secret Manager secret

#### **Step 2: Run Compliance Scan**
```bash
source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"
export GCP_PROJECTS="test-2277"

# Full scan
python engine/gcp_engine.py > scan_results.json

# Or filtered scan
export GCP_ENGINE_FILTER_SERVICES="gcs,compute,pubsub"
python engine/gcp_engine.py > scan_filtered.json
```

#### **Step 3: Analyze Results**
```bash
# Pretty print
cat scan_results.json | python -m json.tool | less

# Summary
cat scan_results.json | python -c "
import json, sys
data = json.load(sys.stdin)
total = sum(len(r.get('checks', [])) for r in data)
passed = sum(sum(1 for c in r.get('checks', []) if c.get('result')=='PASS') for r in data)
print(f'Total: {passed}/{total} ({round(passed/total*100,1)}%)')
"
```

#### **Step 4: Cleanup**
```bash
./cleanup_test_resources.sh test-2277
```

---

## 🎯 Testing Individual Services

### **Test Single Service:**
```bash
export GCP_ENGINE_FILTER_SERVICES="gcs"
export GCP_PROJECTS="test-2277"
python engine/gcp_engine.py | python -m json.tool
```

### **Test with Region Filter:**
```bash
export GCP_ENGINE_FILTER_SERVICES="compute"
export GCP_ENGINE_FILTER_REGIONS="us-central1,us-east1"
python engine/gcp_engine.py
```

### **Test Specific Check:**
```bash
export GCP_ENGINE_FILTER_CHECK_IDS="gcp.storage.bucket.bucket_object_versioning"
python engine/gcp_engine.py
```

---

## 📊 Systematic Service Testing

### **Test All Services One-by-One:**
```bash
python test_all_services.py
```

This will:
- Test each of the 41 configured services
- Report which ones work vs have errors
- Show inventory and check counts
- Save detailed results to `service_test_results.json`

---

## 🧪 Testing Checklist

### **Before Testing:**
- [ ] Virtual environment activated
- [ ] PYTHONPATH set correctly
- [ ] GCP credentials configured (`gcloud auth application-default login`)
- [ ] Test project selected

### **During Testing:**
- [ ] Monitor for engine errors (should be 0)
- [ ] Check discovery finds resources
- [ ] Verify checks execute
- [ ] Note warnings (API disabled = expected, not error)

### **After Testing:**
- [ ] Review pass/fail rates
- [ ] Identify rule parameter issues (not engine bugs)
- [ ] Cleanup test resources if provisioned
- [ ] Document findings

---

## 📈 Expected Results

### **Engine Health:**
- ✅ **0 engine errors** across all services
- ✅ **Warnings OK** - API disabled/no resources (handled gracefully)
- ✅ **Pass/fail** - Based on actual GCP config compliance

### **Service Coverage:**
- **With resources**: Checks execute, pass/fail based on config
- **Without resources**: 0 checks, 0 errors (expected)
- **API disabled**: Warnings, but no engine crash (expected)

### **Typical Results:**
- **GCS**: 40-50% pass (many optional features not configured)
- **Compute**: 85-95% pass (good security defaults)
- **Other services**: Varies based on configuration

---

## 🔧 Troubleshooting

### **"API not enabled" warnings:**
- **Expected**: Service not enabled in test project
- **Fix**: Enable API or test with different project
- **Impact**: No checks for that service, but no engine error ✅

### **"0 checks executed":**
- **Expected**: No resources of that type exist
- **Fix**: Provision test resources or use project with existing resources
- **Impact**: Can't test checks, but engine works ✅

### **Actual engine errors:**
- **Unexpected**: Should not happen
- **Fix**: Check YAML syntax, action names, field paths
- **Report**: This indicates a real issue to fix

---

## 📋 Resource Costs

**Estimated costs for full test:**
- Compute instance (e2-micro): ~$0.01/hour
- GCS buckets: ~$0.01/month
- Other resources: Minimal

**Total**: ~$1-2 for full test cycle (if cleaned up within 1 hour)

**Recommendation**: Run comprehensive test, then cleanup immediately.

---

## 🎯 Quick Commands

```bash
# Full automated test
./run_comprehensive_test.sh test-2277 us-central1

# Just provision
./provision_test_resources.sh test-2277 us-central1

# Just scan
python engine/gcp_engine.py > results.json

# Just cleanup
./cleanup_test_resources.sh test-2277

# Test specific service
export GCP_ENGINE_FILTER_SERVICES="gcs"
python engine/gcp_engine.py | python -m json.tool
```

---

## ✅ Success Criteria

A successful test shows:
1. ✅ Engine runs without fatal errors
2. ✅ Discovery finds provisioned resources
3. ✅ Checks execute for each resource
4. ✅ Results show PASS/FAIL based on config
5. ✅ All services tested (with/without resources)

**The engine is working if it runs all checks without errors, regardless of pass/fail rates.**

---

## 📞 Support

Issues? Check:
1. `YAML_ACTION_PATTERNS.md` - YAML structure guidelines
2. `ENGINE_STATUS.md` - Engine capabilities
3. `SESSION_SUMMARY.md` - Implementation notes
4. `FINAL_STATUS.md` - Current state

The engine is designed to run without errors. Pass/fail rates depend on your GCP configuration!

