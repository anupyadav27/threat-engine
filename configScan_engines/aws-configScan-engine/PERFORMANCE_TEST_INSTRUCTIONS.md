# Performance Test Instructions

## ✅ No Running Scans Detected

The system is ready for testing.

## 🚀 Test Script Created

**File:** `test_performance_optimized.py`

**Tests:**
- EC2 (high time-consuming service)
- Inspector (previously very slow)
- SageMaker (previously very slow)

**Scope:**
- Single account (default)
- Single region: us-east-1
- Optimized settings: max_total_workers=100

## 📊 How to Run the Test

### Option 1: Run Directly
```bash
cd configScan_engines/aws-configScan-engine
python3 test_performance_optimized.py
```

### Option 2: Run in Background and Monitor
```bash
cd configScan_engines/aws-configScan-engine
python3 test_performance_optimized.py > /tmp/scan_test.log 2>&1 &
tail -f /tmp/scan_test.log
```

### Option 3: Use Monitor Script
```bash
cd configScan_engines/aws-configScan-engine
python3 test_performance_optimized.py &
./monitor_test_scan.sh
```

## 📈 Expected Performance Improvements

### EC2 describe_images
- **Before:** 78+ minutes (without OwnerIds filter)
- **After:** 10-30 seconds (with OwnerIds: ['self'] + default pagination)
- **Improvement:** ~150-500x faster

### Inspector list_assessment_templates
- **Before:** Very slow (no MaxResults, incomplete results)
- **After:** Fast (MaxResults: 1000 + automatic pagination)
- **Improvement:** Complete results + much faster

### SageMaker list_device_fleets
- **Before:** Very slow (no MaxResults, incomplete results)
- **After:** Fast (MaxResults: 1000 + automatic pagination)
- **Improvement:** Complete results + much faster

## 🔍 What to Check

1. **Scan Duration:**
   - Should complete in < 5 minutes for these 3 services
   - If > 10 minutes, check logs for issues

2. **Results Files:**
   - Check: `engines-output/aws-configScan-engine/output/test_performance_*/results_*.ndjson`
   - Should contain compliance check results

3. **Inventory Files:**
   - Check: `engines-output/aws-configScan-engine/output/test_performance_*/inventory_*.ndjson`
   - Should contain discovered resources

4. **Log Messages:**
   - Look for: "Added default MaxResults: 1000 for {action}"
   - This confirms default pagination is working

5. **Performance Metrics:**
   - Total time should be displayed at end
   - Compare with previous scan times

## 🎯 Success Criteria

✅ Scan completes in < 5 minutes  
✅ All 3 services scanned successfully  
✅ Results files created  
✅ No errors in logs  
✅ Default pagination messages appear  

## 📝 Check Results

After scan completes, check:
```bash
# Find latest test scan
ls -lt engines-output/aws-configScan-engine/output/test_performance_*/

# Check results
cat engines-output/aws-configScan-engine/output/test_performance_*/results_*.ndjson | wc -l

# Check inventory
cat engines-output/aws-configScan-engine/output/test_performance_*/inventory_*.ndjson | wc -l
```

## 🔧 Optimizations Active

1. **Default Pagination:**
   - MaxResults: 1000 automatically added
   - All pages fetched automatically
   - No YAML changes needed

2. **Customer-Managed Filters:**
   - EC2: OwnerIds: ['self']
   - Inspector: MaxResults: 1000
   - SageMaker: MaxResults: 1000

3. **Worker Counts:**
   - max_total_workers: 100
   - MAX_DISCOVERY_WORKERS: 50
   - FOR_EACH_MAX_WORKERS: 50

