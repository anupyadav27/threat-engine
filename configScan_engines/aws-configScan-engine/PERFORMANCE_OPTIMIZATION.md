# Performance Optimization Guide

## Current Performance Analysis

### Scan Configuration
- **Total Tasks**: 7,720 (5 accounts × 17 regions × ~100 services)
- **Max Workers**: 20 (current bottleneck)
- **Current Rate**: ~0.18 tasks/sec (645 tasks/hour)
- **Estimated Time**: 13-24 hours for full scan

### Key Bottlenecks Identified

1. **Worker Count (Primary Bottleneck)**
   - Only 20 workers handling 7,720 tasks
   - Each worker processes 1 task at a time
   - Slow tasks (30-400s) block workers, causing queue buildup

2. **Very Slow Discoveries (>60s)**
   - EC2 `describe_images`: 396 seconds per discovery
   - SageMaker `list_device_fleets`: 266 seconds per discovery
   - Inspector `list_assessment_templates`: 218 seconds
   - Total: 190+ slow discoveries identified

3. **Service-Level Slowness**
   - Inspector: Avg 16.6s, Max 218s
   - SageMaker: Avg 10.3s, Max 266s
   - SecurityHub: Avg 16.3s, Max 133s

## Optimization Recommendations

### 1. Increase Worker Count (IMMEDIATE - Highest Impact)

**Change Required:**
```python
# In scan() call, change:
max_total_workers=20  # Current

# To:
max_total_workers=50  # Recommended (or 100 for maximum speed)
```

**Expected Impact:**
- 20 workers → 645 tasks/hour = 13 hours
- 50 workers → ~1,600 tasks/hour = ~5 hours
- 100 workers → ~2,500+ tasks/hour = ~3 hours

**Implementation:**
- Update scan command in `test_local_scan.py` or wherever scan is initiated
- No code changes needed - just parameter change

### 2. Service Availability Pre-Check (FUTURE)

**Concept:**
- Before creating tasks, probe services with independent discoveries
- Skip unavailable services (not available in region/account)
- Reduces task count from 7,720 to actual available services

**Implementation Status:** Not yet implemented (see design discussion)

### 3. Exclude Very Slow Services (OPTIONAL)

**Services to Consider Excluding:**
- Inspector (if not critical for compliance)
  - Avg 16.6s per discovery
  - 218s max per discovery
  - Saves ~1-2 hours for full scan

- SageMaker Device Fleets (if not needed)
  - `list_device_fleets`: 266s per discovery
  - Can skip if not using SageMaker Edge

**How to Exclude:**
```python
exclude_services=['inspector', 'sagemaker']  # Optional
```

### 4. Retry Logic Optimization

**Current Status:** ✅ Already Optimized
- Expected errors (NoSuch*, NotFound, MissingParameter) skip retries
- Retry events: 0 (confirmed in diagnostics)
- No further optimization needed

## Diagnostic Tools

### Performance Diagnostic Script

Run to analyze current scan:
```bash
python3 configScan_engines/aws-configScan-engine/diagnose_scan_performance.py [log_file]
```

**Outputs:**
- Task count and completion rate
- Slow discoveries identification
- Service-level statistics
- Error patterns
- Recommendations

**Example Usage:**
```bash
# Analyze latest scan
python3 diagnose_scan_performance.py

# Analyze specific scan
python3 diagnose_scan_performance.py engines-output/aws-configScan-engine/output/full_scan_all_optimized/logs/scan.log
```

## Expected Performance After Optimization

### With max_total_workers=50:
- **Rate**: ~1,600 tasks/hour
- **Time**: ~5 hours for 7,720 tasks
- **Improvement**: 2.5x faster

### With max_total_workers=100:
- **Rate**: ~2,500+ tasks/hour
- **Time**: ~3 hours for 7,720 tasks
- **Improvement**: 4x faster

### With Service Availability Pre-Check (Future):
- **Task Count**: Reduces from 7,720 to ~5,000-6,000 (estimated)
- **Additional Improvement**: 20-30% faster on top of worker increase

## Implementation Checklist

- [x] Created diagnostic script
- [x] Documented slow discoveries
- [x] Reviewed retry logic (already optimized)
- [ ] Update scan command to use max_total_workers=50 (user action required)
- [ ] Implement service availability pre-check (future enhancement)

## Notes

- Worker count can be safely increased to 50-100 without memory issues (stream_results=True)
- Slow discoveries are mostly AWS API limitations, not code issues
- Current retry logic is optimal (no retries for expected errors)
- Diagnostic script can be run anytime during or after scan


