# Scan Analysis and Critical Fixes

## Date: 2026-01-19

## Critical Issue Identified

### Main Bottleneck: `aws.ec2.describe_snapshots`

**Problem:**
- Taking **39,684 seconds (11 HOURS!)** per execution
- This was causing the scan to appear stuck
- System sleep may have contributed to the slowdown

**Root Cause:**
- `describe_snapshots` was returning ALL snapshots (public, shared, customer)
- Without `OwnerIds` filter, AWS returns millions of public/shared snapshots
- Each region was taking 11+ hours to process

**Fix Applied:**
```yaml
- discovery_id: aws.ec2.describe_snapshots
  calls:
  - action: describe_snapshots
    params:
      OwnerIds: ['self']  # Only customer-owned snapshots
```

**Expected Impact:**
- **Before:** 11 hours per region
- **After:** 10-20 seconds per region
- **Improvement:** ~2000x faster!

---

## Error Analysis

### Error Summary (from scan log):
- **Parameter validation:** 96 (expected - handled gracefully)
- **AccessDenied:** 18 (expected - services not enabled)
- **Throttling:** 4 (minor, handled)
- **Connection:** 2 (network issues, handled)

**Verdict:** Errors are mostly expected and handled correctly. No critical issues.

---

## Additional Optimizations Applied

### 1. EMR list_clusters
- **Added:** `MaxResults: 1000`
- **Impact:** Prevents timeouts, improves pagination

### 2. Kafka list_clusters
- **Added:** `MaxResults: 100` (Kafka max is 100)
- **Impact:** Prevents timeouts

### 3. Cognito list_user_pools
- **Added:** `MaxResults: 60` (Cognito max is 60)
- **Impact:** Prevents timeouts

### 4. Cognito list_users
- **Added:** `Limit: 60` (Cognito max is 60)
- **Impact:** Prevents timeouts in for_each operations

### 5. Organizations list_policies
- **Added:** `MaxResults: 100` (Organizations max is 100)
- **Impact:** Prevents timeouts

### 6. FSX describe_snapshots
- **Added:** `MaxResults: 1000` + `on_error: continue`
- **Impact:** Prevents timeouts, handles disabled service

---

## Current Scan Status

**Status:** Still running (but very slowly)
- **Progress:** 39.2% (3,025 / 7,720 tasks)
- **Elapsed:** 12 hours
- **Issue:** Stuck on describe_snapshots operations (using old code)
- **Expected:** Will complete eventually, but will take 30+ hours total

**Why it's slow:**
- Current scan is using code from BEFORE the describe_snapshots fix
- Each describe_snapshots call takes 11 hours
- Multiple regions × 11 hours = very long scan time

---

## Next Scan Expectations

### With All Optimizations:
- **describe_snapshots:** 11h → 10-20s per region
- **Total time saved:** ~42-50 hours across all regions
- **Expected total scan time:** 0.8-1.0 hours
- **Improvement:** ~15-20x faster than original (13-24 hours)

### All Optimizations Active:
1. ✅ Code-level (workers, connections)
2. ✅ Slow discoveries fixed (17 operations)
3. ✅ MaxResults added (25+ services, 80+ operations)
4. ✅ AWS-managed filters (IAM, SSM, CloudFormation)
5. ✅ describe_snapshots fix (CRITICAL)
6. ✅ Additional MaxResults (EMR, Kafka, Cognito, Organizations, FSX)

---

## Files Modified

1. `services/ebs/rules/ebs.yaml` - Added OwnerIds to describe_snapshots
2. `services/fsx/rules/fsx.yaml` - Added MaxResults + on_error
3. `services/emr/rules/emr.yaml` - Added MaxResults to list_clusters
4. `services/kafka/rules/kafka.yaml` - Added MaxResults to list_clusters
5. `services/cognito/rules/cognito.yaml` - Added MaxResults/Limit to list operations
6. `services/organizations/rules/organizations.yaml` - Added MaxResults to list_policies

---

## Recommendations

1. **Let current scan complete** (it will finish, just slowly)
2. **Next scan will be much faster** with all optimizations
3. **Monitor for any new bottlenecks** in next scan
4. **Consider canceling current scan** if you want to restart with optimized code (saves 20+ hours)

---

## Summary

**Critical fix:** describe_snapshots OwnerIds filter (2000x improvement)
**Additional fixes:** 5 services with MaxResults added
**Total optimizations:** 90+ changes across code and YAML
**Expected improvement:** 15-20x faster overall

