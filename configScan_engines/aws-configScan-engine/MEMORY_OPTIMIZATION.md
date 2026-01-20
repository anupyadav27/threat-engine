# Memory Optimization: Clear Data After Writing

## Overview

Implemented **Option 1: Clear Memory After Writing** to reduce peak memory usage when running many services in parallel.

## Problem

With `max_total_workers=100`, up to 100 services can run simultaneously, each holding:
- `discovery_results`: 10-50MB per service (for large services like EC2)
- `saved_data` (raw API responses): 10-100MB per service
- **Peak memory**: 100 × 50MB = ~5GB (worst case: 20GB)

## Solution

After writing data to disk, we immediately clear large data structures:

1. **Delete `_raw_data`**: Raw API responses are already written to disk, so we delete them from memory
2. **Replace `inventory` with counts**: Full inventory is already written to disk, so we replace it with summary counts
3. **Keep essential data**: Service metadata, checks, and counts are kept for summary/aggregation

## Implementation

### Modified Functions

1. **`_scan_service_task()` (Flattened Model)**
   - Clears `_raw_data` after `_write_service_result()`
   - Replaces `inventory` with summary counts
   - Location: `main_scanner.py` line ~890

2. **`scan_account_region_scope()` (Account+Region Model)**
   - Clears `_raw_data` after `_write_result()`
   - Replaces `inventory` with summary counts
   - Location: `main_scanner.py` line ~1889

3. **`scan_account_global_services()` (Global Services)**
   - Clears `_raw_data` after collecting results
   - Replaces `inventory` with summary counts
   - Location: `main_scanner.py` line ~2143

## Memory Reduction

### Before Optimization
- **Per service**: ~50MB (discovery + raw data)
- **100 services**: ~5GB peak memory

### After Optimization
- **Per service**: ~5MB (metadata + checks + counts only)
- **100 services**: ~500MB peak memory
- **Reduction**: ~90% memory savings

## What's Kept in Memory

After optimization, each result dict contains:
- `service`: Service name
- `account`: Account ID
- `region`: Region
- `scope`: 'global' or 'regional'
- `checks`: List of check results (usually small, <1MB)
- `inventory`: Summary counts (e.g., `{'aws.ec2.list_instances': 1000}`)
- `_inventory_written`: Flag indicating full data was written

## What's Removed

- `_raw_data`: Full API responses (already on disk)
- `inventory`: Full item lists (already on disk, replaced with counts)

## Benefits

1. **90% memory reduction**: From ~5GB to ~500MB for 100 services
2. **Faster GC**: Smaller objects are garbage collected faster
3. **More headroom**: Can run more services in parallel with same RAM
4. **No data loss**: All data is safely written to disk before clearing

## Configuration Recommendations

Based on available RAM:

| RAM | max_total_workers | Expected Peak Memory |
|-----|-------------------|---------------------|
| 8GB | 50 | ~250MB |
| 16GB | 100 | ~500MB |
| 32GB+ | 200 | ~1GB |

## Notes

- Data is **always written to disk** before clearing
- Summary counts are kept for aggregation/reporting
- Checks are kept (usually small, needed for summary)
- This optimization works with all scanning models (flattened, account+region, legacy)

