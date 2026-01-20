# Scan Output Issue Analysis

## Problem
Scan completed but `results.ndjson` and `inventory.ndjson` are empty (only 1 blank line each).

## Root Cause
When using `max_total_workers > 0` (flattened model), results are written to **per-account+region files**, NOT to the main `results.ndjson` and `inventory.ndjson` files.

### File Structure:
- **Flattened model** (`max_total_workers > 0`):
  - `results_{account_id}_{region}.ndjson` - per account+region
  - `inventory_{account_id}_{region}.ndjson` - per account+region
  - Main `results.ndjson` and `inventory.ndjson` are created but remain empty

- **Account+Region model** (`max_account_region_workers > 0`):
  - Uses per-account+region files
  - Main files also empty

- **Legacy model** (default):
  - Uses main `results.ndjson` and `inventory.ndjson` files

## Solution

### Option 1: Use Legacy Model (for testing)
```python
summary = scan(
    include_services=['ec2', 'inspector', 'sagemaker'],
    include_regions=['us-east-1'],
    max_total_workers=0,  # Use legacy model
    max_workers=10,       # Service-level parallelism
    stream_results=True,
    save_report=False,
    output_scan_id=f"test_performance_{timestamp}"
)
```

### Option 2: Check Per-Account+Region Files
When using `max_total_workers > 0`, check for:
- `results_{account_id}_{region}.ndjson`
- `inventory_{account_id}_{region}.ndjson`

### Option 3: Update Test Script
The test script has been updated to check both main files and per-account+region files.

## Why Files Are Empty

1. **No resources found**: Account might not have EC2/Inspector/SageMaker resources
2. **No checks run**: Services scanned but no compliance checks executed
3. **Empty inventory**: Resources discovered but inventory extraction failed

## Next Steps

1. Check per-account+region files for actual results
2. Review raw data files to see what was discovered
3. Check logs for any errors
4. Verify services have resources in the test account

