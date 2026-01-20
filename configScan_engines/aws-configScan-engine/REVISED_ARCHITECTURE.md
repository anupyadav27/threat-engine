# Revised Architecture: 3-Phase Discovery → Inventory → Checks

## Overview

The scanner has been refactored to implement a clear 3-phase architecture that maximizes parallelism and ensures checks only run when resources exist.

## Architecture

### PHASE 1: DISCOVERY
- **Run ALL discoveries** for the boto3 client
- Store ALL discovery results in memory: `discovery_results = {}`
- Independent discoveries run in parallel
- Dependent discoveries run after their dependencies complete
- All discovery data is stored before any checks run

### PHASE 2: BUILD INVENTORY (Optional)
- Extract inventory items from `discovery_results`
- Build complete inventory for reporting
- Identify primary inventory items (fallback for checks)

### PHASE 3: CHECKS (Parallel Execution)
- **Run ALL checks in parallel** using `ThreadPoolExecutor`
- All checks share the same `discovery_results` (reference, not copy)
- Checks are independent - they only depend on discoveries, not each other
- Each check iterates over relevant inventory items from `discovery_results`
- Controlled by `MAX_CHECK_WORKERS` environment variable (default: 50)

## Key Principles

### 1. Service Isolation
- Each service uses only its own boto3 client
- No cross-service dependencies
- Each service's YAML contains only discoveries/checks for that service's client

### 2. Checks Share Discovery Results
- All checks reference the same `discovery_results` dictionary
- No copying of data - memory efficient
- Consistent data across all checks

### 3. Account-Level vs Resource Checks
- **Account-level checks** (`.account.` in rule_id): Run once even if no inventory
- **Resource checks**: Only run if inventory items exist
- No checks run for empty regions (except account-level checks)

### 4. Parallel Execution
- **Discoveries**: Independent discoveries run in parallel
- **Checks**: ALL checks run in parallel (they're independent)
- Maximum parallelism for maximum speed

## Implementation Details

### Helper Function: `_run_single_check()`
- Extracted check execution into a reusable function
- Can be executed in parallel with other checks
- Takes check config, service info, and shared `discovery_results`
- Returns list of check result records

### Environment Variables
- `MAX_DISCOVERY_WORKERS`: Controls discovery parallelism (default: 50)
- `MAX_CHECK_WORKERS`: Controls check parallelism (default: 50)

### Code Structure

```python
def run_regional_service(service_name, region, session_override=None):
    # PHASE 1: DISCOVERY
    discovery_results = {}
    # ... run all discoveries, store in discovery_results ...
    
    # PHASE 2: BUILD INVENTORY
    primary_items = ...  # Extract from discovery_results
    
    # PHASE 3: CHECKS (Parallel)
    with ThreadPoolExecutor(max_workers=MAX_CHECK_WORKERS) as executor:
        futures = {executor.submit(_run_single_check, check, ...): check 
                   for check in all_checks}
        for future in as_completed(futures):
            results = future.result()
            checks_output.extend(results)
```

## Benefits

1. **Clear Separation**: Discover → Inventory → Check phases are distinct
2. **Maximum Parallelism**: All checks run simultaneously
3. **Memory Efficient**: Checks share discovery results (no copying)
4. **Logical Flow**: No checks run without resources (except account-level)
5. **Service Isolation**: Each service is self-contained

## Migration Notes

- Existing YAML files work without changes
- Discovery phase remains the same
- Check execution is now parallel (was sequential)
- Account-level checks now properly identified and handled

