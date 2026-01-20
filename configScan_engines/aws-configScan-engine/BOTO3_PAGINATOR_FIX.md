# Boto3 Paginator Implementation & File Writing Fix

## Problem 1: Service-Specific Logic

**Issue:** We were hardcoding EC2-specific logic to skip MaxResults for certain operations. This is not scalable and doesn't follow AWS best practices.

**Solution:** Use boto3's built-in paginators which automatically handle pagination for ALL services that support it.

## Problem 2: Missing Per-Account+Region Files

**Issue:** Files like `results_{account_id}_{region}.ndjson` and `inventory_{account_id}_{region}.ndjson` are not being created in the `latest/` folder.

**Root Cause:** Need to verify `_write_service_result` is correctly writing to `task['results_file']` and `task['inventory_file']` when using flattened model.

## Implementation

### 1. Boto3 Paginator (AWS Best Practice)

```python
def _paginate_api_call(client, action: str, params: Dict[str, Any], max_pages: int = 100) -> Dict[str, Any]:
    # Try boto3 paginator first (AWS-recommended approach)
    try:
        paginator = client.get_paginator(action)
        page_iterator = paginator.paginate(**params)
        
        # Collect all pages
        all_items = []
        result_array_key = None
        first_page = None
        
        for page in page_iterator:
            if first_page is None:
                first_page = page
                # Detect result array key
                for key, value in page.items():
                    if isinstance(value, list) and key not in ['NextToken', 'Marker']:
                        result_array_key = key
                        all_items.extend(value)
                        break
            else:
                if result_array_key and result_array_key in page:
                    all_items.extend(page[result_array_key])
        
        # Build combined response
        if first_page and result_array_key:
            combined_response = first_page.copy()
            combined_response[result_array_key] = all_items
            return combined_response
            
    except Exception:
        # Fall back to manual pagination if paginator not available
        # ... existing manual pagination code ...
```

### 2. Remove Service-Specific Logic

**Before:**
```python
# EC2 operations that DON'T support MaxResults
ec2_no_maxresults = {...}
if service_name == 'ec2' and action in ec2_no_maxresults:
    # Skip pagination
```

**After:**
```python
# Use boto3 paginator for all services
# It automatically handles operations that don't support pagination
response = _paginate_api_call(call_client, action, resolved_params)
```

### 3. File Writing Fix

Ensure `_write_service_result` writes to:
- `task['results_file']` (per-account+region)
- `task['inventory_file']` (per-account+region)

When `max_total_workers > 0` (flattened model), these should be:
- `results_{account_id}_{region}.ndjson`
- `inventory_{account_id}_{region}.ndjson`

## Benefits

1. **No Service-Specific Code:** Boto3 paginators work for all services automatically
2. **AWS Best Practice:** Using official boto3 pagination
3. **Automatic Fallback:** If paginator not available, falls back to manual pagination
4. **Cleaner Code:** Removes 20+ lines of hardcoded EC2 operations

## Testing

After implementation:
1. Run test scan
2. Verify no "Unknown parameter: MaxResults" errors
3. Verify per-account+region files are created in `latest/` folder
4. Verify pagination works for all services

