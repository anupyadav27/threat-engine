# Discovery Engine Cleanup Summary

## Changes Made

### 1. Removed Environment Variable Hack

**Before:**
```python
# In discovery_engine.py
os.environ['MAX_CHECK_WORKERS'] = '0'  # Hack to skip checks
run_result = run_global_service(service)
```

**After:**
```python
# Clean parameter-based approach
run_result = run_global_service(service, skip_checks=True)
```

### 2. Added `skip_checks` Parameter

**Files Modified:**
- `engine/service_scanner.py`
  - `run_global_service()` - Added `skip_checks: bool = False` parameter
  - `run_regional_service()` - Added `skip_checks: bool = False` parameter
  - Both functions now check `skip_checks` instead of `MAX_CHECK_WORKERS` env var

- `engine/discovery_engine.py`
  - Removed `os.environ['MAX_CHECK_WORKERS'] = '0'` hack
  - Updated calls to pass `skip_checks=True`:
    - `run_global_service(service, skip_checks=True)`
    - `run_regional_service(service, region=region, skip_checks=True)`

### 3. Clean Separation

**Discovery Engine:**
- ✅ Only runs discoveries
- ✅ No check-related code
- ✅ No environment variable hacks
- ✅ Clean parameter-based control

**Service Scanner:**
- ✅ Supports both discovery-only and full scan modes
- ✅ `skip_checks=True` for discovery-only
- ✅ `skip_checks=False` (default) for full scan with checks
- ✅ Backward compatible (default behavior unchanged)

## Benefits

1. **Cleaner Code**: No more environment variable hacks
2. **Explicit Control**: Parameter makes intent clear
3. **Better Separation**: Discovery and checks are properly separated
4. **Maintainability**: Easier to understand and modify
5. **Backward Compatible**: Existing code using default parameters still works

## Testing

To verify discoveries run cleanly:

```python
from engine.discovery_engine import DiscoveryEngine
from engine.database_manager import DatabaseManager

db = DatabaseManager()
discovery = DiscoveryEngine(db)

# Run discovery scan (checks automatically skipped)
scan_id = discovery.run_discovery_scan(
    customer_id="test",
    tenant_id="test",
    provider="aws",
    hierarchy_id="123456789012",
    hierarchy_type="account",
    services=["s3", "ec2"],
    regions=["us-east-1"]
)
```

## Migration Notes

If you have code that was relying on `MAX_CHECK_WORKERS=0`:

**Old way (deprecated):**
```python
os.environ['MAX_CHECK_WORKERS'] = '0'
run_result = run_global_service('s3')
```

**New way:**
```python
run_result = run_global_service('s3', skip_checks=True)
```

The environment variable approach still works for backward compatibility, but the parameter approach is preferred.
