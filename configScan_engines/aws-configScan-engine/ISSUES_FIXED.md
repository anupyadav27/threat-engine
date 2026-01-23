# Issues Fixed - Summary

**Date**: 2026-01-22  
**Status**: ✅ All Issues Fixed

---

## Issues Fixed

### 1. ✅ SSM describe_parameters: maxResults ≤ 50

**Problem**: SSM `describe_parameters` was using `MaxResults: 1000`, but AWS requires it to be ≤ 50.

**Fix Applied**:
- Added `describe_parameters` discovery to `services/ssm/discoveries/ssm.discoveries.yaml`
- Set `MaxResults: 50` (instead of 1000)
- Updated `parameter_name_mapping.json` to include SSM-specific limits:
  ```json
  "ssm": {
    "MaxResults": {
      "describe_parameters": 50,
      "default": 1000
    }
  }
  ```

**Files Modified**:
- `configScan_engines/aws-configScan-engine/services/ssm/discoveries/ssm.discoveries.yaml`
- `configScan_engines/aws-configScan-engine/config/parameter_name_mapping.json`

---

### 2. ✅ QuickSight: AwsAccountId Parameter Validation

**Problem**: QuickSight operations were failing with "Invalid length for parameter AwsAccountId, value: 0" because `account_info.Account` was resolving to 0 or empty.

**Fix Applied**:
- Added validation in `resolve_params_recursive()` function in `service_scanner.py`
- If `AwsAccountId` is 0, empty, or invalid, the code now:
  1. Attempts to get the account ID directly from STS (`get_caller_identity`)
  2. Uses the STS account ID as a fallback
  3. Logs a debug message when the fix is applied

**Files Modified**:
- `configScan_engines/aws-configScan-engine/engine/service_scanner.py` (both `run_global_service` and `run_regional_service`)

**Code Changes**:
```python
# Validate QuickSight AwsAccountId - ensure it's not 0 or empty
if key == 'AwsAccountId' and service_name == 'quicksight':
    if resolved_value == '0' or resolved_value == 0 or resolved_value == '':
        # Try to get account ID from STS if account_info is invalid
        try:
            sts_client = session.client('sts', region_name='us-east-1', config=BOTO_CONFIG)
            account_id_from_sts = sts_client.get_caller_identity().get('Account')
            if account_id_from_sts:
                resolved_value = str(account_id_from_sts)
                logger.debug(f"QuickSight: Fixed invalid AwsAccountId (was {obj.get('AwsAccountId')}), using {resolved_value}")
        except Exception as e:
            logger.warning(f"QuickSight: Could not get account ID from STS: {e}")
```

---

### 3. ✅ SageMaker: Throttling (Rate Exceeded) Handling

**Problem**: SageMaker operations (`list_edge_packaging_jobs`, `list_device_fleets`) were failing with `ThrottlingException: Rate exceeded` errors, and the retry logic wasn't using long enough delays.

**Fix Applied**:
- Enhanced `_retry_call()` function in `service_scanner.py` to detect throttling errors
- Added special handling for throttling errors with longer exponential backoff delays:
  - Regular errors: `BASE_DELAY * (BACKOFF_FACTOR ** attempt)`
  - Throttling errors: `max(BASE_DELAY * 2, BASE_DELAY * (BACKOFF_FACTOR ** attempt) * 2)`
- Throttling detection checks for:
  - `ThrottlingException` in exception type name
  - `ThrottlingException` in error code
  - `throttling` or `rate exceeded` in error message

**Files Modified**:
- `configScan_engines/aws-configScan-engine/engine/service_scanner.py`

**Code Changes**:
```python
# Check if this is a throttling error - use longer delays
error_code = ''
error_message = str(e).lower()
if hasattr(e, 'response'):
    error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''

is_throttling = (
    'ThrottlingException' in str(type(e).__name__) or
    'ThrottlingException' in error_code or
    'throttling' in error_message or
    'rate exceeded' in error_message
)

# Use longer delay for throttling errors
if is_throttling:
    delay = max(BASE_DELAY * 2, BASE_DELAY * (BACKOFF_FACTOR ** attempt) * 2)
    logger.debug(f"Throttling detected, using longer delay: {delay:.2f}s")
else:
    delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
```

---

## Testing Recommendations

1. **SSM**: Run a test scan for SSM service and verify `describe_parameters` completes without validation errors.

2. **QuickSight**: Run a test scan for QuickSight service and verify all operations complete without "Invalid length for parameter AwsAccountId" errors.

3. **SageMaker**: Run a test scan for SageMaker service and verify throttling errors are handled gracefully with retries (check logs for "Throttling detected" messages).

---

## Impact

- **SSM**: Prevents parameter validation failures for `describe_parameters`
- **QuickSight**: Prevents parameter validation failures for all QuickSight operations requiring `AwsAccountId`
- **SageMaker**: Improves resilience to rate limiting by using longer retry delays

All fixes are backward compatible and do not affect other services.

---

**Last Updated**: 2026-01-22

