# Duplicate Check Analysis for API Gateway v2

## Current Duplicate Groups

### Group 1: DefaultRouteSettings Checks (4 checks)

**Current Implementation:** All check `item.DefaultRouteSettings != 'null'`

1. **`api_quota_limit_configured`** (line 81-86)
   - **Requirement:** "Api Quota Limit Configuration"
   - **Should Validate:** Quota limit is configured in DefaultRouteSettings
   - **Current:** Only checks if DefaultRouteSettings exists
   - **Ideal:** Should check `DefaultRouteSettings.QuotaLimit` is set

2. **`api_burst_limit_configured`** (line 93-98)
   - **Requirement:** "Api Burst Limit Configuration"  
   - **Should Validate:** Burst limit is configured in DefaultRouteSettings
   - **Current:** Only checks if DefaultRouteSettings exists
   - **Ideal:** Should check `DefaultRouteSettings.ThrottleBurstLimit` is set

3. **`api_rate_limit_configured`** (line 139-144)
   - **Requirement:** "Api Rate Limit Configuration"
   - **Should Validate:** Rate limit is configured in DefaultRouteSettings
   - **Current:** Only checks if DefaultRouteSettings exists
   - **Ideal:** Should check `DefaultRouteSettings.ThrottleRateLimit` is set

4. **`api_throttle_overrides_bounded`** (line 145-150)
   - **Requirement:** "Api Throttle Overrides Bounded"
   - **Should Validate:** Throttle overrides are bounded (not unlimited)
   - **Current:** Only checks if DefaultRouteSettings exists
   - **Ideal:** Should check throttle limits are set and not -1 (unlimited)

**Analysis:** 
- ❌ **NOT truly identical** - Each should validate different nested fields
- ⚠️ **Current limitation:** Nested fields (QuotaLimit, ThrottleBurstLimit, ThrottleRateLimit) are not directly accessible in direct_vars.json
- ✅ **Acceptable workaround:** Checking if DefaultRouteSettings exists is a reasonable proxy, but not ideal

---

### Group 2: AccessLogSettings Basic Checks (5 checks)

**Current Implementation:** All check `item.AccessLogSettings != 'null'`

1. **`resource.api_access_logging_enabled`** (line 99-104)
   - **Requirement:** "Access Logging"
   - **Scope:** `apigatewayv2.resource.logging`
   - **Should Validate:** Access logging is enabled
   - **Current:** ✅ Correct - Checks if AccessLogSettings exists
   - **Note:** Resource-level, but checking stage-level (API Gateway v2 only has stage-level logging)

2. **`stage.api_logs_retention_days_minimum`** (line 105-110)
   - **Requirement:** "Api Logs Retention Days Minimum"
   - **Scope:** `apigatewayv2.stage.logging`
   - **Should Validate:** Log retention days meets minimum requirement
   - **Current:** ❌ INCORRECT - Only checks if AccessLogSettings exists
   - **Ideal:** Should check CloudWatch Logs retention policy (not in AccessLogSettings)
   - **Issue:** Retention is configured in CloudWatch Logs, not in AccessLogSettings

3. **`stage.api_access_logging_enabled`** (line 111-116)
   - **Requirement:** "Access Logging"
   - **Scope:** `apigatewayv2.stage.logging`
   - **Should Validate:** Access logging is enabled
   - **Current:** ✅ Correct - Checks if AccessLogSettings exists

4. **`api.access_logging_enabled`** (line 133-138)
   - **Requirement:** "Access Logging"
   - **Scope:** `apigatewayv2.api.logging`
   - **Should Validate:** Access logging is enabled
   - **Current:** ✅ Acceptable - Checks if AccessLogSettings exists
   - **Note:** API-level check, but API Gateway v2 only has stage-level logging

5. **`stage.api_execution_logging_level_minimum_error_configured`** (line 127-132)
   - **Requirement:** "Activity Logging"
   - **Scope:** `apigatewayv2.stage.logging`
   - **Description:** "Checks that AWS APIGATEWAYV2 stage has comprehensive audit logging enabled"
   - **Should Validate:** Execution log level is at least ERROR
   - **Current:** ❌ INCORRECT - Only checks if AccessLogSettings exists
   - **Ideal:** Should check `DefaultRouteSettings.DataTraceEnabled` and/or `LoggingLevel` field

**Analysis:**
- ❌ **NOT truly identical** - Different checks should validate different aspects
- ⚠️ **Issues:**
  - `api_logs_retention_days_minimum` cannot be validated from AccessLogSettings (it's a CloudWatch Logs setting)
  - `api_execution_logging_level_minimum_error_configured` should check logging level, not just if AccessLogSettings exists

---

### Group 3: Enhanced AccessLogSettings Checks (2 checks)

1. **`stage.api_access_log_sink_configured`** (line 117-126)
   - **Requirement:** "Api Access Log Sink Configuration"
   - **Current:** ✅ Enhanced - Checks AccessLogSettings exists AND DestinationArn exists
   - **Status:** Correctly enhanced

2. **`stage.api_access_log_fields_identity_configured`** (line 151-160)
   - **Requirement:** "Api Access Log Fields Identity Configuration"
   - **Current:** ✅ Enhanced - Checks AccessLogSettings exists AND Format exists
   - **Status:** Correctly enhanced

---

## Summary

### Truly Identical (Acceptable)
- `resource.api_access_logging_enabled` and `stage.api_access_logging_enabled` - Both correctly check if access logging is enabled

### Technically Identical but Should Be Different
- **DefaultRouteSettings group:** All 4 checks are identical but should check different nested fields
  - **Limitation:** Nested fields not accessible in current schema
  - **Recommendation:** Keep as-is for now, but note for future enhancement

- **AccessLogSettings group:** 5 checks are identical but should validate different aspects
  - **Critical Issues:**
    1. `api_logs_retention_days_minimum` - Cannot be validated from AccessLogSettings (needs CloudWatch Logs check)
    2. `api_execution_logging_level_minimum_error_configured` - Should check logging level field, not just AccessLogSettings existence

### Recommendations

1. **DefaultRouteSettings checks:** Keep current implementation as acceptable proxy until nested field access is available

2. **AccessLogSettings checks:**
   - Remove or mark `api_logs_retention_days_minimum` as unable to validate (requires CloudWatch Logs integration)
   - Update `api_execution_logging_level_minimum_error_configured` to check logging level field if available, or mark as unable to validate

3. **Document limitations:** Note that some checks are proxies/approximations due to schema limitations

