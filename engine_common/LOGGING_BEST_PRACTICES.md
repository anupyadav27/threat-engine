# Logging Best Practices for CSPM Engines

## Overview

This guide provides best practices for using the standardized logging infrastructure across all CSPM engines.

## Quick Start

### Basic Logging

```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="my-engine")

# Simple log
logger.info("Operation started")

# With context
with LogContext(tenant_id="tenant-123", scan_run_id="scan-456"):
    logger.info("Scan started")
```

### API Endpoint Logging

```python
from fastapi import APIRouter
from common.logger import setup_logger, LogContext, log_duration, audit_log
import time

logger = setup_logger(__name__, engine_name="my-engine")

@router.post("/api/v1/operation")
async def my_operation(request: Request):
    start_time = time.time()
    
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=request.scan_run_id
    ):
        logger.info("Operation started", extra={
            "extra_fields": {
                "param1": request.param1,
                "param2": request.param2
            }
        })
        
        try:
            # ... operation logic ...
            result = perform_operation()
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Operation completed", duration_ms)
            
            return result
        except Exception as e:
            logger.error("Operation failed", exc_info=True)
            raise
```

## Logging Patterns

### 1. Context-Aware Logging

Always use `LogContext` for operations that have tenant/scan context:

```python
with LogContext(
    tenant_id=tenant_id,
    scan_run_id=scan_run_id,
    account_id=account_id,
    request_id=request_id
):
    logger.info("Processing scan")
    # All logs within this context will include these IDs
```

### 2. Performance Logging

Use `log_duration()` for timing operations:

```python
import time
from common.logger import log_duration

start = time.time()
# ... operation ...
duration_ms = (time.time() - start) * 1000
log_duration(logger, "Operation completed", duration_ms)
```

### 3. Audit Logging

Use `audit_log()` for admin operations:

```python
from common.logger import audit_log

# Success
audit_log(
    logger,
    "account_created",
    f"account:{account_id}",
    user_id=user_id,
    tenant_id=tenant_id,
    result="success",
    details={"account_name": account_name}
)

# Failure
audit_log(
    logger,
    "account_creation_failed",
    f"tenant:{tenant_id}",
    user_id=user_id,
    tenant_id=tenant_id,
    result="failure",
    details={"error": str(e)}
)
```

### 4. Security Event Logging

Use `security_event_log()` for security events:

```python
from common.logger import security_event_log

# Authentication failure
security_event_log(
    logger,
    "auth_failure",
    "medium",
    "Invalid credentials provided",
    user_id=user_id,
    ip_address=client_ip
)

# Authorization violation
security_event_log(
    logger,
    "authorization_violation",
    "high",
    "User attempted to access unauthorized resource",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    details={"resource": resource_id, "action": action}
)
```

### 5. Transaction Logging

Use `transaction_log()` for database transactions on critical data:

```python
from common.logger import transaction_log

# Create operation
transaction_log(
    logger,
    "create_tenant",
    "tenants",
    record_id=tenant_id,
    operation_type="create",
    tenant_id=tenant_id,
    user_id=user_id,
    details={"tenant_name": tenant_name, "plan": plan}
)

# Update operation
transaction_log(
    logger,
    "update_account_credentials",
    "accounts",
    record_id=account_id,
    operation_type="update",
    tenant_id=tenant_id,
    user_id=user_id,
    details={"fields_changed": ["access_key", "secret_key"]}
)

# Delete operation
transaction_log(
    logger,
    "delete_account",
    "accounts",
    record_id=account_id,
    operation_type="delete",
    tenant_id=tenant_id,
    user_id=user_id
)
```

### 6. Business Event Logging

Use `business_event_log()` for business-critical events:

```python
from common.logger import business_event_log

# Scan completion
business_event_log(
    logger,
    "scan_completed",
    "AWS ConfigScan Completed",
    tenant_id=tenant_id,
    account_id=account_id,
    scan_run_id=scan_run_id,
    status="completed",
    metrics={
        "resources_scanned": 1000,
        "findings_found": 25,
        "duration_seconds": 120
    }
)

# Onboarding milestone
business_event_log(
    logger,
    "onboarding_milestone",
    "First Scan Completed",
    tenant_id=tenant_id,
    account_id=account_id,
    status="completed",
    details={"milestone": "first_scan"}
)

# Report generation
business_event_log(
    logger,
    "report_generated",
    "Compliance Report Generated",
    tenant_id=tenant_id,
    scan_run_id=scan_run_id,
    status="completed",
    metrics={"report_size_mb": 5.2, "pages": 50}
)
```

### 7. Data Access Logging

Use `data_access_log()` for tracking data access:

```python
from common.logger import data_access_log

# Report read
data_access_log(
    logger,
    "report",
    report_id,
    action="read",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    success=True,
    details={"report_type": "compliance", "framework": "SOC2"}
)

# Data export
data_access_log(
    logger,
    "scan_result",
    scan_run_id,
    action="export",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    success=True,
    details={"format": "csv", "rows_exported": 1000}
)

# Failed access attempt
data_access_log(
    logger,
    "report",
    report_id,
    action="read",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    success=False,
    details={"reason": "unauthorized", "required_role": "admin"}
)
```

### 8. Activity Logging

Use `activity_log()` for user activity tracking:

```python
from common.logger import activity_log

# Page view
activity_log(
    logger,
    "page_view",
    "Dashboard Viewed",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    session_id=session_id,
    details={"page": "/dashboard", "duration_seconds": 45}
)

# Search activity
activity_log(
    logger,
    "search",
    "Threat Search",
    user_id=user_id,
    tenant_id=tenant_id,
    ip_address=client_ip,
    details={"query": "high severity", "results_count": 10}
)

# Filter applied
activity_log(
    logger,
    "filter",
    "Scan Results Filtered",
    user_id=user_id,
    tenant_id=tenant_id,
    details={"filters": {"severity": "high", "status": "active"}}
)
```

### 9. Compliance Event Logging

Use `compliance_event_log()` for compliance-specific events:

```python
from common.logger import compliance_event_log

# Control passed
compliance_event_log(
    logger,
    "SOC2",
    requirement_id="CC6.1",
    event_type="control_passed",
    description="Access control mechanism verified",
    tenant_id=tenant_id,
    account_id=account_id,
    scan_run_id=scan_run_id,
    severity="info",
    details={"evidence": "access_logs_verified", "timestamp": "2026-01-23T10:00:00Z"}
)

# Control failed
compliance_event_log(
    logger,
    "ISO27001",
    requirement_id="A.9.2.1",
    event_type="control_failed",
    description="User access review not completed",
    tenant_id=tenant_id,
    severity="error",
    details={"last_review": "2025-12-01", "required_frequency": "monthly"}
)

# Evidence collected
compliance_event_log(
    logger,
    "GDPR",
    requirement_id="Art.32",
    event_type="evidence_collected",
    description="Data encryption evidence collected",
    tenant_id=tenant_id,
    scan_run_id=scan_run_id,
    severity="info",
    details={"encrypted_resources": 100, "total_resources": 100}
)
```

### 10. Error Logging

Always use `exc_info=True` for exceptions:

```python
try:
    # ... operation ...
except Exception as e:
    logger.error("Operation failed", exc_info=True, extra={
        "extra_fields": {
            "error": str(e),
            "context": "additional context"
        }
    })
    raise
```

### 11. Structured Data Logging

Use `extra_fields` for structured data:

```python
logger.info("Scan completed", extra={
    "extra_fields": {
        "total_checks": 100,
        "passed_checks": 80,
        "failed_checks": 20,
        "duration_seconds": 45.2
    }
})
```

## Common Operations

### Scan Operations

```python
with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
    logger.info("Starting scan", extra={
        "extra_fields": {
            "provider": provider,
            "regions": regions,
            "services": services
        }
    })
    
    try:
        result = execute_scan()
        log_duration(logger, "Scan completed", duration_ms)
        logger.info("Scan completed", extra={
            "extra_fields": {
                "total_results": len(result)
            }
        })
    except Exception as e:
        logger.error("Scan failed", exc_info=True)
        raise
```

### Database Operations

```python
with LogContext(tenant_id=tenant_id):
    logger.debug("Querying database", extra={
        "extra_fields": {
            "table": "accounts",
            "filter": {"tenant_id": tenant_id}
        }
    })
    
    try:
        result = db.query(...)
        logger.debug("Database query completed", extra={
            "extra_fields": {
                "rows_returned": len(result)
            }
        })
    except Exception as e:
        logger.error("Database query failed", exc_info=True)
        raise
```

### External API Calls

```python
with LogContext(tenant_id=tenant_id, scan_run_id=scan_run_id):
    logger.info("Calling external API", extra={
        "extra_fields": {
            "endpoint": endpoint,
            "method": "POST"
        }
    })
    
    try:
        response = await client.post(endpoint, json=payload)
        logger.info("External API call succeeded", extra={
            "extra_fields": {
                "status_code": response.status_code
            }
        })
    except Exception as e:
        logger.error("External API call failed", exc_info=True, extra={
            "extra_fields": {
                "endpoint": endpoint,
                "error": str(e)
            }
        })
        raise
```

## Log Levels

- **DEBUG**: Detailed information for debugging
- **INFO**: General informational messages
- **WARNING**: Warning messages (non-critical issues)
- **ERROR**: Error messages (operations failed)
- **CRITICAL**: Critical errors (system may be unstable)

## Environment Configuration

### Development

```bash
export LOG_FORMAT=human
export LOG_LEVEL=DEBUG
```

### Production

```bash
export LOG_FORMAT=json
export LOG_LEVEL=INFO
export LOG_FILE=/var/log/cspm/engine.log
export LOG_MAX_BYTES=104857600  # 100MB
export LOG_BACKUP_COUNT=10
```

### With Aggregation

```bash
export LOG_FORMAT=json
export LOG_LEVEL=INFO
export CLOUDWATCH_LOG_GROUP=/cspm/engines
export ELK_ENDPOINT=tcp://logstash:5000
export DATADOG_API_KEY=your-api-key
```

## Middleware Integration

All FastAPI apps should include logging middleware:

```python
from common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="my-engine")
```

This automatically logs all requests/responses with context.

## Best Practices

1. **Always use LogContext** for operations with tenant/scan context
2. **Use structured logging** with extra_fields for searchable data
3. **Log at appropriate levels** (DEBUG for development, INFO for production)
4. **Include correlation IDs** in error logs for tracking
5. **Use audit_log** for all admin operations
6. **Use security_event_log** for security events
7. **Use transaction_log** for critical database operations
8. **Use business_event_log** for business milestones
9. **Use data_access_log** for data access tracking
10. **Use activity_log** for user activity tracking
11. **Use compliance_event_log** for compliance requirements
12. **Use log_duration** for performance-critical operations
13. **Never log sensitive data** (passwords, secrets, tokens)
14. **Use exc_info=True** for exception logging
15. **Include context** (tenant_id, scan_run_id) in all logs

## Examples

### Complete API Endpoint

```python
@app.post("/api/v1/scan")
async def create_scan(request: ScanRequest):
    import time
    start_time = time.time()
    
    scan_run_id = request.scan_run_id or str(uuid.uuid4())
    
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=scan_run_id
    ):
        logger.info("Received scan request", extra={
            "extra_fields": {
                "provider": request.provider,
                "regions": request.regions,
                "services": request.services
            }
        })
        
        try:
            # Execute scan
            result = await execute_scan(request)
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Scan completed", duration_ms)
            
            audit_log(
                logger,
                "scan_completed",
                f"scan:{scan_run_id}",
                tenant_id=request.tenant_id,
                result="success",
                details={
                    "total_checks": result.total_checks,
                    "passed_checks": result.passed_checks
                }
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Scan failed", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "scan_failed",
                f"scan:{scan_run_id}",
                tenant_id=request.tenant_id,
                result="failure",
                details={"error": str(e)}
            )
            raise
```

## Common Mistakes to Avoid

1. **Don't use print()** - Always use logger
2. **Don't log sensitive data** - Sanitize credentials, tokens
3. **Don't forget context** - Always use LogContext for tenant/scan operations
4. **Don't log at wrong level** - Use appropriate log levels
5. **Don't forget exc_info** - Always use exc_info=True for exceptions
6. **Don't log too much** - Use DEBUG sparingly in production
7. **Don't log too little** - Include enough context for debugging
