# Logging Migration Guide

## Enterprise Features Added

### New Functions

- `audit_log()` - Log admin operations with user_id, action, resource, result
- `security_event_log()` - Log security events (auth failures, violations, suspicious activity)
- `get_correlation_id()` - Generate/get correlation ID for error tracking
- `setup_cloudwatch_handler()` - CloudWatch Logs integration
- `setup_elk_handler()` - ELK Stack integration
- `setup_datadog_handler()` - DataDog integration

### Middleware

- `RequestLoggingMiddleware` - Automatic request/response logging
- `CorrelationIDMiddleware` - Automatic correlation ID generation

### Log Rotation

- Size-based rotation (LOG_MAX_BYTES)
- Time-based rotation (LOG_ROTATION_WHEN)
- Backup count (LOG_BACKUP_COUNT)

## Quick Start

### 1. Replace Basic Logging

**Before**:
```python
import logging
logger = logging.getLogger(__name__)
logger.info("Scan started")
```

**After**:
```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="configscan-aws")

# With context
with LogContext(tenant_id="tenant-123", scan_run_id="scan-456"):
    logger.info("Scan started")
```

### 2. Replace print() Statements

**Before**:
```python
print(f"[Scan {scan_id}] Received scan request:")
print(f"  Tenant ID: {request.tenant_id}")
```

**After**:
```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="configscan-aws")

with LogContext(tenant_id=request.tenant_id, scan_run_id=scan_id):
    logger.info("Received scan request", extra={
        "extra_fields": {
            "regions": request.include_regions,
            "services": request.include_services
        }
    })
```

### 3. Add Performance Metrics

**Before**:
```python
start_time = time.time()
# ... do work ...
duration = time.time() - start_time
print(f"Scan completed in {duration}s")
```

**After**:
```python
from common.logger import setup_logger, log_duration
import time

logger = setup_logger(__name__)

start_time = time.time()
# ... do work ...
duration_ms = (time.time() - start_time) * 1000
log_duration(logger, "Scan completed", duration_ms)
```

## Migration Checklist

### Onboarding Engine
- [ ] Replace `logging.getLogger(__name__)` with `setup_logger()`
- [ ] Add LogContext to all API endpoints
- [ ] Add tenant_id/scan_run_id context
- [ ] Replace print() statements
- [ ] Add performance metrics

### ConfigScan Engines
- [ ] Replace print() in `api_server.py`
- [ ] Integrate with common logger
- [ ] Add tenant/scan context
- [ ] Update `setup_scan_logging()` to use common logger

### Threat Engine
- [ ] Add logging setup
- [ ] Add context to all operations
- [ ] Add performance metrics

### Compliance Engine
- [ ] Add logging setup
- [ ] Add context to all operations

### DataSec Engine
- [ ] Add logging setup
- [ ] Add context to all operations

### Inventory Engine
- [ ] Add logging setup
- [ ] Add context to all operations

## Environment Variables

```bash
# Log format: 'json' or 'human' (default: human)
LOG_FORMAT=json

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
LOG_LEVEL=INFO

# Optional: Log file path
LOG_FILE=/var/log/cspm/engine.log
```

## Examples

### API Endpoint with Context

```python
from fastapi import APIRouter
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="onboarding")

@router.post("/scan")
async def create_scan(request: ScanRequest):
    scan_run_id = str(uuid.uuid4())
    
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=scan_run_id,
        account_id=request.account_id
    ):
        logger.info("Creating scan", extra={
            "extra_fields": {
                "provider": request.provider,
                "regions": request.regions
            }
        })
        
        # All logs within this context will include tenant_id and scan_run_id
        result = await execute_scan(request)
        
        logger.info("Scan created successfully", extra={
            "extra_fields": {"scan_id": result.scan_id}
        })
    
    return result
```

### Background Task with Context

```python
async def run_scan(scan_id: str, tenant_id: str):
    with LogContext(tenant_id=tenant_id, scan_run_id=scan_id):
        logger.info("Starting scan")
        
        try:
            # ... scan logic ...
            logger.info("Scan completed")
        except Exception as e:
            logger.error("Scan failed", exc_info=True)
            raise
```

### Performance Logging

```python
import time
from common.logger import log_duration

start = time.time()
# ... operation ...
duration_ms = (time.time() - start) * 1000
log_duration(logger, "Operation completed", duration_ms)
```
