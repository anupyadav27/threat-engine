# Logging Improvements Implementation Plan

## Summary

Created standardized logging infrastructure for SaaS admin portal integration.

## Files Created

### 1. `common/logger.py`
**Purpose**: Centralized logging module with structured JSON logging and context support

**Features**:
- ✅ Structured JSON logging for aggregation
- ✅ Human-readable format for development
- ✅ Context variables (tenant_id, scan_run_id, execution_id, account_id, request_id)
- ✅ Performance metrics support
- ✅ Multiple handlers (console, file)
- ✅ Environment-based configuration

**Key Functions**:
- `setup_logger()` - Configure logger with context
- `get_logger()` - Get logger instance
- `LogContext` - Context manager for setting log context
- `log_with_metrics()` - Log with performance metrics
- `log_duration()` - Log with duration
- `set_log_context()` - Set context variables

### 2. `LOGGING_ANALYSIS_AND_IMPROVEMENTS.md`
**Purpose**: Comprehensive analysis of current logging state and improvement plan

**Contents**:
- Current logging analysis for each engine
- Requirements for SaaS admin portal
- Improvement plan with priorities
- Success metrics

### 3. `common/LOGGING_MIGRATION_GUIDE.md`
**Purpose**: Step-by-step guide for migrating existing code to new logging

**Contents**:
- Quick start examples
- Migration checklist
- Environment variables
- Code examples

## Current State Analysis

### ✅ Onboarding Engine
- **Status**: Basic logging exists
- **Issues**: No context, no structured format
- **Action**: Migrate to common logger

### ⚠️ ConfigScan Engines
- **Status**: Mixed - some logging, but API uses print()
- **Issues**: 23 print() statements in api_server.py
- **Action**: Replace print() with structured logging

### ❌ Threat Engine
- **Status**: No logging found
- **Action**: Add logging

### ❓ Other Engines
- **Status**: Need analysis
- **Action**: Review and add logging

## Implementation Steps

### Step 1: Update Onboarding Engine (Example)

**File**: `onboarding_engine/api/onboarding.py`

**Before**:
```python
import logging
logger = logging.getLogger(__name__)
```

**After**:
```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="onboarding")

@router.post("/scan")
async def create_scan(request: ScanRequest):
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=scan_run_id
    ):
        logger.info("Creating scan")
```

### Step 2: Update ConfigScan API Server

**File**: `configScan_engines/aws-configScan-engine/api_server.py`

**Before**:
```python
print(f"[Scan {scan_id}] Received scan request:")
print(f"  Tenant ID: {request.tenant_id}")
```

**After**:
```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="configscan-aws")

async def create_scan(request: ScanRequest):
    scan_id = request.scan_run_id or str(uuid.uuid4())
    
    with LogContext(
        tenant_id=request.tenant_id,
        scan_run_id=scan_id
    ):
        logger.info("Received scan request", extra={
            "extra_fields": {
                "account": request.account,
                "regions": request.include_regions,
                "services": request.include_services
            }
        })
```

### Step 3: Update Orchestrator

**File**: `onboarding_engine/orchestrator/engine_orchestrator.py`

**Before**:
```python
import logging
logger = logging.getLogger(__name__)
```

**After**:
```python
from common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="orchestrator")

async def trigger_downstream_engines(...):
    with LogContext(
        tenant_id=tenant_id,
        scan_run_id=scan_run_id,
        execution_id=execution_id
    ):
        logger.info("Triggering downstream engines")
        # ... orchestration logic ...
```

## Benefits for SaaS Admin Portal

### 1. Tenant Isolation
- All logs include tenant_id
- Easy filtering by tenant
- Multi-tenant log aggregation

### 2. Scan Tracking
- All logs include scan_run_id
- Trace complete scan lifecycle
- Cross-engine correlation

### 3. Structured Data
- JSON format for aggregation
- Easy parsing and search
- Integration with ELK/CloudWatch/DataDog

### 4. Performance Monitoring
- Duration metrics in logs
- Performance tracking
- Bottleneck identification

### 5. Error Tracking
- Exception details in logs
- Error correlation
- Alerting support

## Next Steps

1. **Migrate Onboarding Engine** (Priority: High)
   - Update all files to use common logger
   - Add context to API endpoints
   - Replace print() statements

2. **Migrate ConfigScan Engines** (Priority: High)
   - Replace print() in api_server.py
   - Add context to scan operations
   - Integrate with existing scan logging

3. **Add Logging to Missing Engines** (Priority: Medium)
   - Threat engine
   - Compliance engine
   - DataSec engine
   - Inventory engine

4. **Admin Portal Integration** (Priority: Medium)
   - Create log query API
   - Add real-time log streaming
   - Implement log search UI

5. **Centralized Aggregation** (Priority: Low)
   - Set up CloudWatch/ELK
   - Configure log shipping
   - Set up dashboards

## Testing

### Test JSON Format
```bash
export LOG_FORMAT=json
python -c "from common.logger import setup_logger; logger = setup_logger('test'); logger.info('Test message')"
```

### Test Context
```python
from common.logger import setup_logger, LogContext

logger = setup_logger('test')

with LogContext(tenant_id="tenant-123", scan_run_id="scan-456"):
    logger.info("Test with context")
```

### Test Performance Metrics
```python
from common.logger import setup_logger, log_duration
import time

logger = setup_logger('test')
start = time.time()
# ... operation ...
log_duration(logger, "Operation", (time.time() - start) * 1000)
```

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
```

## Success Criteria

- ✅ All engines use common logger
- ✅ All logs include tenant_id and scan_run_id
- ✅ Zero print() statements in production code
- ✅ Logs can be aggregated and searched
- ✅ Admin portal can query logs by tenant/scan
- ✅ Performance metrics available
- ✅ Error tracking works
