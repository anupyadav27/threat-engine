# Engine Common (Shared Utilities Library)

> Shared Python library providing standardized logging, storage paths, API models, middleware, and resilience patterns used across all engines.

---

## Overview

`engine_common` is **not a standalone service** — it's a shared library imported by other engines. It provides common infrastructure code that ensures consistency across the platform:

- Structured JSON logging with tenant context
- Centralized storage path resolution (local + S3)
- Shared Pydantic models for health checks, errors, and scan metadata
- FastAPI middleware for request logging and correlation IDs
- Retry handlers and circuit breaker patterns for external API calls

---

## Directory Structure

```
engine_common/
├── __init__.py               # Package initialization
├── storage_paths.py          # Storage path resolution (S3/local)
├── logger.py                 # Structured logging with tenant context
├── retry_handler.py          # Retry logic for external API calls
├── circuit_breaker.py        # Circuit breaker pattern
├── api_models.py             # Shared Pydantic models
└── middleware.py              # FastAPI middleware
```

---

## Modules

### `logger.py` — Structured Logging

Provides JSON-formatted logging with automatic tenant context propagation.

```python
from engine_common.logger import StructuredFormatter, LogContext, PhaseLogger

# Set tenant context for all log messages
with LogContext(tenant_id="tenant-123", scan_run_id="scan-456"):
    logger.info("Starting scan")
    # Output: {"timestamp": "...", "tenant_id": "tenant-123", "scan_run_id": "scan-456", "message": "Starting scan"}
```

**Key Classes:**
| Class | Purpose |
|-------|---------|
| `StructuredFormatter` | JSON log formatting with context fields |
| `LogContext` | Context manager for tenant_id, scan_run_id, account_id, user_id, ip_address |
| `PhaseLogger` | Phase-specific logging (discovery, check, inventory, etc.) |

**Features:**
- Audit logging for security-sensitive operations
- Security event logging for authentication failures
- Automatic field sanitization (masks passwords, tokens, keys)

---

### `storage_paths.py` — Storage Path Resolution

Centralized path management for scan results, supporting both local filesystem and S3.

```python
from engine_common.storage_paths import StoragePathResolver

resolver = StoragePathResolver()

# Get paths for scan artifacts
results_path = resolver.get_scan_results_path(scan_id="scan-123")
inventory_path = resolver.get_inventory_path(scan_id="scan-123")
summary_path = resolver.get_summary_path(scan_id="scan-123")
scan_dir = resolver.get_scan_directory(scan_id="scan-123")
```

**Environment Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `local` | Storage backend (`local` or `s3`) |
| `S3_BUCKET` | - | S3 bucket name (when `STORAGE_TYPE=s3`) |
| `WORKSPACE_ROOT` | `./engine_output` | Base path for local storage |

**Path Structure:**
```
engine_output/
├── {scan_id}/
│   ├── discoveries.ndjson
│   ├── check_results.ndjson
│   ├── inventory.ndjson
│   └── summary.json
└── latest/ -> symlink to most recent scan
```

---

### `api_models.py` — Shared Pydantic Models

Standardized request/response models used across all engine APIs.

```python
from engine_common.api_models import HealthResponse, ErrorResponse, ScanMetadata

# Health check response
health = HealthResponse(
    status="healthy",
    engine="threat",
    version="1.0.0"
)

# Scan metadata
metadata = ScanMetadata(
    scan_id="scan-123",
    tenant_id="tenant-456",
    status="running"
)
```

**Models:**
| Model | Fields | Usage |
|-------|--------|-------|
| `HealthResponse` | status, engine, version, uptime | `/health` endpoints |
| `ErrorResponse` | error, detail, status_code | Error responses |
| `ScanMetadata` | scan_id, tenant_id, status, timestamps | Scan tracking |
| `OrchestrationStatus` | pipeline stages, progress | Pipeline status |

---

### `middleware.py` — FastAPI Middleware

Request/response logging and correlation ID management.

```python
from fastapi import FastAPI
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

app = FastAPI()
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CorrelationIDMiddleware)
```

**Middleware:**
| Middleware | Purpose |
|-----------|---------|
| `RequestLoggingMiddleware` | Logs all requests/responses with timing |
| `CorrelationIDMiddleware` | Generates/propagates `X-Correlation-ID` header |

**Features:**
- Automatic sanitization of sensitive fields in logs
- Security event logging for failed auth attempts
- Request duration tracking

---

### `retry_handler.py` — Retry Logic

Configurable retry decorator for external API calls (AWS, database, inter-engine).

```python
from engine_common.retry_handler import retry_with_backoff

@retry_with_backoff(max_retries=3, backoff_factor=2)
def call_aws_api():
    # Automatically retries on failure with exponential backoff
    return boto3.client('s3').list_buckets()
```

---

### `circuit_breaker.py` — Circuit Breaker Pattern

Prevents cascading failures when downstream services are unavailable.

```python
from engine_common.circuit_breaker import CircuitBreaker

breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

@breaker
def call_downstream_service():
    # After 5 failures, circuit opens and calls fail fast
    # After 30 seconds, circuit enters half-open state
    return httpx.get("http://engine-threat:8020/health")
```

---

## Usage in Other Engines

Engines import `engine_common` as a shared dependency:

```python
# In any engine's api_server.py
import sys
sys.path.append('..')  # Add parent directory

from engine_common.logger import LogContext
from engine_common.storage_paths import StoragePathResolver
from engine_common.middleware import RequestLoggingMiddleware
```

Or via Docker volume mounts / Python path configuration in Kubernetes deployments.

---

## Dependencies

`engine_common` has no external dependencies beyond the Python standard library and packages already required by engines (FastAPI, Pydantic). It is designed to be lightweight and dependency-free.
