---
story_id: AZ-02b
title: Per-Call Timeout Wrapper on Azure ThreadPoolExecutor
status: done
sprint: azure-track-wave-2
depends_on: [AZ-01]
blocks: [AZ-04]
sme: Python/azure-mgmt-* engineer
estimate: 0.5 days
---

# Story: Per-Call Timeout Wrapper on Azure ThreadPoolExecutor

## Context
Azure SDK calls can hang indefinitely if the service is slow or rate-limited. The AWS scanner wraps every API call with `future.result(timeout=OPERATION_TIMEOUT)` where `OPERATION_TIMEOUT=10`. Azure must do the same.

Without this, a single hung Azure call blocks an executor thread indefinitely, causing the entire region scan to stall.

## Files to Modify

- `engines/discoveries/providers/azure/scanner/service_scanner.py` — add timeout wrapper utility

## Implementation Notes

```python
import logging
from concurrent.futures import Future, TimeoutError as FuturesTimeoutError

logger = logging.getLogger(__name__)
OPERATION_TIMEOUT = 10  # seconds — same as AWS scanner

def _call_with_timeout(future: Future, service: str, region: str) -> Any:
    """Execute a submitted future with timeout.
    
    Args:
        future: Submitted executor future
        service: Service name for logging context
        region: Region name for logging context
        
    Returns:
        Future result, or None on timeout/error
    """
    try:
        return future.result(timeout=OPERATION_TIMEOUT)
    except FuturesTimeoutError:
        logger.warning(
            "Azure API call timed out after %ds: service=%s region=%s",
            OPERATION_TIMEOUT, service, region
        )
        return None
    except Exception as exc:
        logger.error(
            "Azure API call failed: service=%s region=%s error=%s",
            service, region, exc
        )
        return None
```

Usage in scanner:
```python
with ThreadPoolExecutor(max_workers=10) as executor:
    future = executor.submit(client.virtual_machines.list_all)
    result = _call_with_timeout(future, service="compute", region=region)
    if result is None:
        continue  # timed out or errored — skip, already logged
```

## Reference Files
- AWS timeout pattern: `engines/discoveries/providers/aws/scanner/service_scanner.py` — search for `OPERATION_TIMEOUT`

## Acceptance Criteria
- [ ] `OPERATION_TIMEOUT = 10` constant defined
- [ ] `_call_with_timeout()` function implemented
- [ ] Unit test: mock future that raises `TimeoutError` → function returns `None`, logs WARNING
- [ ] Unit test: mock future that raises generic `Exception` → function returns `None`, logs ERROR
- [ ] Unit test: mock future that returns normally → function returns result

## Definition of Done
- [ ] Timeout wrapper implemented and unit-tested
- [ ] `OPERATION_TIMEOUT` matches AWS value (10 seconds)
- [ ] No bare `future.result()` calls without timeout in the scanner file