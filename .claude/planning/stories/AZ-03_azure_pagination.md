---
story_id: AZ-03
title: Azure Pagination Helpers
status: done
sprint: azure-track-wave-3
depends_on: [AZ-02]
blocks: [AZ-04]
sme: Python/azure-mgmt-* engineer
estimate: 0.5 days
---

# Story: Azure Pagination Helpers

## Context
Azure SDK returns `ItemPaged` lazy iterators, not full lists. Unlike AWS paginator tokens, Azure handles pagination internally — you iterate through `ItemPaged` and SDK fetches next pages automatically. The helper standardizes this into a flat list of dicts for consistent processing downstream.

Also includes the HTTP 429 retry wrapper (SHARED-04 requirement surfaced here since pagination is where rate limits hit).

## Files to Modify

- `engines/discoveries/providers/azure/pagination.py` — full implementation

## Implementation Notes

```python
"""Azure pagination helpers with retry-on-rate-limit."""
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BASE_DELAY = 2.0    # seconds
MAX_DELAY = 30.0    # seconds


def azure_list_all(
    client_method: Callable,
    serializer: Optional[Callable] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Iterate an Azure ItemPaged result into a flat list of dicts.
    
    Handles:
    - Lazy pagination (SDK fetches pages automatically)
    - HTTP 429 rate limit with exponential backoff
    - Per-item serialization via .as_dict() or custom serializer
    
    Args:
        client_method: Azure SDK list method to call (e.g., client.virtual_machines.list_all)
        serializer: Optional custom serializer. Defaults to item.as_dict()
        **kwargs: Additional kwargs passed to client_method
        
    Returns:
        Flat list of resource dicts
    """
    results: List[Dict[str, Any]] = []
    attempt = 0
    
    while attempt <= MAX_RETRIES:
        try:
            pager = client_method(**kwargs)
            for item in pager:
                if serializer:
                    results.append(serializer(item))
                elif hasattr(item, "as_dict"):
                    results.append(item.as_dict())
                else:
                    results.append(vars(item))
            return results
            
        except HttpResponseError as exc:
            if exc.status_code == 429:
                delay = min(BASE_DELAY * (2 ** attempt), MAX_DELAY)
                logger.warning(
                    "Azure rate limit (429) — retrying in %.1fs (attempt %d/%d)",
                    delay, attempt + 1, MAX_RETRIES
                )
                time.sleep(delay)
                attempt += 1
            else:
                logger.error("Azure API error: %s", exc)
                return results  # return partial results, log error
                
    logger.error("Azure rate limit exceeded after %d retries — returning partial results", MAX_RETRIES)
    return results
```

## Acceptance Criteria
- [ ] Unit test: mock `ItemPaged` with 3 pages of 10 items each → `azure_list_all()` returns flat list of 30 dicts
- [ ] Unit test: mock client that raises `HttpResponseError(status_code=429)` on first 2 calls, succeeds on 3rd → function succeeds with exponential backoff, logs 2 WARNING messages
- [ ] Unit test: mock client that raises `HttpResponseError(status_code=429)` on all `MAX_RETRIES+1` calls → function logs ERROR and returns empty list (does not raise)
- [ ] `BASE_DELAY=2`, `MAX_DELAY=30`, `MAX_RETRIES=3` constants present
- [ ] Items serialized via `.as_dict()` by default

## Definition of Done
- [ ] `pagination.py` implemented with all unit tests passing
- [ ] Rate limit retry logic tested
- [ ] No `time.sleep()` in non-retry path