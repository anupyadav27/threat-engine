"""
Simple in-process TTL cache for BFF view responses.

Keyed on (view_name, tenant_id, scan_run_id, ..., role_level) so each
tenant+scan+role combo gets its own cached copy.  Including role_level
prevents a viewer's stripped response from being served to a platform_admin
(STRIDE: Info Disclosure — per-role cache namespace).

Cache is invalidated automatically when the TTL expires — no manual
invalidation needed since scans run infrequently.

Usage:
    from ._cache import cached_view, cache_key, auth_level_from_header

    role_level = auth_level_from_header(request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None))
    key = cache_key("compliance", tenant_id, scan_run_id or "latest",
                    role_level=role_level)
    result = cached_view(key)
    if result is not None:
        return result

    result = ... compute ...

    cached_view(key, result, ttl=120)
    return result
"""

import base64
import json
import time
from typing import Any, Dict, Optional, Tuple, Union

# { cache_key: (expires_at_epoch_float, value) }
_store: Dict[str, Tuple[float, Any]] = {}


def auth_level_from_header(header: Optional[str]) -> str:
    """
    Extract the role level integer from an X-Auth-Context header value.

    X-Auth-Context is a JSON string (plain JSON, not base64).  If parsing
    fails for any reason, returns "0" so the caller still gets a valid key
    segment.  This function never raises.

    Security note: the decoded payload is used ONLY to form a cache-key
    partition string — it is not used for access-control decisions.
    """
    if not header:
        return "0"
    try:
        ctx = json.loads(header)
        return str(ctx.get("level", 0))
    except Exception:
        # Attempt base64-decode fallback (defensive — header should be plain JSON)
        try:
            ctx = json.loads(base64.b64decode(header + "==").decode())
            return str(ctx.get("level", 0))
        except Exception:
            return "0"


def cache_key(*parts, role_level: Union[int, str, None] = None) -> str:
    """
    Build a string cache key from arbitrary parts plus an optional role_level.

    role_level is appended as the last segment when provided (not None).
    Existing callers that omit role_level continue to work unchanged.

    For RBAC-isolated views, always pass role_level so that different roles
    receive separate cache entries and do not share stripped/unstripped data.
    """
    all_parts = [str(p) for p in parts]
    if role_level is not None:
        all_parts.append(f"rl{role_level}")
    return "|".join(all_parts)


def cached_view(key: str, value: Any = None, ttl: int = 60) -> Optional[Any]:
    """
    Get-or-set helper.

    - Called with only ``key``  → returns cached value or None (cache miss).
    - Called with ``key + value + ttl`` → stores value, returns None.
    """
    now = time.monotonic()

    if value is None:
        # GET
        entry = _store.get(key)
        if entry is not None:
            expires_at, stored = entry
            if now < expires_at:
                return stored
            del _store[key]
        return None

    # SET — evict expired entries lazily (every 100 writes)
    if len(_store) % 100 == 0:
        expired = [k for k, (exp, _) in _store.items() if now >= exp]
        for k in expired:
            del _store[k]

    _store[key] = (now + ttl, value)
    return None


# ── Convenience TTLs (seconds) ────────────────────────────────────────────────
TTL_COMPLIANCE  =  30   # keep fresh — new scans complete and should appear quickly
TTL_NETWORK     =  60
TTL_IAM         =  60
TTL_THREATS     =  60
TTL_MISCONFIG   =  60
TTL_DATASEC     =  60
TTL_SECOPS      =  30   # scan list can update while user is on page
TTL_POLICIES    = 120
TTL_CIEM        =  60
TTL_DASHBOARD   =  30   # aggregates many engines — keep fresh
