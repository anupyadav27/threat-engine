"""
Reference table queries for account_providers, account_types, account_provider_type_map.

These replace the hardcoded dicts in constants.py.  The loader caches results
in-process for 5 minutes so hot paths (per-request validation) stay fast.
"""
import time
from typing import Any, Dict, FrozenSet, List, Optional

from engine_onboarding.database.connection import get_db_connection

# ── in-process cache (TTL = 300 s) ───────────────────────────────────────────

_CACHE: Dict[str, Any] = {}
_CACHE_TS: float = 0.0
_TTL: float = 300.0


def _load(conn) -> None:
    """Load all three reference tables into _CACHE."""
    global _CACHE, _CACHE_TS
    cur = conn.cursor()

    # account_providers
    cur.execute("""
        SELECT provider, display_name, category, credential_models,
               description, logo_key, display_order
        FROM   account_providers
        WHERE  is_active = true
        ORDER  BY display_order
    """)
    providers: Dict[str, Dict] = {}
    for row in cur.fetchall():
        providers[row[0]] = {
            "provider":          row[0],
            "display_name":      row[1],
            "category":          row[2],
            "credential_models": row[3] or [],
            "description":       row[4],
            "logo_key":          row[5],
            "display_order":     row[6],
        }

    # account_types
    cur.execute("""
        SELECT account_type, display_name, description, engines_triggered, display_order
        FROM   account_types
        WHERE  is_active = true
        ORDER  BY display_order
    """)
    account_types: Dict[str, Dict] = {}
    for row in cur.fetchall():
        account_types[row[0]] = {
            "account_type":    row[0],
            "display_name":    row[1],
            "description":     row[2],
            "engines_triggered": row[3] or [],
            "display_order":   row[4],
        }

    # provider → type map
    cur.execute("""
        SELECT provider, account_type, is_default
        FROM   account_provider_type_map
        ORDER  BY provider, is_default DESC
    """)
    provider_to_default: Dict[str, str] = {}
    provider_to_types: Dict[str, List[str]] = {}
    for row in cur.fetchall():
        p, t, is_def = row
        provider_to_types.setdefault(p, []).append(t)
        if is_def and p not in provider_to_default:
            provider_to_default[p] = t

    _CACHE = {
        "providers":           providers,
        "account_types":       account_types,
        "provider_to_default": provider_to_default,
        "provider_to_types":   provider_to_types,
    }
    _CACHE_TS = time.monotonic()


def _ensure_loaded() -> None:
    if time.monotonic() - _CACHE_TS > _TTL or not _CACHE:
        conn = get_db_connection()
        try:
            _load(conn)
        finally:
            conn.close()


# ── Public helpers (no conn arg — use internal connection pool) ───────────────

def get_all_providers() -> List[Dict]:
    """Return list of all active provider dicts, ordered by display_order."""
    _ensure_loaded()
    return list(_CACHE["providers"].values())


def get_all_account_types() -> List[Dict]:
    """Return list of all active account_type dicts, ordered by display_order."""
    _ensure_loaded()
    return list(_CACHE["account_types"].values())


def get_default_account_type(provider: str) -> str:
    """Return the default account_type for a provider (replaces PROVIDER_TO_ACCOUNT_TYPE)."""
    _ensure_loaded()
    return _CACHE["provider_to_default"].get(provider, "cloud_csp")


def get_valid_account_types_for_provider(provider: str) -> List[str]:
    """Return all account_types a provider can serve."""
    _ensure_loaded()
    return _CACHE["provider_to_types"].get(provider, ["cloud_csp"])


def get_engines_for_account_type(account_type: str) -> List[str]:
    """Return the engine list that should run for a given account_type."""
    _ensure_loaded()
    at = _CACHE["account_types"].get(account_type)
    return at["engines_triggered"] if at else ["discovery", "check", "inventory", "threat"]


def is_valid_provider(provider: str) -> bool:
    _ensure_loaded()
    return provider in _CACHE["providers"]


def is_valid_account_type(account_type: str) -> bool:
    _ensure_loaded()
    return account_type in _CACHE["account_types"]


def get_valid_account_type_set() -> FrozenSet[str]:
    """FrozenSet of all valid account_type strings — for validation without per-tenant scoping."""
    _ensure_loaded()
    return frozenset(_CACHE["account_types"].keys())


def invalidate_cache() -> None:
    """Force cache reload on next access (call after seeding/updates)."""
    global _CACHE_TS
    _CACHE_TS = 0.0
