"""Scope filtering helpers for BFF view handlers.

Reads tenant_ids (comma-separated engine_tenant_ids) and account_ids
(comma-separated cloud account IDs) from incoming request query params.

Usage in BFF handlers that perform direct SQL:
    query, params = apply_scope(query, params, request)

Usage in BFF handlers that need the raw lists:
    tids = scope_tenant_ids(request)  # List[str] | None
    aids = scope_account_ids(request) # List[str] | None
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from fastapi import Request


def apply_scope(query: str, params: list, request: Request) -> Tuple[str, list]:
    """Append tenant/account WHERE clauses from scope query params."""
    tids = scope_tenant_ids(request)
    if tids:
        query += " AND tenant_id = ANY(%s)"
        params.append(tids)

    aids = scope_account_ids(request)
    if aids:
        query += " AND account_id = ANY(%s)"
        params.append(aids)

    return query, params


def scope_tenant_ids(request: Request) -> Optional[List[str]]:
    """Return list of tenant_ids from scope params, or None if not set."""
    raw = request.query_params.get("tenant_ids", "").strip()
    if not raw:
        return None
    ids = [t.strip() for t in raw.split(",") if t.strip()]
    return ids or None


def scope_account_ids(request: Request) -> Optional[List[str]]:
    """Return list of account_ids from scope params, or None if not set."""
    raw = request.query_params.get("account_ids", "").strip()
    if not raw:
        return None
    ids = [a.strip() for a in raw.split(",") if a.strip()]
    return ids or None


def build_scope_params(request: Request) -> dict:
    """Return dict of non-None scope params for forwarding to engine HTTP calls."""
    out: dict = {}
    tids = scope_tenant_ids(request)
    if tids:
        out["tenant_ids"] = ",".join(tids)
    aids = scope_account_ids(request)
    if aids:
        out["account_ids"] = ",".join(aids)
    return out
