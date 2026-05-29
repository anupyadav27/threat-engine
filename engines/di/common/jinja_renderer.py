"""Catalog-as-truth Jinja renderer for discovery emit blocks (DCAT-01).

Every catalog YAML / rule_discoveries DB row declares an `emit.item:` block of
field templates like `{{ response.KeyMetadata.KeySpec }}`. This module renders
those templates against the boto3/SDK response so the resulting
`discovery_findings.emitted_fields` is FLAT — no nested envelopes.

Failure observability is built-in: any field that fails to render is recorded
to `discovery_emit_failures` so the catalog gap is observable, not silent.

Used by every CSP scanner (aws/gcp/azure/oci/alicloud/k8s/ibm). Provider
scanners must call render_emit_item() and emit_failure_log() in place of the
old "raw response dump" path.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("discovery.jinja_renderer")


# ── Jinja environment (NativeEnvironment preserves Python types) ─────────────

try:
    from jinja2 import ChainableUndefined, Undefined
    from jinja2.nativetypes import NativeEnvironment

    _JINJA_AVAILABLE = True
    _ENV: Optional[NativeEnvironment] = NativeEnvironment(
        undefined=ChainableUndefined,
        autoescape=False,
        keep_trailing_newline=False,
    )
except ImportError:  # pragma: no cover — Jinja must be installed
    _JINJA_AVAILABLE = False
    _ENV = None
    ChainableUndefined = None  # type: ignore[assignment,misc]
    Undefined = None  # type: ignore[assignment,misc]


# ── Failure record schema ────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_undefined(value: Any) -> bool:
    """Detect Jinja Undefined / ChainableUndefined sentinel."""
    if Undefined is None:
        return False
    return isinstance(value, Undefined)


def _normalize_value(rendered: Any) -> Any:
    """Convert Jinja Undefined / empty placeholders into None.

    Native env preserves Python types, but missing paths yield Undefined.
    Empty string from `{{ x.missing }}` (when not Strict) → None too.
    """
    if rendered is None:
        return None
    if _is_undefined(rendered):
        return None
    if isinstance(rendered, str) and rendered in ("", "None", "Undefined"):
        return None
    return rendered


# ── Public API ───────────────────────────────────────────────────────────────


def render_emit_item(
    item_template: Dict[str, str],
    context: Dict[str, Any],
    *,
    discovery_id: str = "",
    resource_uid: str = "",
    failure_sink: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Render every field in an emit.item block against the SDK response.

    Args:
        item_template: dict of {field_name: '{{ response.X.Y }}'} from catalog.
        context: ctx for Jinja — typically {'response': raw_response,
                 'item': iteration_item, 'context': scan_context}.
        discovery_id: catalog discovery_id for failure logs.
        resource_uid: optional resource ARN/UID for failure logs.
        failure_sink: optional list — if provided, failed renders append a
                      structured row here (caller flushes to DB).

    Returns:
        flat dict {field_name: rendered_value_or_None}.
    """
    if not _JINJA_AVAILABLE or _ENV is None:
        logger.warning("Jinja2 unavailable — emit rendering disabled")
        return {}

    if not isinstance(item_template, dict):
        return {}

    out: Dict[str, Any] = {}
    response_keys: List[str] = []
    if isinstance(context.get("response"), dict):
        response_keys = list(context["response"].keys())[:15]

    for field_name, template_str in item_template.items():
        if not isinstance(template_str, str):
            # Non-template literal value (e.g. constant) — pass through
            out[field_name] = template_str
            continue

        if "{{" not in template_str:
            # Plain string literal in YAML — keep as-is
            out[field_name] = template_str
            continue

        try:
            rendered = _ENV.from_string(template_str).render(**context)
        except Exception as exc:
            out[field_name] = None
            if failure_sink is not None:
                failure_sink.append({
                    "discovery_id": discovery_id,
                    "resource_uid": resource_uid,
                    "field_name": field_name,
                    "template": template_str,
                    "failure_reason": "jinja_syntax",
                    "failure_detail": str(exc)[:500],
                    "response_keys": response_keys,
                    "occurred_at": _now(),
                })
            continue

        normalized = _normalize_value(rendered)
        if normalized is None and rendered is not None:
            # Path was undefined — log it
            if failure_sink is not None:
                failure_sink.append({
                    "discovery_id": discovery_id,
                    "resource_uid": resource_uid,
                    "field_name": field_name,
                    "template": template_str,
                    "failure_reason": "undefined_path",
                    "failure_detail": (
                        f"path missing in response; "
                        f"top-level keys: {response_keys}"
                    ),
                    "response_keys": response_keys,
                    "occurred_at": _now(),
                })

        out[field_name] = normalized

    return out


def render_emit_for_list(
    item_template: Dict[str, str],
    items: List[Any],
    base_context: Dict[str, Any],
    *,
    discovery_id: str = "",
    failure_sink: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Render an emit.item template once per element in an items_for list.

    Each element is bound to the `item` context variable; the original
    `response` and `context` are still accessible.

    Args:
        item_template: same as render_emit_item.
        items: extracted list (e.g. response.Keys from list_keys).
        base_context: outer ctx — must contain 'response' and 'context'.
        discovery_id: for failure logging.
        failure_sink: optional shared sink for failure rows.

    Returns:
        list of flat dicts, one per element.
    """
    if not isinstance(items, list):
        return []

    results: List[Dict[str, Any]] = []
    for element in items:
        ctx = dict(base_context)
        ctx["item"] = element
        # Per-resource UID for the failure sink (best-effort)
        rid = ""
        if isinstance(element, dict):
            rid = (
                element.get("resource_arn")
                or element.get("Arn")
                or element.get("ResourceId")
                or element.get("KeyArn")
                or ""
            )
        rendered = render_emit_item(
            item_template,
            ctx,
            discovery_id=discovery_id,
            resource_uid=rid,
            failure_sink=failure_sink,
        )
        results.append(rendered)
    return results


# ── DB-side: failure log persistence ─────────────────────────────────────────


_DDL_DISCOVERY_EMIT_FAILURES = """
CREATE TABLE IF NOT EXISTS discovery_emit_failures (
    id              BIGSERIAL PRIMARY KEY,
    scan_run_id     UUID,
    tenant_id       VARCHAR(64),
    provider        VARCHAR(20),
    service         VARCHAR(64),
    discovery_id    VARCHAR(128) NOT NULL,
    resource_uid    VARCHAR(512),
    field_name      VARCHAR(128) NOT NULL,
    template        TEXT NOT NULL,
    failure_reason  VARCHAR(32) NOT NULL,
    failure_detail  TEXT,
    response_keys   JSONB,
    occurred_at     TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_emit_fail_lookup
    ON discovery_emit_failures(provider, service, discovery_id, field_name);
CREATE INDEX IF NOT EXISTS idx_emit_fail_recent
    ON discovery_emit_failures(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_emit_fail_scan
    ON discovery_emit_failures(scan_run_id);
"""


def ensure_failure_table(conn) -> None:
    """Create discovery_emit_failures if missing — safe to call on every boot."""
    try:
        with conn.cursor() as cur:
            cur.execute(_DDL_DISCOVERY_EMIT_FAILURES)
        conn.commit()
    except Exception as exc:
        logger.warning("ensure_failure_table failed: %s", exc)


def flush_failures(
    conn,
    rows: List[Dict[str, Any]],
    *,
    scan_run_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    service: Optional[str] = None,
) -> int:
    """Bulk insert collected failure rows. Tolerant of partial column sets."""
    if not rows:
        return 0
    if os.getenv("DISCOVERY_EMIT_FAIL_LOG", "true").lower() in ("0", "false", "off"):
        return 0
    inserted = 0
    try:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO discovery_emit_failures
                        (scan_run_id, tenant_id, provider, service, discovery_id,
                         resource_uid, field_name, template, failure_reason,
                         failure_detail, response_keys, occurred_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        scan_run_id,
                        tenant_id,
                        provider,
                        service,
                        r.get("discovery_id"),
                        r.get("resource_uid"),
                        r.get("field_name"),
                        r.get("template"),
                        r.get("failure_reason"),
                        r.get("failure_detail"),
                        _serialize_json(r.get("response_keys")),
                        r.get("occurred_at") or _now(),
                    ),
                )
                inserted += 1
        conn.commit()
    except Exception as exc:
        logger.warning("flush_failures partial — %d/%d inserted: %s",
                       inserted, len(rows), exc)
        try:
            conn.rollback()
        except Exception:
            pass
    return inserted


def _serialize_json(value: Any) -> Optional[str]:
    if value is None:
        return None
    import json as _json
    try:
        return _json.dumps(value, default=str)
    except Exception:
        return None


# ── Helpers ──────────────────────────────────────────────────────────────────


def feature_enabled() -> bool:
    """Discovery render gate. Default true; set DISCOVERY_RENDER_EMIT=false to disable."""
    return os.getenv("DISCOVERY_RENDER_EMIT", "true").lower() not in (
        "0",
        "false",
        "off",
    )


__all__ = [
    "render_emit_item",
    "render_emit_for_list",
    "ensure_failure_table",
    "flush_failures",
    "feature_enabled",
]
