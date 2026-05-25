"""
Phase 1 — Enricher (all CSPs)

Runs enrich_ops for each Phase 0 row.  Each enrich_op produces its own
asset_inventory rows with its own discovery_id — check engine DIReader
queries asset_inventory by discovery_id directly (WHERE discovery_id = for_each).

Row model:
  - items_for is set  → N rows, uid = parent_uid#{i}, one per list item
  - items_for is None → 1 row, uid = parent_uid (merged response)

The Phase 0 root row is preserved as-is in enriched_rows.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("di.phase1.enricher")

_PARAM_RE = re.compile(r"\{item\.([^}]+)\}")


class Phase1Result:
    """Holds Phase 1 enrichment output."""

    def __init__(self) -> None:
        self.enriched_rows: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []


async def run_phase1(
    phase0_rows: List[Dict[str, Any]],
    scanner: Any,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> Phase1Result:
    """Run Phase 1 enrichment for all Phase 0 rows.

    Each Phase 0 row is preserved. For each enrich_op in its identifier,
    one or more new rows are emitted with the enrich_op's discovery_id.

    Args:
        phase0_rows: Output from Phase 0 — list of row dicts with 'identifier' key.
        scanner: Authenticated scanner from Phase 0.
        scan_run_id: Pipeline scan run UUID.
        tenant_id: Tenant identifier.
        provider: Cloud provider name.

    Returns:
        Phase1Result with all rows (Phase 0 roots + Phase 1 enrich rows).
    """
    result = Phase1Result()

    if not phase0_rows:
        return result

    logger.info(
        "Phase 1 start: provider=%s rows=%d", provider, len(phase0_rows)
    )

    for row in phase0_rows:
        # Always keep the Phase 0 root row
        result.enriched_rows.append(_strip_identifier(dict(row)))

        identifier = row.get("identifier", {})
        enrich_ops: List[Dict[str, Any]] = identifier.get("enrich_ops") or []

        for enrich_op in enrich_ops:
            try:
                new_rows = await _run_one_enrich_op(
                    row=row,
                    enrich_op=enrich_op,
                    scanner=scanner,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    provider=provider,
                )
                result.enriched_rows.extend(new_rows)
                logger.debug(
                    "Phase 1 enrich: op=%s uid=%s → %d rows",
                    enrich_op.get("discovery_id"), row["resource_uid"], len(new_rows),
                )
            except Exception as e:
                on_error = enrich_op.get("on_error", "skip")
                logger.error(
                    "Phase 1 enrich op=%s uid=%s failed (%s): %s",
                    enrich_op.get("discovery_id"), row["resource_uid"], on_error, e,
                )
                if on_error != "skip":
                    result.errors.append({
                        "scan_run_id": scan_run_id,
                        "tenant_id": tenant_id,
                        "account_id": row.get("account_id", ""),
                        "provider": provider,
                        "service": row.get("service", ""),
                        "region": row.get("region", ""),
                        "resource_type": row.get("resource_type", ""),
                        "error_type": type(e).__name__,
                        "error_message": str(e)[:2000],
                        "raw_item_keys": enrich_op.get("discovery_id"),
                    })

    logger.info(
        "Phase 1 complete: provider=%s total_rows=%d errors=%d",
        provider, len(result.enriched_rows), len(result.errors),
    )
    return result


async def _run_one_enrich_op(
    row: Dict[str, Any],
    enrich_op: Dict[str, Any],
    scanner: Any,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """Call one enrich_op and return asset_inventory rows for it.

    Args:
        row: The Phase 0 parent row (contains emitted_fields for param substitution).
        enrich_op: The enrich_op dict from resource_inventory_identifier.enrich_ops.
        scanner: Authenticated scanner.

    Returns:
        List of new asset_inventory row dicts with enrich_op's discovery_id.
    """
    parent_uid = row["resource_uid"]
    parent_item = row.get("emitted_fields") or {}
    enrich_did = enrich_op.get("discovery_id", "")
    items_for = enrich_op.get("items_for")
    service = row.get("service", "")
    region = row.get("region", "")

    # Resolve params: substitute {item.FieldName} from parent emitted_fields
    resolved_params = _resolve_params(enrich_op.get("params") or {}, parent_item)

    # Call the scanner for this specific op
    items = await _call_enrich_op(
        scanner=scanner,
        service=service,
        region=region,
        enrich_op=enrich_op,
        resolved_params=resolved_params,
    )

    base = _base_fields(row, scan_run_id, tenant_id, provider)
    new_rows: List[Dict[str, Any]] = []

    if items_for:
        # One asset_inventory row per list item — uid = parent_uid#{i}
        for i, item in enumerate(items):
            emitted = item if isinstance(item, dict) else {"value": item}
            new_rows.append({
                **base,
                "resource_uid": f"{parent_uid}#{i}",
                "discovery_id": enrich_did,
                "emitted_fields": emitted,
                "raw_response": emitted,
                "phase": 1,
            })
    else:
        # One row — merge all returned fields (typically a single-resource detail call)
        merged: Dict[str, Any] = {}
        for item in items:
            if isinstance(item, dict):
                merged.update(item)
        new_rows.append({
            **base,
            "resource_uid": parent_uid,
            "discovery_id": enrich_did,
            "emitted_fields": merged,
            "raw_response": merged,
            "phase": 1,
        })

    return new_rows


async def _call_enrich_op(
    scanner: Any,
    service: str,
    region: str,
    enrich_op: Dict[str, Any],
    resolved_params: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Invoke the scanner for one enrich_op with resolved params.

    Passes a single-op config to scan_service so the scanner applies its
    standard pagination, retry, and error-handling logic.
    """
    if not hasattr(scanner, "scan_service"):
        return []

    op_entry = dict(enrich_op)
    op_entry["params"] = resolved_params

    config = {"root_ops": [op_entry], "skip_writes": True}

    try:
        items, _ = await scanner.scan_service(
            service=service,
            region=region,
            config=config,
            skip_dependents=True,
        )
        return items or []
    except Exception:
        raise


def _resolve_params(
    params: Dict[str, Any],
    parent_item: Dict[str, Any],
) -> Dict[str, Any]:
    """Substitute {item.FieldName} placeholders in params from parent item."""
    resolved: Dict[str, Any] = {}
    for key, val in params.items():
        if isinstance(val, str):
            def _replace(m: re.Match) -> str:
                field = m.group(1)
                v = parent_item.get(field)
                return str(v) if v is not None else m.group(0)
            resolved[key] = _PARAM_RE.sub(_replace, val)
        else:
            resolved[key] = val
    return resolved


def _base_fields(
    row: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> Dict[str, Any]:
    """Build the common fields shared between parent and enrich rows."""
    return {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": row.get("account_id", ""),
        "provider": provider,
        "region": row.get("region", ""),
        "credential_ref": row.get("credential_ref"),
        "credential_type": row.get("credential_type"),
        "resource_type": row.get("resource_type", ""),
        "resource_name": row.get("resource_name"),
        "service": row.get("service", ""),
    }


def _strip_identifier(row: Dict[str, Any]) -> Dict[str, Any]:
    """Remove the 'identifier' helper key before writing to DB."""
    row.pop("identifier", None)
    return row
