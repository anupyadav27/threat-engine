#!/usr/bin/env python3
"""
Apply Relationship Rules to Inventory Findings
================================================
Reads resource_security_relationship_rules (is_active=TRUE) and inventory_findings,
extracts field values from each finding's properties, matches them against
target findings by resource_uid, and writes edges to inventory_relationships.

Usage:
    export INVENTORY_DB_URL="postgresql://user:pass@host:5432/threat_engine_inventory"
    python apply_relationship_rules.py

    # Scope to specific accounts or scan
    python apply_relationship_rules.py --account 588989875114 --provider aws
    python apply_relationship_rules.py --scan-id <scan_run_id>
    python apply_relationship_rules.py --dry-run
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── DB connection ─────────────────────────────────────────────────────────────

def _connect(dsn: Optional[str] = None) -> psycopg2.extensions.connection:
    dsn = dsn or os.getenv("INVENTORY_DB_URL")
    if not dsn:
        sys.exit("Set INVENTORY_DB_URL or pass DSN as first CLI argument.")
    return psycopg2.connect(dsn)


# ── Field extraction ──────────────────────────────────────────────────────────

def _get_nested(data: Any, path: str) -> Any:
    """
    Navigate a dot-separated path through nested dicts/lists.
    When hitting a list, fans out and collects results from all items.
    """
    if data is None or path == "":
        return data
    parts = path.split(".", 1)
    key = parts[0]
    rest = parts[1] if len(parts) > 1 else None

    if isinstance(data, dict):
        value = data.get(key)
    elif isinstance(data, list):
        # Fan out across list items
        results = []
        for item in data:
            v = _get_nested(item, path)
            if v is not None:
                if isinstance(v, list):
                    results.extend(v)
                else:
                    results.append(v)
        return results or None
    else:
        return None

    if rest is None:
        return value
    return _get_nested(value, rest)


def _extract_values(
    asset: Dict[str, Any],
    source_field: str,
    source_field_item: Optional[str],
) -> List[str]:
    """
    Extract string values from an asset using source_field (dot-path) and
    optional source_field_item (key within each list element).

    Search order: emitted_fields → properties (raw) → configuration → top-level.
    """
    props = asset.get("properties") or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = {}

    config = asset.get("configuration") or {}
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}

    # Prefer emitted_fields (normalised) then raw properties then configuration
    emitted = props.get("emitted_fields") or {}
    search_contexts = [emitted, props, config, asset]

    raw_value = None
    for ctx in search_contexts:
        if not isinstance(ctx, dict):
            continue
        v = _get_nested(ctx, source_field)
        if v is not None:
            raw_value = v
            break

    if raw_value is None:
        return []

    # If source_field_item is set, extract that sub-key from each list element
    if source_field_item:
        if isinstance(raw_value, list):
            results: List[str] = []
            for item in raw_value:
                if isinstance(item, dict):
                    sub = _get_nested(item, source_field_item)
                    if sub is not None:
                        if isinstance(sub, list):
                            results.extend(str(s) for s in sub if s is not None)
                        else:
                            results.append(str(sub))
            return results
        elif isinstance(raw_value, dict):
            sub = _get_nested(raw_value, source_field_item)
            return [str(sub)] if sub is not None else []
        return []

    # No item key — return scalar or list as strings
    if isinstance(raw_value, list):
        return [str(v) for v in raw_value if v is not None]
    return [str(raw_value)] if raw_value is not None else []


# ── Target UID construction ───────────────────────────────────────────────────

def _build_target_uids(
    pattern: str,
    extracted_value: str,
    asset: Dict[str, Any],
) -> List[str]:
    """
    Produce candidate target resource_uids from the rule's target_uid_pattern.

    Strategy:
      1. If pattern is a simple {placeholder}, the extracted value IS the uid.
      2. For complex patterns (ARN templates), substitute:
           - The "main" placeholder with extracted_value
           - Context placeholders (AccountId, Region, etc.) from the source asset
      3. Also return extracted_value as a direct fallback.
    """
    candidates: List[str] = []

    # Always try the raw extracted value first (it may already be the target uid)
    candidates.append(extracted_value)

    # Check if pattern is just a single placeholder
    if re.fullmatch(r'\{[\w.]+\}', pattern.strip()):
        return candidates  # just the extracted value

    # Build context from source asset
    props = asset.get("properties") or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = {}
    emitted = props.get("emitted_fields") or {} if isinstance(props, dict) else {}

    context: Dict[str, str] = {
        "AccountId":      str(asset.get("account_id", "")),
        "Account":        str(asset.get("account_id", "")),
        "Partition":      "aws",
        "Region":         str(asset.get("region", "")),
        "SubscriptionId": str(asset.get("account_id", "")),
        "project":        str(emitted.get("ProjectId") or emitted.get("project") or ""),
        "zone":           str(asset.get("region", "")),
        "region":         str(asset.get("region", "")),
    }

    # Find variable names in the pattern
    var_names = re.findall(r'\{(\w+)\}', pattern)

    result = pattern
    for var in var_names:
        if var in context and context[var]:
            result = result.replace(f"{{{var}}}", context[var])
        else:
            # Substitute the extracted value for the unresolved variable
            result = result.replace(f"{{{var}}}", extracted_value)

    if result != extracted_value:
        candidates.append(result)

    return candidates


# ── Main rule application ─────────────────────────────────────────────────────

def _load_rules(conn: psycopg2.extensions.connection) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT csp, service, from_resource_type, relation_type, to_resource_type,
                   source_field, source_field_item, target_uid_pattern
            FROM resource_security_relationship_rules
            WHERE is_active = TRUE
            ORDER BY csp, from_resource_type
        """)
        return [dict(r) for r in cur.fetchall()]


def _load_findings(
    conn: psycopg2.extensions.connection,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Tuple[Dict[str, Dict], Dict[Tuple[str, str], List[Dict]]]:
    """
    Load all findings into two indexes:
      by_uid:  resource_uid → finding
      by_type: (provider, resource_type) → [findings]
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        conditions = []
        params: List[Any] = []
        if account_id:
            conditions.append("account_id = %s")
            params.append(account_id)
        if provider:
            conditions.append("provider = %s")
            params.append(provider)
        if scan_id:
            conditions.append("scan_run_id = %s")
            params.append(scan_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        cur.execute(f"""
            SELECT finding_id, tenant_id, scan_run_id,
                   resource_uid, resource_type, provider,
                   account_id, region, name,
                   properties, configuration, tags
            FROM inventory_findings
            {where}
        """, params)
        rows = cur.fetchall()

    by_uid: Dict[str, Dict] = {}
    by_type: Dict[Tuple[str, str], List[Dict]] = {}

    for row in rows:
        d = dict(row)
        uid = d["resource_uid"]
        if uid:
            by_uid[uid] = d
        key = (d["provider"] or "", d["resource_type"] or "")
        by_type.setdefault(key, []).append(d)

    log.info(f"Loaded {len(rows)} findings → {len(by_uid)} unique UIDs, {len(by_type)} resource types")
    return by_uid, by_type


def apply_rules(
    conn: psycopg2.extensions.connection,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    scan_id: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    rules = _load_rules(conn)
    log.info(f"Loaded {len(rules)} active rules")

    by_uid, by_type = _load_findings(conn, account_id, provider, scan_id)

    # Build a lowercase-uid index for case-insensitive matching
    by_uid_lower: Dict[str, Dict] = {k.lower(): v for k, v in by_uid.items()}

    relationships: List[Dict[str, Any]] = []
    seen: set = set()

    matched_rules = 0
    skipped_rules = 0

    for rule in rules:
        csp          = rule["csp"]
        from_rt      = rule["from_resource_type"]
        to_rt        = rule["to_resource_type"]
        relation     = rule["relation_type"]
        src_field    = rule["source_field"]
        src_item     = rule["source_field_item"]
        tgt_pattern  = rule["target_uid_pattern"]

        source_assets = by_type.get((csp, from_rt), [])
        if not source_assets:
            skipped_rules += 1
            continue

        rule_matched = 0
        for asset in source_assets:
            values = _extract_values(asset, src_field, src_item)
            for val in values:
                if not val or val in ("None", "null", ""):
                    continue

                # Build candidate target UIDs
                candidates = _build_target_uids(tgt_pattern, val, asset)

                target = None
                for candidate in candidates:
                    target = (
                        by_uid.get(candidate)
                        or by_uid_lower.get(candidate.lower())
                    )
                    if target:
                        break

                if target is None:
                    continue

                # Dedup key
                edge_key = (
                    asset["resource_uid"],
                    target["resource_uid"],
                    relation,
                )
                if edge_key in seen:
                    continue
                seen.add(edge_key)

                relationships.append({
                    "relationship_id":     str(uuid.uuid4()),
                    "tenant_id":           asset.get("tenant_id") or target.get("tenant_id"),
                    "scan_run_id":   asset.get("scan_run_id"),
                    "provider":            csp,
                    "account_id":          asset.get("account_id"),
                    "region":              asset.get("region"),
                    "relation_type":       relation,
                    "from_uid":            asset["resource_uid"],
                    "to_uid":              target["resource_uid"],
                    "from_resource_type":  from_rt,
                    "to_resource_type":    to_rt,
                    "relationship_strength": "strong",
                    "bidirectional":       False,
                    "properties":          json.dumps({"matched_field": src_field, "matched_value": val}),
                    "metadata":            json.dumps({"rule_source": "resource_security_relationship_rules"}),
                    "source_resource_uid": asset["resource_uid"],
                    "target_resource_uid": target["resource_uid"],
                    "relationship_type":   relation,
                    "first_seen_at": datetime.now(timezone.utc).isoformat(),
                    "last_confirmed_at":   datetime.now(timezone.utc).isoformat(),
                    "created_at":          datetime.now(timezone.utc).isoformat(),
                })
                rule_matched += 1

        if rule_matched > 0:
            matched_rules += 1

    log.info(
        f"Rule matching complete: {len(relationships)} edges from "
        f"{matched_rules}/{len(rules)} rules. "
        f"({skipped_rules} rules had no source assets in scope)"
    )

    if dry_run:
        log.info(f"[DRY RUN] Would insert {len(relationships)} relationships")
        # Print a sample
        for rel in relationships[:10]:
            log.info(
                f"  {rel['from_resource_type']} --[{rel['relation_type']}]--> "
                f"{rel['to_resource_type']}  "
                f"({rel['from_uid'][-40:]} → {rel['to_uid'][-40:]})"
            )
        return len(relationships)

    # Write to inventory_relationships
    if not relationships:
        log.info("No relationships to write.")
        return 0

    sql = """
        INSERT INTO inventory_relationships (
            relationship_id, tenant_id, scan_run_id,
            provider, account_id, region,
            relation_type, from_uid, to_uid,
            from_resource_type, to_resource_type,
            relationship_strength, bidirectional,
            properties, metadata,
            source_resource_uid, target_resource_uid, relationship_type,
            first_seen_at, last_confirmed_at, created_at
        ) VALUES (
            %(relationship_id)s, %(tenant_id)s, %(scan_run_id)s,
            %(provider)s, %(account_id)s, %(region)s,
            %(relation_type)s, %(from_uid)s, %(to_uid)s,
            %(from_resource_type)s, %(to_resource_type)s,
            %(relationship_strength)s, %(bidirectional)s,
            %(properties)s::jsonb, %(metadata)s::jsonb,
            %(source_resource_uid)s, %(target_resource_uid)s, %(relationship_type)s,
            %(first_seen_at)s, %(last_confirmed_at)s, %(created_at)s
        )
        ON CONFLICT DO NOTHING
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, relationships, page_size=500)
    conn.commit()
    log.info(f"Written {len(relationships)} relationships to inventory_relationships")
    return len(relationships)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Apply relationship rules to inventory findings")
    parser.add_argument("dsn", nargs="?", help="PostgreSQL DSN (or set INVENTORY_DB_URL)")
    parser.add_argument("--account", help="Filter by account_id")
    parser.add_argument("--provider", help="Filter by provider (aws/azure/gcp)")
    parser.add_argument("--scan-id", dest="scan_id", help="Filter by scan_run_id")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()

    conn = _connect(args.dsn)
    total = apply_rules(
        conn,
        account_id=args.account,
        provider=args.provider,
        scan_id=args.scan_id,
        dry_run=args.dry_run,
    )
    conn.close()
    log.info(f"Done. Total edges: {total}")
