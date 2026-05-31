"""
Phase 0 — Identifier Loader

Reads from rule_discoveries (threat_engine_check) to build the identifier
map that drives Phase 0 enumeration and Phase 1 enrichment.

Design principles:
  - rule_discoveries.is_active = TRUE/FALSE is the enable/disable flag for
    a service. Setting it FALSE silences that service across ALL engines.
  - Only services that have at least one active check rule are loaded.
    The 329 discovery-only services (no check rules) are skipped automatically.
  - discoveries_data JSONB stores the full YAML as a dict. Root ops have no
    for_each; enrichment ops have for_each pointing at their parent discovery_id.
  - Works for all CSPs: aws, azure, gcp, oci, ibm, alicloud, k8s — the
    rule_discoveries table has a provider column covering all of them.

Returned identifier dict (keyed by root op discovery_id):
  {
    "aws.s3.list_buckets": {
      "service":        "s3",
      "csp":            "aws",
      "boto3_client":   "s3",
      "discovery_id":   "aws.s3.list_buckets",
      "uid_template":   "arn:aws:s3:::{item.Name}",   # None → heuristic
      "uid_source":     "template" | "heuristic",
      "root_op":        { ...full op dict from YAML... },
      "enrich_ops":     [ ...ops whose for_each == this discovery_id... ],
      "items_for":      True,                          # root emits a list
      "emit_fields":    ["Name", "BucketArn", ...],
      "resource_type":  "s3_bucket",
    },
    ...
  }
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

import psycopg2
import psycopg2.extras

logger = logging.getLogger("di.phase0.identifier_loader")

# Services whose check rules live under a logical group name that differs
# from the rule_discoveries service name. Maps logical → real discovery service.
_SERVICE_ALIAS: Dict[str, List[str]] = {
    "compute": ["ec2", "ecs", "ssm"],
    "network": ["vpc"],
    "media_import_export": ["importexport"],
}

# Inverse: real service → logical name (for de-duplication)
_ALIAS_REVERSE: Dict[str, str] = {}
for _logical, _reals in _SERVICE_ALIAS.items():
    for _r in _reals:
        _ALIAS_REVERSE[_r] = _logical

# Discovery IDs that return account/IAM metadata rather than real inventoriable
# resources — their emitted ARNs belong to a different service than the scanner.
_SKIP_DISCOVERY_IDS: Set[str] = {
    "aws.ec2.describe_principal_id_format",  # returns IAM principal ARNs, not EC2 resources
}


def _get_check_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=(
            os.getenv("CHECK_DB_PASSWORD")
            or os.getenv("DB_PASSWORD")
            or ""
        ),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _load_check_services(cur: Any, csp: str) -> Set[str]:
    """Return the set of services that have at least one active check rule.

    Resolves service aliases: check rules filed under 'compute' map to
    ec2/ecs/ssm in rule_discoveries.
    """
    cur.execute(
        """
        SELECT DISTINCT service
        FROM   rule_checks
        WHERE  provider = %s
          AND  is_active = TRUE
        """,
        (csp,),
    )
    logical_services = {row["service"] for row in cur.fetchall()}

    real_services: Set[str] = set()
    for svc in logical_services:
        if svc in _SERVICE_ALIAS:
            real_services.update(_SERVICE_ALIAS[svc])
        else:
            real_services.add(svc)

    logger.info(
        "Check-needed services for csp=%s: %d services", csp, len(real_services)
    )
    return real_services


def _derive_resource_type(service: str, action: str) -> str:
    """Derive a human-readable resource_type from service + action.

    list_buckets → s3_bucket
    describe_instances → ec2_instance
    list_users → iam_user
    """
    # Strip common verb prefixes to get the entity noun
    entity = action
    for prefix in ("list_", "describe_", "get_", "scan_", "search_"):
        if action.startswith(prefix):
            entity = action[len(prefix):]
            break

    # Singularise naively: trailing 's' → remove; 'es' → remove
    if entity.endswith("ies"):
        entity = entity[:-3] + "y"
    elif entity.endswith("ses") or entity.endswith("xes"):
        entity = entity[:-2]
    elif entity.endswith("s") and not entity.endswith("ss"):
        entity = entity[:-1]

    return f"{service}_{entity}"


def load_identifiers(csp: str) -> Dict[str, Any]:
    """Load active identifiers for a CSP, keyed by root-op discovery_id.

    Only loads services that:
      1. Have is_active = TRUE in rule_discoveries
      2. Have at least one active check rule in rule_checks

    Returns:
        Dict mapping root-op discovery_id → identifier dict.
        Raises on DB connection failure (no silent fallback).
    """
    conn = _get_check_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

            # Step 1: find services needed by check rules
            check_services = _load_check_services(cur, csp)
            if not check_services:
                logger.warning("No check-rule services found for csp=%s", csp)
                return {}

            # Step 2: load rule_discoveries rows for those services.
            # uid_template and uid_source columns override the op-level values in
            # discoveries_data when set — allows SQL fixes without editing JSONB.
            cur.execute(
                """
                SELECT service, boto3_client_name, discoveries_data,
                       COALESCE(max_discovery_workers, 0) AS max_workers,
                       uid_template  AS row_uid_template,
                       uid_source    AS row_uid_source
                FROM   rule_discoveries
                WHERE  provider   = %s
                  AND  is_active  = TRUE
                  AND  service    = ANY(%s)
                ORDER  BY service
                """,
                (csp, list(check_services)),
            )
            rows = cur.fetchall()

        identifiers: Dict[str, Any] = {}

        for row in rows:
            service = row["service"]
            boto3_client = row["boto3_client_name"] or service
            data = row["discoveries_data"] or {}

            ops: List[Dict[str, Any]] = data.get("discovery", [])
            if not ops:
                logger.debug("No discovery ops for service=%s csp=%s", service, csp)
                continue

            # Separate root ops (no for_each) from enrich ops (has for_each)
            root_ops = [op for op in ops if not op.get("for_each")]
            enrich_ops = [op for op in ops if op.get("for_each")]

            # Group enrich ops by their parent discovery_id
            enrich_by_parent: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for op in enrich_ops:
                enrich_by_parent[op["for_each"]].append(op)

            # Row-level column overrides op-level JSONB value when set — allows SQL
            # uid_template fixes without editing the discoveries_data JSONB blob.
            row_uid_template_col = row.get("row_uid_template")
            row_uid_source_col   = row.get("row_uid_source")

            for root_op in root_ops:
                did = root_op.get("discovery_id")
                if not did:
                    continue
                if did in _SKIP_DISCOVERY_IDS:
                    logger.debug("Skipping metadata-only discovery_id=%s", did)
                    continue

                uid_template = row_uid_template_col or root_op.get("uid_template")
                uid_source = (
                    row_uid_source_col
                    or root_op.get("uid_source")
                    or ("template" if uid_template else "heuristic")
                )

                emit = root_op.get("emit") or {}
                emit_fields = list((emit.get("item") or {}).keys())
                items_for = bool(emit.get("items_for"))

                action = ""
                calls = root_op.get("calls") or []
                if calls:
                    action = calls[0].get("action", "")

                resource_type = _derive_resource_type(service, action)

                identifiers[did] = {
                    "service":       service,
                    "csp":           csp,
                    "boto3_client":  boto3_client,
                    "discovery_id":  did,
                    "uid_template":  uid_template,
                    "uid_source":    uid_source,
                    "root_op":       root_op,
                    "enrich_ops":    enrich_by_parent.get(did, []),
                    "items_for":     items_for,
                    "emit_fields":   emit_fields,
                    "resource_type": resource_type,
                    "max_workers":   int(row.get("max_workers") or 0),
                }

        logger.info(
            "Loaded %d root-op identifiers for csp=%s (from %d services)",
            len(identifiers), csp, len(rows),
        )
        return identifiers

    finally:
        conn.close()


def load_identifiers_by_service(csp: str) -> Dict[str, List[Dict[str, Any]]]:
    """Return identifiers grouped by service — used by Phase 1 enricher planning.

    Only returns identifiers that have at least one enrich_op.
    """
    all_identifiers = load_identifiers(csp)

    by_service: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for identifier in all_identifiers.values():
        if identifier["enrich_ops"]:
            by_service[identifier["service"]].append(identifier)

    logger.info(
        "Enrichment identifiers: %d services for csp=%s",
        len(by_service), csp,
    )
    return dict(by_service)
