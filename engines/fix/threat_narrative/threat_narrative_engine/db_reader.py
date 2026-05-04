"""
Database reader for the Threat Narrative Engine.

Reads all context data needed for LLM narrative generation from:
  - threat_detections / threat_analysis (threat DB)
  - risk_scenarios (risk DB)
  - datasec_findings (datasec DB)
  - ciem_findings (ciem DB)
  - check_findings + rule_control_mapping + compliance_frameworks (check DB)
  - discovery_findings (discoveries DB)

All queries are parameterized — no f-string SQL.
JSONB columns are auto-deserialized by psycopg2; never call json.loads() on them.
All missing fields default to safe fallback values — callers receive a fully-populated dict.
"""

import logging
import os
from typing import Any

import psycopg2
import psycopg2.extras

from threat_narrative_engine.prompt_templates import (
    build_attack_chain_description,
    build_estimated_impact_display,
    build_identity_description,
)

logger = logging.getLogger("threat_narrative")


# ── Connection factories ───────────────────────────────────────────────────────

def _resolve_password(prefix: str) -> str:
    """Resolve DB password with three-level fallback.

    Args:
        prefix: DB env var prefix (e.g. "THREAT", "RISK").

    Returns:
        Password string, may be empty if not configured.
    """
    p = prefix.upper()
    return (
        os.getenv(f"{p}_DB_PASSWORD")
        or os.getenv("DB_PASSWORD")
        or os.getenv("DISCOVERIES_DB_PASSWORD", "")
    )


def _make_conn(prefix: str, default_db: str) -> psycopg2.extensions.connection:
    """Create a psycopg2 connection using engine-specific env vars.

    Args:
        prefix: DB env var prefix (e.g. "THREAT", "RISK").
        default_db: Default database name if env var not set.

    Returns:
        An open psycopg2 connection.

    Raises:
        psycopg2.OperationalError: If connection fails.
    """
    p = prefix.upper()
    return psycopg2.connect(
        host=os.getenv(f"{p}_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv(f"{p}_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv(f"{p}_DB_NAME", default_db),
        user=os.getenv(f"{p}_DB_USER", os.getenv("DB_USER", "postgres")),
        password=_resolve_password(p),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


# ── Detection ID listing ───────────────────────────────────────────────────────

def list_detection_ids(scan_run_id: str) -> list[str]:
    """Return all detection_id values for a given scan_run_id.

    Args:
        scan_run_id: The pipeline scan run UUID.

    Returns:
        List of detection_id strings. Empty list if none found.

    Raises:
        psycopg2.OperationalError: If threat DB is unreachable.
    """
    conn = _make_conn("THREAT", "threat_engine_threat")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT detection_id::text
                FROM threat_detections
                WHERE scan_id = %s OR scan_run_id = %s
                """,
                (scan_run_id, scan_run_id),
            )
            rows = cur.fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


# ── Main context reader ────────────────────────────────────────────────────────

def read_detection_context(scan_run_id: str, detection_id: str) -> dict[str, Any]:
    """Read all data needed for narrative generation for one detection.

    Queries (in order):
      1. threat_detections: scenario type, attack_chain, mitre_techniques[],
         risk_score, resource_uid, resource_type, account_id, region, threat_category
      2. threat_analysis: blast_radius (JSONB), estimated_impact (if present)
      3. risk_scenarios: blast_radius_score, affected_resources[] (join on
         scan_run_id + resource_uid)
      4. datasec_findings: data_classification (join on resource_uid + scan_run_id)
      5. ciem_findings: identity_type, privilege_level, principal_name (join on
         scan_run_id + resource_uid)
      6. check_findings + rule_control_mapping + compliance_frameworks:
         framework names + control IDs where check_findings.resource_uid =
         detection.resource_uid and check_findings.scan_run_id = scan_run_id
      7. discovery_findings: resource_name, resource_tags (for owner + env labels)

    Args:
        scan_run_id: The pipeline scan run UUID.
        detection_id: The specific threat detection UUID.

    Returns:
        Dict with all fields needed by prompt_templates. Any missing field
        defaults to a safe fallback value (empty string, 0, empty list).
        Never returns None for a field that a template will format().
    """
    ctx: dict[str, Any] = {
        # Detection fields
        "detection_id": detection_id,
        "scan_run_id": scan_run_id,
        "scenario_type": "",
        "attack_chain": None,
        "attack_chain_description": "multi-stage attack path",
        "entry_technique_description": "initial access",
        "mitre_techniques": [],
        "risk_score": 0,
        "resource_uid": "",
        "resource_type": "",
        "account_id": "",
        "region": "",
        "threat_category": "",
        # Analysis / risk fields
        "blast_radius_score": 0,
        "affected_resource_count": 0,
        "estimated_impact": None,
        "estimated_impact_display": "unknown financial impact",
        "estimated_record_count": "an unknown number of",
        # DataSec fields
        "data_classification": "unknown classification",
        # CIEM fields
        "ciem_row": None,
        "identity_description": "no identity signal contributing",
        # Compliance fields
        "framework_list": "none identified",
        # Discovery fields
        "resource_name": "",
        "resource_tags": {},
    }

    # ── 1. threat_detections ──────────────────────────────────────────────────
    try:
        conn = _make_conn("THREAT", "threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        detection_id,
                        detection_type    AS scenario_type,
                        threat_category,
                        attack_chain,
                        mitre_techniques,
                        risk_score,
                        resource_uid,
                        resource_type,
                        account_id,
                        region
                    FROM threat_detections
                    WHERE detection_id = %s::uuid
                    """,
                    (detection_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()

        if row:
            ctx["scenario_type"] = row.get("scenario_type") or ""
            ctx["threat_category"] = row.get("threat_category") or ""
            # JSONB — auto-deserialized by psycopg2, never call json.loads()
            ctx["attack_chain"] = row.get("attack_chain")
            ctx["mitre_techniques"] = row.get("mitre_techniques") or []
            ctx["risk_score"] = row.get("risk_score") or 0
            ctx["resource_uid"] = row.get("resource_uid") or ""
            ctx["resource_type"] = row.get("resource_type") or ""
            ctx["account_id"] = row.get("account_id") or ""
            ctx["region"] = row.get("region") or ""

            ctx["attack_chain_description"] = build_attack_chain_description(
                ctx["attack_chain"]
            )

            # Entry technique from first MITRE technique
            techniques = ctx["mitre_techniques"]
            if isinstance(techniques, list) and techniques:
                first = techniques[0]
                if isinstance(first, dict):
                    ctx["entry_technique_description"] = (
                        first.get("description") or first.get("name") or first.get("id") or "initial access"
                    )
                elif isinstance(first, str):
                    ctx["entry_technique_description"] = first
        else:
            logger.warning(
                "threat_detections row not found",
                extra={"detection_id": detection_id},
            )
    except psycopg2.OperationalError as exc:
        logger.error(
            "Failed to connect to threat DB for detection context",
            extra={"detection_id": detection_id, "error": str(exc)},
        )
        raise  # DB connectivity failure should propagate

    # ── 2. threat_analysis ───────────────────────────────────────────────────
    try:
        conn = _make_conn("THREAT", "threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT blast_radius, estimated_impact
                    FROM threat_analysis
                    WHERE detection_id = %s::uuid
                    LIMIT 1
                    """,
                    (detection_id,),
                )
                row = cur.fetchone()
        finally:
            conn.close()

        if row:
            blast = row.get("blast_radius") or {}
            if isinstance(blast, dict):
                ctx["affected_resource_count"] = (
                    blast.get("affected_count")
                    or blast.get("resource_count")
                    or len(blast.get("affected_resources", []))
                    or 0
                )
            ctx["estimated_impact"] = row.get("estimated_impact")
            ctx["estimated_impact_display"] = build_estimated_impact_display(
                ctx["estimated_impact"]
            )
    except psycopg2.OperationalError as exc:
        logger.warning(
            "Could not read threat_analysis — using defaults",
            extra={"detection_id": detection_id, "error": str(exc)},
        )
    except Exception as exc:
        logger.warning(
            "Unexpected error reading threat_analysis",
            extra={"detection_id": detection_id, "error": str(exc)},
        )

    # ── 3. risk_scenarios ────────────────────────────────────────────────────
    resource_uid = ctx["resource_uid"]
    if resource_uid:
        try:
            conn = _make_conn("RISK", "threat_engine_risk")
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT blast_radius_score, affected_resources
                        FROM risk_scenarios
                        WHERE scan_run_id = %s
                          AND resource_uid = %s
                        ORDER BY blast_radius_score DESC
                        LIMIT 1
                        """,
                        (scan_run_id, resource_uid),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()

            if row:
                ctx["blast_radius_score"] = row.get("blast_radius_score") or 0
                affected = row.get("affected_resources") or []
                if isinstance(affected, list):
                    ctx["affected_resource_count"] = max(
                        ctx["affected_resource_count"], len(affected)
                    )
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read risk_scenarios — using defaults",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading risk_scenarios",
                extra={"detection_id": detection_id, "error": str(exc)},
            )

    # ── 4. datasec_findings ──────────────────────────────────────────────────
    if resource_uid:
        try:
            conn = _make_conn("DATASEC", "threat_engine_datasec")
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT data_classification
                        FROM datasec_findings
                        WHERE scan_run_id = %s
                          AND resource_uid = %s
                        LIMIT 1
                        """,
                        (scan_run_id, resource_uid),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()

            if row and row.get("data_classification"):
                ctx["data_classification"] = row["data_classification"]
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read datasec_findings — using defaults",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading datasec_findings",
                extra={"detection_id": detection_id, "error": str(exc)},
            )

    # ── 5. ciem_findings ─────────────────────────────────────────────────────
    if resource_uid:
        try:
            conn = _make_conn("CIEM", "threat_engine_ciem")
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT identity_type, privilege_level, principal_name
                        FROM ciem_findings
                        WHERE scan_run_id = %s
                          AND resource_uid = %s
                        LIMIT 1
                        """,
                        (scan_run_id, resource_uid),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()

            if row:
                ctx["ciem_row"] = dict(row)
                ctx["identity_description"] = build_identity_description(dict(row))
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read ciem_findings — using defaults",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading ciem_findings",
                extra={"detection_id": detection_id, "error": str(exc)},
            )

    # ── 6. check_findings + rule_control_mapping + compliance_frameworks ──────
    # NOTE: rule_discoveries table is in check DB (not discoveries DB).
    #       Column is 'service' (not 'service_name'). See CLAUDE.md.
    if resource_uid:
        try:
            conn = _make_conn("CHECK", "threat_engine_check")
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT cf.name AS framework_name
                        FROM check_findings chf
                        JOIN rule_control_mapping rcm ON chf.rule_id = rcm.rule_id
                        JOIN compliance_frameworks cf ON rcm.framework_id = cf.framework_id
                        WHERE chf.scan_run_id = %s
                          AND chf.resource_uid = %s
                          AND chf.status = 'FAIL'
                        LIMIT 10
                        """,
                        (scan_run_id, resource_uid),
                    )
                    rows = cur.fetchall()
            finally:
                conn.close()

            if rows:
                framework_names = [r[0] for r in rows if r[0]]
                if framework_names:
                    ctx["framework_list"] = ", ".join(sorted(set(framework_names)))
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read compliance frameworks — using defaults",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading compliance frameworks",
                extra={"detection_id": detection_id, "error": str(exc)},
            )

    # ── 7. discovery_findings ────────────────────────────────────────────────
    if resource_uid:
        try:
            conn = _make_conn("DISCOVERIES", "threat_engine_discoveries")
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """
                        SELECT resource_name, resource_tags
                        FROM discovery_findings
                        WHERE scan_run_id = %s
                          AND resource_uid = %s
                        LIMIT 1
                        """,
                        (scan_run_id, resource_uid),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()

            if row:
                ctx["resource_name"] = row.get("resource_name") or resource_uid
                ctx["resource_tags"] = row.get("resource_tags") or {}
        except psycopg2.OperationalError as exc:
            logger.warning(
                "Could not read discovery_findings — using resource_uid as name",
                extra={"detection_id": detection_id, "error": str(exc)},
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error reading discovery_findings",
                extra={"detection_id": detection_id, "error": str(exc)},
            )

    # Fallback: use resource_uid if resource_name was not resolved
    if not ctx["resource_name"]:
        ctx["resource_name"] = resource_uid or "cloud resource"

    return ctx
