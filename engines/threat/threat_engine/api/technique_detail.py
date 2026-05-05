"""TechniqueDetailModal endpoint (JNY-01 — REDESIGNED, junction table).

DB-backed replacement for the previously static MITRE technique map. Reads
technique metadata from the ``mitre_technique_reference`` global catalog and
combines per-tenant finding counts via the ``threat_finding_techniques``
junction table (migration ``threat_finding_techniques_001a``).

Rationale for junction table over the prior generated-column design:
    Production schema stores MITRE techniques as a JSONB array
    (``threat_findings.mitre_techniques``), not as a singular VARCHAR. Postgres
    15 cannot back a generated STORED column with a SET-RETURNING expression,
    so the M:N relationship is materialized in ``threat_finding_techniques``
    and kept in sync by an AFTER trigger. See migration file for full design
    notes.

Schema reality (MV-1 verified 2026-05-04):
    The live table uses legacy column names:
      - ``technique_name``  (aliased to ``name`` in the response for UI compat)
      - ``tactics``         (aliased to ``tactic_ids`` for UI compat)
    Plus 9 columns added by ``threat_mitre_technique_ref_001.sql``:
      parent_id, is_subtechnique, kill_chain_phases, mitigations,
      d3fend_mappings, revoked, deprecated, version, last_modified.

Routes:
    GET /api/v1/techniques/{technique_id}

Query params:
    tenant_id (UUID, optional): when supplied, returned counts are scoped to
        that tenant. When absent, counts are zero (no cross-tenant data leak).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

import psycopg2
from fastapi import APIRouter, Depends, HTTPException
from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_threat_conn

# Auth — must be present in production. Falls back to a 401-raising stub
# only when the auth package is genuinely unavailable (dev/test images).
try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AUTH_AVAILABLE = False

    def require_permission(_perm: str):  # type: ignore[no-redef]
        def _denied():
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["mitre"])


_TECHNIQUE_ID_RE = r"^T[0-9]{4}(\.[0-9]{3,4})?$"


# -----------------------------------------------------------------------------
# Combined query: reference row + exact + parent-rollup counts in one round-trip
# -----------------------------------------------------------------------------
_LOOKUP_SQL = """
WITH ref AS (
    SELECT
        technique_id,
        parent_id,
        technique_name           AS name,
        description,
        is_subtechnique,
        tactics                  AS tactic_ids,
        kill_chain_phases,
        platforms,
        sub_techniques,
        detection_keywords,
        detection_guidance,
        mitigations,
        remediation_guidance,
        d3fend_mappings,
        url,
        version,
        revoked,
        deprecated,
        severity_base,
        last_modified
    FROM mitre_technique_reference
    WHERE technique_id = %(technique_id)s
),
exact_count AS (
    -- Open findings whose technique set contains exactly this technique_id.
    -- Junction table makes this a pure btree lookup on
    -- (tenant_id, technique_id); no JSONB scan.
    SELECT COUNT(DISTINCT tf.finding_id)::bigint AS c
    FROM threat_finding_techniques tft
    JOIN threat_findings tf ON tf.finding_id = tft.finding_id
    WHERE tf.status = 'OPEN'
      AND tft.technique_id = %(technique_id)s
      AND (%(tenant_id)s IS NULL OR tft.tenant_id = %(tenant_id)s)
),
rollup_count AS (
    -- Open findings rolled up to the parent technique (parent + all subs).
    -- For a parent id (T1078) this counts T1078 + every T1078.* sub.
    -- For a sub id  (T1078.004) it counts the same parent group, by design.
    SELECT COUNT(DISTINCT tf.finding_id)::bigint AS c
    FROM threat_finding_techniques tft
    JOIN threat_findings tf ON tf.finding_id = tft.finding_id
    WHERE tf.status = 'OPEN'
      AND tft.parent_technique_id = %(parent_or_self)s
      AND (%(tenant_id)s IS NULL OR tft.tenant_id = %(tenant_id)s)
)
SELECT
    ref.*,
    (SELECT c FROM exact_count)  AS affected_count,
    (SELECT c FROM rollup_count) AS affected_count_with_subs
FROM ref;
"""


def _resolve_parent_or_self(technique_id: str) -> str:
    """Return the parent of a sub-technique, else the id itself.

    ``T1078.004`` -> ``T1078``; ``T1078`` -> ``T1078``.
    """
    return technique_id.split(".", 1)[0]


@router.get("/techniques/{technique_id}")
def get_technique_detail(
    technique_id: str,
    auth: Any = Depends(require_permission("threat:read")),
) -> Dict[str, Any]:
    """Return MITRE technique metadata + tenant-scoped finding counts.

    Tenant scoping is derived from the AuthContext (gateway-injected
    ``X-Auth-Context``); never from a query string. This closes the
    cross-tenant aggregate-count read flagged in CP-A security review (R-1/R-2).

    Args:
        technique_id: MITRE technique id (e.g. ``T1078`` or ``T1078.004``).
        auth: AuthContext injected by ``require_permission("threat:read")``.

    Returns:
        Dict with technique metadata (legacy columns aliased: ``technique_name``
        -> ``name``, ``tactics`` -> ``tactic_ids``) and two counts:
          - ``affected_count``: open findings matching exactly this id.
          - ``affected_count_with_subs``: open findings rolled up to the parent
            technique (equals ``affected_count`` for parent ids; for a sub-id
            it counts the parent + all sibling subs).

    Raises:
        HTTPException 400: if the technique_id format is invalid.
        HTTPException 404: if the technique is not in the reference catalog.
        HTTPException 410: if the technique is revoked or deprecated (historical
            findings remain queryable; UI should mark deprecation).
        HTTPException 503: if the threat database is unavailable.
    """
    if not re.match(_TECHNIQUE_ID_RE, technique_id):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid technique_id format: {technique_id!r}",
        )

    # Tenant scope from AuthContext (gateway-injected). Never trust a query param.
    tenant_id: Optional[str] = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
    )

    parent_or_self = _resolve_parent_or_self(technique_id)
    params = {
        "technique_id": technique_id,
        "parent_or_self": parent_or_self,
        "tenant_id": tenant_id,
    }

    try:
        conn = get_threat_conn()
    except psycopg2.OperationalError as exc:
        logger.error("threat DB unavailable for technique lookup: %s", exc)
        raise HTTPException(status_code=503, detail="threat database unavailable")

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(_LOOKUP_SQL, params)
            row = cur.fetchone()
    except psycopg2.DatabaseError as exc:
        logger.error("DB error in technique lookup: %s", exc)
        raise HTTPException(status_code=500, detail="internal database error")
    finally:
        conn.close()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Technique not found in reference catalog: {technique_id}",
        )

    # 410 Gone for revoked/deprecated — historical findings remain findable but
    # the UI should render a deprecation banner instead of the live detail view.
    # Per security-architect handoff: do not silently succeed on stale techniques.
    if row.get("revoked") or row.get("deprecated"):
        flag = "revoked" if row.get("revoked") else "deprecated"
        logger.info(
            "technique lookup returned %s technique: %s", flag, technique_id
        )
        raise HTTPException(
            status_code=410,
            detail={
                "code": "technique_gone",
                "flag": flag,
                "technique_id": technique_id,
                "parent_id": row.get("parent_id"),
                "version": row.get("version"),
                "last_modified": (
                    row["last_modified"].isoformat()
                    if row.get("last_modified") is not None
                    else None
                ),
                "message": (
                    f"MITRE technique {technique_id} is marked {flag}. "
                    "Historical findings remain queryable via /findings."
                ),
            },
        )

    # RealDictCursor preserves JSONB as already-decoded Python objects (psycopg2
    # auto-deserializes JSONB) — return as-is.
    return dict(row)
