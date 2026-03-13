"""
Threat Intelligence & Threat Hunting DB writer.

Writes to:
  - threat_intelligence  (IOC/TTP feed data)
  - threat_hunt_queries  (saved Cypher hunt queries)
  - threat_hunt_results  (hunt execution results)
"""

from __future__ import annotations

import hashlib
import json
import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _default_json(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _connection_string() -> str:
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "threat_user")
    pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def _ensure_tenant(conn, tenant_id: str):
    """Upsert tenant row in the local threat DB tenants table.

    The threat DB has FK constraints from threat_intelligence (and other tables)
    referencing tenants(tenant_id). This must be called before writing any
    tenant-scoped data to avoid FK violations.
    """
    import psycopg2
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (tenant_id, tenant_name)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
                """,
                (tenant_id, tenant_id),
            )
        conn.commit()
    except Exception as e:
        logger.warning("Failed to upsert tenant %s: %s", tenant_id, e)
        try:
            conn.rollback()
        except Exception:
            pass


def _ts_now():
    return datetime.now(timezone.utc)


# ── Threat Intelligence ──────────────────────────────────────────────────────

def save_intel(intel: Dict[str, Any]) -> str:
    """
    Save a threat intelligence entry.

    Required keys: tenant_id, source, intel_type, severity, confidence, threat_data
    Optional: category, indicators, ttps, tags, expires_at
    """
    import psycopg2
    from psycopg2.extras import Json

    conn = psycopg2.connect(_connection_string())
    try:
        _ensure_tenant(conn, intel["tenant_id"])

        # Hash for dedup
        raw = json.dumps(intel.get("threat_data", {}), sort_keys=True, default=_default_json)
        value_hash = hashlib.sha256(raw.encode()).hexdigest()[:64]

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_intelligence (
                    tenant_id, source, intel_type, category,
                    severity, confidence, value_hash,
                    threat_data, indicators, ttps, tags,
                    first_seen_at, last_seen_at, expires_at, is_active
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                ON CONFLICT (intel_id) DO UPDATE SET
                    last_seen_at = EXCLUDED.last_seen_at,
                    threat_data = EXCLUDED.threat_data,
                    indicators = EXCLUDED.indicators,
                    is_active = EXCLUDED.is_active
                RETURNING intel_id
            """, (
                intel["tenant_id"],
                intel["source"],
                intel["intel_type"],
                intel.get("category"),
                intel["severity"],
                intel["confidence"],
                value_hash,
                Json(intel.get("threat_data", {}), dumps=lambda o: json.dumps(o, default=_default_json)),
                Json(intel.get("indicators", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                Json(intel.get("ttps", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                Json(intel.get("tags", []), dumps=lambda o: json.dumps(o, default=_default_json)),
                _ts_now(),
                _ts_now(),
                intel.get("expires_at"),
                intel.get("is_active", True),
            ))
            intel_id = str(cur.fetchone()[0])

        conn.commit()
        return intel_id
    finally:
        conn.close()


def save_intel_batch(items: List[Dict[str, Any]]) -> int:
    """Save multiple intel entries. Returns count saved."""
    count = 0
    for item in items:
        try:
            save_intel(item)
            count += 1
        except Exception as e:
            logger.warning(f"Failed to save intel: {e}")
    return count


def get_intel(
    tenant_id: str,
    intel_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    active_only: bool = True,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Query threat intelligence entries."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(_connection_string())
    try:
        where = ["tenant_id = %s"]
        params: List[Any] = [tenant_id]

        if intel_type:
            where.append("intel_type = %s")
            params.append(intel_type)
        if severity:
            where.append("severity = %s")
            params.append(severity)
        if source:
            where.append("source = %s")
            params.append(source)
        if active_only:
            where.append("is_active = true")

        params.append(limit)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT * FROM threat_intelligence
                WHERE {' AND '.join(where)}
                ORDER BY last_seen_at DESC
                LIMIT %s
            """, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def correlate_intel_with_threats(
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """
    Correlate threat intelligence with existing threat_detections.

    Matches on:
      - mitre_techniques overlap
      - resource_arn patterns in indicators
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(_connection_string())
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Match by MITRE technique overlap
            cur.execute("""
                SELECT
                    d.detection_id,
                    d.resource_arn,
                    d.severity AS detection_severity,
                    d.mitre_techniques AS detection_techniques,
                    i.intel_id,
                    i.source AS intel_source,
                    i.intel_type,
                    i.severity AS intel_severity,
                    i.ttps AS intel_ttps,
                    i.threat_data
                FROM threat_detections d
                CROSS JOIN threat_intelligence i
                WHERE d.tenant_id = %s
                  AND i.tenant_id = %s
                  AND i.is_active = true
                  AND d.mitre_techniques ?| (
                      SELECT array_agg(elem::text)
                      FROM jsonb_array_elements_text(i.ttps) elem
                  )
                LIMIT 500
            """, (tenant_id, tenant_id))
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# ── Threat Hunt Queries ──────────────────────────────────────────────────────

def save_hunt_query(query: Dict[str, Any]) -> str:
    """Save a threat hunt query. Returns hunt_id."""
    import psycopg2
    from psycopg2.extras import Json

    conn = psycopg2.connect(_connection_string())
    try:
        _ensure_tenant(conn, query["tenant_id"])

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_hunt_queries (
                    tenant_id, query_name, description,
                    hunt_type, query_language, query_text,
                    target_data_sources, mitre_tactics, mitre_techniques,
                    tags, schedule_cron, is_active, created_by
                )
                VALUES (
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
                RETURNING hunt_id
            """, (
                query["tenant_id"],
                query["query_name"],
                query.get("description", ""),
                query.get("hunt_type", "graph"),
                query.get("query_language", "cypher"),
                query["query_text"],
                Json(query.get("target_data_sources", ["neo4j"])),
                Json(query.get("mitre_tactics", [])),
                Json(query.get("mitre_techniques", [])),
                Json(query.get("tags", [])),
                query.get("schedule_cron"),
                query.get("is_active", True),
                query.get("created_by", "system"),
            ))
            hunt_id = str(cur.fetchone()[0])

        conn.commit()
        return hunt_id
    finally:
        conn.close()


def get_hunt_queries(
    tenant_id: str,
    active_only: bool = True,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List saved hunt queries."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(_connection_string())
    try:
        where = ["tenant_id = %s"]
        params: List[Any] = [tenant_id]
        if active_only:
            where.append("is_active = true")
        params.append(limit)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT * FROM threat_hunt_queries
                WHERE {' AND '.join(where)}
                ORDER BY created_at DESC
                LIMIT %s
            """, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_hunt_query(hunt_id: str) -> Optional[Dict[str, Any]]:
    """Get a single hunt query by ID."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(_connection_string())
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM threat_hunt_queries WHERE hunt_id = %s::uuid", (hunt_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


# ── Threat Hunt Results ──────────────────────────────────────────────────────

def save_hunt_result(result: Dict[str, Any]) -> str:
    """Save a hunt execution result. Returns result_id."""
    import psycopg2
    from psycopg2.extras import Json

    conn = psycopg2.connect(_connection_string())
    try:
        _ensure_tenant(conn, result["tenant_id"])

        with conn.cursor() as cur:
            # Save result
            cur.execute("""
                INSERT INTO threat_hunt_results (
                    hunt_id, tenant_id,
                    execution_timestamp, total_results, new_detections,
                    execution_time_ms, results_data, status, error_message
                )
                VALUES (
                    %s::uuid, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
                RETURNING result_id
            """, (
                result["hunt_id"],
                result["tenant_id"],
                _ts_now(),
                result.get("total_results", 0),
                result.get("new_detections", 0),
                result.get("execution_time_ms"),
                Json(result.get("results_data", {}), dumps=lambda o: json.dumps(o, default=_default_json)),
                result.get("status", "completed"),
                result.get("error_message"),
            ))
            result_id = str(cur.fetchone()[0])

            # Update hunt query stats
            cur.execute("""
                UPDATE threat_hunt_queries
                SET last_executed_at = %s,
                    execution_count = execution_count + 1,
                    hit_count = hit_count + %s
                WHERE hunt_id = %s::uuid
            """, (_ts_now(), result.get("total_results", 0), result["hunt_id"]))

        conn.commit()
        return result_id
    finally:
        conn.close()


def get_hunt_results(
    tenant_id: str,
    hunt_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get hunt execution results."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(_connection_string())
    try:
        where = ["r.tenant_id = %s"]
        params: List[Any] = [tenant_id]

        if hunt_id:
            where.append("r.hunt_id = %s::uuid")
            params.append(hunt_id)

        params.append(limit)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT r.*, q.query_name, q.hunt_type, q.query_language
                FROM threat_hunt_results r
                LEFT JOIN threat_hunt_queries q ON r.hunt_id = q.hunt_id
                WHERE {' AND '.join(where)}
                ORDER BY r.execution_timestamp DESC
                LIMIT %s
            """, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
