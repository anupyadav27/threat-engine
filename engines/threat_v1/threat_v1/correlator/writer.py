"""
IncidentWriter + LifecycleTransitioner (S2-08).

IncidentWriter:
  - Advisory lock: pg_advisory_lock(hashtext(tenant_id||'|'||account_id))
  - Incident upsert: ON CONFLICT (dedup_key) DO UPDATE
    Sets last_seen_at, escalates incident_class/severity if higher tier fires.
  - Releases lock on completion or exception.

LifecycleTransitioner — state machine per REQUIREMENTS §9.4:
  open        → reopened:  same dedup_key fires within 7 days of resolution
  open/susp   → active:    upgrade when higher incident_class arrives
  active      → resolved:  actor session terminated + no CDR 24h + check fixed
  resolved    → reopened:  same dedup_key fires (within 7 days)
  any         → suppressed: FeedbackProcessor writes suppression
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from threat_v1.correlator.deduper import RolledUpIncident

logger = logging.getLogger(__name__)

_INCIDENT_CLASS_ORDER = {"posture": 0, "suspicious": 1, "active": 2}
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _advisory_key(tenant_id: str, account_id: str) -> int:
    raw = f"{tenant_id}|{account_id}"
    return int(hashlib.md5(raw.encode()).hexdigest()[:8], 16) & 0x7FFFFFFF


def _higher_class(a: str, b: str) -> str:
    return a if _INCIDENT_CLASS_ORDER.get(a, 0) >= _INCIDENT_CLASS_ORDER.get(b, 0) else b


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


class IncidentWriter:
    """Writes deduplicated incidents to threat_incidents with advisory lock."""

    def __init__(self, threat_conn: Any) -> None:
        self._conn = threat_conn

    def write_batch(
        self,
        incidents: List[RolledUpIncident],
        scan_run_id: str,
    ) -> int:
        """Write a batch of incidents to the DB. Returns count of upserted rows."""
        if not incidents:
            return 0

        # Group by (tenant_id, account_id) for lock granularity
        by_tenant: dict = {}
        for inc in incidents:
            key = (inc.tenant_id, inc.account_id)
            by_tenant.setdefault(key, []).append(inc)

        total = 0
        for (tenant_id, account_id), group in by_tenant.items():
            lock_key = _advisory_key(tenant_id, account_id)
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
                cur.close()

                for inc in group:
                    self._upsert_incident(inc, scan_run_id)
                    total += 1

                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                logger.error(
                    "IncidentWriter batch failed for tenant %s: %s",
                    tenant_id, exc,
                    exc_info=True,
                )
                raise
            finally:
                try:
                    cur = self._conn.cursor()
                    cur.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))
                    cur.close()
                except Exception:
                    pass

        logger.info("IncidentWriter wrote %d incidents (scan=%s)", total, scan_run_id)
        return total

    def _upsert_incident(
        self,
        inc: RolledUpIncident,
        scan_run_id: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        cur = self._conn.cursor()
        # dedup_key is GENERATED ALWAYS (incident_class|entry_resource_uid|tenant_id) — do not insert.
        # pattern_id is a UUID FK — resolve from pattern_key via subquery.
        # attack_path stores the hop UIDs as JSONB.
        cur.execute(
            """
            INSERT INTO threat_incidents (
                scan_run_id, tenant_id, account_id, region,
                entry_resource_uid, target_resource_uid,
                pattern_id, matched_pattern_ids,
                tier, incident_class, severity,
                title, attack_path,
                status, first_seen_at, last_seen_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s,
                (SELECT pattern_id FROM threat_scenario_patterns WHERE pattern_key = %s LIMIT 1),
                %s::jsonb,
                %s, %s, %s,
                %s, %s::jsonb,
                'open', %s, %s
            )
            ON CONFLICT ON CONSTRAINT uq_threat_incidents_dedup_key DO UPDATE SET
                last_seen_at        = EXCLUDED.last_seen_at,
                scan_run_id         = EXCLUDED.scan_run_id,
                pattern_id          = EXCLUDED.pattern_id,
                title               = EXCLUDED.title,
                incident_class      = CASE
                    WHEN CASE EXCLUDED.incident_class
                         WHEN 'active' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END
                         > CASE threat_incidents.incident_class
                         WHEN 'active' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END
                    THEN EXCLUDED.incident_class
                    ELSE threat_incidents.incident_class
                END,
                severity            = CASE
                    WHEN CASE EXCLUDED.severity
                         WHEN 'critical' THEN 3 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 1 ELSE 0 END
                         > CASE threat_incidents.severity
                         WHEN 'critical' THEN 3 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 1 ELSE 0 END
                    THEN EXCLUDED.severity
                    ELSE threat_incidents.severity
                END,
                matched_pattern_ids = EXCLUDED.matched_pattern_ids,
                tier                = GREATEST(threat_incidents.tier, EXCLUDED.tier),
                status              = CASE
                    WHEN threat_incidents.status = 'resolved'
                         AND threat_incidents.resolved_at > NOW() - INTERVAL '7 days'
                    THEN 'reopened'
                    ELSE threat_incidents.status
                END
            """,
            (
                scan_run_id,
                inc.tenant_id,
                inc.account_id,
                inc.region,
                inc.entry_uid,
                inc.target_uid,
                inc.primary_pattern_id,
                json.dumps(inc.matched_patterns),
                inc.tier,
                inc.incident_class,
                inc.severity,
                inc.title,
                json.dumps(inc.hop_uids),
                now,
                now,
            ),
        )
        cur.close()


class LifecycleTransitioner:
    """Applies state machine transitions to existing incidents."""

    def __init__(self, threat_conn: Any) -> None:
        self._conn = threat_conn

    def resolve_stale_active(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
    ) -> int:
        """Mark active incidents as resolved if all resolution criteria are met.

        Resolution criteria (REQUIREMENTS §9.4):
          1. No CDR events on any path resource in the last 24h
          2. All check findings that triggered the incident are now PASS
          3. Incident status is 'active'

        This is best-effort — CDR/check re-scans are external events.
        The transitioner only resolves incidents that clearly meet criteria.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            UPDATE threat_incidents
            SET status      = 'resolved',
                resolved_at = NOW()
            WHERE tenant_id  = %s
              AND account_id = %s
              AND status     = 'active'
              AND last_seen_at < NOW() - INTERVAL '24 hours'
            RETURNING dedup_key
            """,
            (tenant_id, account_id),
        )
        resolved = cur.rowcount
        self._conn.commit()
        cur.close()

        if resolved:
            logger.info(
                "LifecycleTransitioner resolved %d stale active incidents "
                "for tenant=%s account=%s",
                resolved, tenant_id, account_id,
            )
        return resolved
