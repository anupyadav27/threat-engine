"""
CDRLoader — reads cdr_findings and writes CDREvent + CDRActor nodes to Neo4j.

Security constraints:
- CP1-02: actor_principal is PII. NEVER store raw actor_principal in Neo4j or logs.
  Only actor_hash = sha256(actor_principal) is stored. The raw value stays in cdr DB.
- CDR findings are tenant-wide (no account_id filter) per W-04 design decision,
  because CDR actor activity crosses accounts.
- CP1-01: all Cypher values via $parameter bindings.
"""
from __future__ import annotations

import os

import hashlib
import logging
from typing import Any, Dict, List

from neo4j import Driver

logger = logging.getLogger(__name__)

_MERGE_CDR_EVENT = """
MERGE (e:CDREvent {finding_id: $finding_id, tenant_id: $tid})
SET e.mitre_techniques = $mitre_techniques,
    e.mitre_tactics    = $mitre_tactics,
    e.event_time       = $event_time,
    e.anomaly_score    = $anomaly_score,
    e.actor_hash       = $actor_hash
WITH e
MERGE (r:Resource {resource_uid: $resource_uid, tenant_id: $tid})
ON CREATE SET r.resource_type = $resource_type,
              r.account_id    = $account_id,
              r.cdr_actor_seen = true
ON MATCH SET  r.cdr_actor_seen = true
MERGE (r)-[:TRIGGERED_ON]->(e)
"""

_MERGE_CDR_ACTOR = """
MERGE (a:CDRActor {actor_hash: $actor_hash, tenant_id: $tid})
SET a.last_seen        = $last_seen,
    a.on_attack_path   = COALESCE(a.on_attack_path, false)
WITH a
MATCH (e:CDREvent {finding_id: $finding_id, tenant_id: $tid})
MERGE (a)-[:PERFORMED]->(e)
"""


def _hash_principal(actor_principal: str) -> str:
    """One-way hash of actor_principal (PII). CP1-02 enforcement."""
    return hashlib.sha256(actor_principal.encode()).hexdigest()


class CDRLoader:
    """Loads CDR behavioral events into the Neo4j threat graph."""

    def __init__(self, cdr_conn: Any, neo4j_driver: Driver) -> None:
        self._cdr_conn = cdr_conn
        self._driver = neo4j_driver

    def load(
        self,
        tenant_id: str,
        scan_run_id: str,
    ) -> Dict[str, int]:
        """Load CDR findings for the tenant into Neo4j.

        Note: No account_id filter — CDR is tenant-wide per W-04.

        Returns:
            Dict with event_count and actor_count.
        """
        rows = self._fetch_cdr(tenant_id, scan_run_id)
        if not rows:
            logger.info(
                "No CDR findings for scan %s / tenant %s",
                scan_run_id, tenant_id,
            )
            return {"event_count": 0, "actor_count": 0}

        actors_seen: set = set()
        event_count = 0

        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            for row in rows:
                # Hash PII before touching Neo4j — raw value never leaves this scope
                raw_principal = row.get("actor_principal") or ""
                actor_hash = _hash_principal(raw_principal) if raw_principal else ""
                finding_id = str(row["finding_id"])
                resource_uid = row.get("resource_uid", "")
                event_time = row.get("event_time")
                event_time_iso = event_time.isoformat() if event_time else ""

                # mitre_techniques/tactics are JSONB arrays in cdr_findings
                techniques = row.get("mitre_techniques") or []
                tactics = row.get("mitre_tactics") or []
                techniques_list = list(techniques) if isinstance(techniques, list) else ([techniques] if techniques else [])
                tactics_list = list(tactics) if isinstance(tactics, list) else ([tactics] if tactics else [])

                session.run(
                    _MERGE_CDR_EVENT,
                    finding_id=finding_id,
                    tid=tenant_id,
                    mitre_techniques=techniques_list,
                    mitre_tactics=tactics_list,
                    event_time=event_time_iso,
                    anomaly_score=float(row.get("anomaly_score") or 0.0),
                    actor_hash=actor_hash,
                    resource_uid=resource_uid,
                    resource_type=row.get("resource_type") or "iam_actor",
                    account_id=row.get("account_id") or "",
                )
                event_count += 1

                if actor_hash:
                    session.run(
                        _MERGE_CDR_ACTOR,
                        actor_hash=actor_hash,
                        tid=tenant_id,
                        last_seen=event_time_iso,
                        finding_id=finding_id,
                    )
                    actors_seen.add(actor_hash)

        logger.info(
            "CDRLoader complete: %d events, %d actors",
            event_count,
            len(actors_seen),
            extra={"tenant_id": tenant_id, "scan_run_id": scan_run_id},
        )
        return {"event_count": event_count, "actor_count": len(actors_seen)}

    def _fetch_cdr(
        self,
        tenant_id: str,
        scan_run_id: str,
    ) -> List[Dict[str, Any]]:
        """Query cdr_findings for tenant. No account_id filter (W-04)."""
        cur = self._cdr_conn.cursor()
        cur.execute(
            """
            SELECT
                finding_id,
                resource_uid,
                resource_type,
                account_id,
                actor_principal,
                mitre_techniques,
                mitre_tactics,
                event_time,
                NULL AS anomaly_score,
                scan_run_id
            FROM cdr_findings
            WHERE tenant_id   = %s
              AND scan_run_id = %s
            """,
            (tenant_id, scan_run_id),
        )
        rows = cur.fetchall()
        cur.close()
        return list(rows)
