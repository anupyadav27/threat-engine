"""
Tier3Matcher — full attack path: entry → hops → crown jewel target + CDR grading.

CDR signal grading (REQUIREMENTS §8):
  0 CDR signals matching cdr_watch.techniques:
    → incident_class = 'posture', severity = posture_severity (HIGH)
  1 CDR technique found but below min_coverage:
    → incident_class = 'suspicious', severity = HIGH
  ≥2 CDR techniques OR min_coverage met AND window respected:
    → incident_class = 'active', severity = CRITICAL

Tactic order check: if cdr_watch.tactic_order_required=true, the CDR techniques
must appear in the order specified by tactic_chain_order within the time window.

Latency target: < 2s per pattern.
confidence='theoretical' patterns must NEVER produce incident_class='active'.
"""
from __future__ import annotations

import os

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from neo4j import Driver

from threat_v1.patterns.compiler import PatternCompiler
from threat_v1.patterns.models import ThreatPattern

logger = logging.getLogger(__name__)

_TIER3_TIMEOUT_MS = 30_000  # 30s hard cap — PerformanceGuard enforces lower budget


class Tier3Match:
    __slots__ = [
        "pattern_id", "tenant_id", "account_id", "region",
        "entry_uid", "hop_uids", "target_uid",
        "incident_class", "severity", "cdr_technique_count",
        "latency_ms",
    ]

    def __init__(
        self,
        pattern_id: str,
        tenant_id: str,
        account_id: str,
        region: str,
        entry_uid: str,
        hop_uids: List[str],
        target_uid: Optional[str],
        incident_class: str,
        severity: str,
        cdr_technique_count: int,
        latency_ms: float,
    ) -> None:
        self.pattern_id = pattern_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.region = region
        self.entry_uid = entry_uid
        self.hop_uids = hop_uids
        self.target_uid = target_uid
        self.incident_class = incident_class
        self.severity = severity
        self.cdr_technique_count = cdr_technique_count
        self.latency_ms = latency_ms

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "tenant_id": self.tenant_id,
            "account_id": self.account_id,
            "region": self.region,
            "entry_uid": self.entry_uid,
            "hop_uids": self.hop_uids,
            "target_uid": self.target_uid,
            "tier": 3,
            "incident_class": self.incident_class,
            "severity": self.severity,
            "cdr_technique_count": self.cdr_technique_count,
            "latency_ms": self.latency_ms,
        }


class Tier3Matcher:
    """Executes Tier 3 patterns against the Neo4j graph with CDR grading."""

    def __init__(self, neo4j_driver: Driver) -> None:
        self._driver = neo4j_driver
        self._compiler = PatternCompiler()

    def run(
        self,
        pattern: ThreatPattern,
        tenant_id: str,
    ) -> List[Tier3Match]:
        """Execute one Tier 3 pattern. Returns list of full-path matches with CDR grading."""
        if pattern.tier != 3:
            raise ValueError(f"Tier3Matcher received tier={pattern.tier} pattern")

        cypher, params = self._compiler.compile(pattern, tenant_id)

        t0 = time.perf_counter()
        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(cypher, parameters=params, timeout=_TIER3_TIMEOUT_MS)
            path_rows = list(result)
        latency_ms = (time.perf_counter() - t0) * 1000

        matches: List[Tier3Match] = []
        for row in path_rows:
            entry_uid = row["entry_uid"]
            target_uid = row.get("target_uid")
            hop_uids = [
                row[f"hop{i}_uid"]
                for i in range(len(pattern.hops))
                if row.get(f"hop{i}_uid")
            ]
            all_uids = [entry_uid] + hop_uids + ([target_uid] if target_uid else [])

            cdr_count, tactic_order_ok = self._grade_cdr(
                session=None,  # reuse driver below
                pattern=pattern,
                tenant_id=tenant_id,
                resource_uids=all_uids,
            )

            incident_class, severity = self._classify(
                pattern, cdr_count, tactic_order_ok,
            )

            matches.append(
                Tier3Match(
                    pattern_id=row["pattern_id"],
                    tenant_id=row["tenant_id"],
                    account_id=row.get("account_id", ""),
                    region=row.get("region", ""),
                    entry_uid=entry_uid,
                    hop_uids=hop_uids,
                    target_uid=target_uid,
                    incident_class=incident_class,
                    severity=severity,
                    cdr_technique_count=cdr_count,
                    latency_ms=latency_ms,
                )
            )

        logger.debug(
            "Tier3 pattern %s: %d matches in %.1f ms",
            pattern.id, len(matches), latency_ms,
        )
        return matches

    def _grade_cdr(
        self,
        session: Any,
        pattern: ThreatPattern,
        tenant_id: str,
        resource_uids: List[str],
    ) -> tuple[int, bool]:
        """Count CDR techniques observed on the attack path resources.

        Returns (technique_count, tactic_order_satisfied).
        """
        if not pattern.cdr_watch or not resource_uids:
            return 0, True

        watch = pattern.cdr_watch
        window_start = (
            datetime.now(timezone.utc) - timedelta(minutes=watch.window_minutes)
        ).isoformat()

        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as s:
            result = s.run(
                """
                MATCH (r:Resource {tenant_id: $tid})-[:TRIGGERED_ON]->(e:CDREvent)
                WHERE r.resource_uid IN $uids
                  AND ANY(t IN e.mitre_techniques WHERE t IN $techniques)
                  AND e.event_time >= $window_start
                UNWIND [t IN e.mitre_techniques WHERE t IN $techniques] AS technique
                RETURN DISTINCT technique, e.event_time AS evt_time
                ORDER BY e.event_time ASC
                """,
                tid=tenant_id,
                uids=resource_uids,
                techniques=watch.techniques,
                window_start=window_start,
            )
            rows = list(result)

        observed_techniques = {r["technique"] for r in rows}
        technique_count = len(observed_techniques)

        tactic_order_ok = True
        if watch.tactic_order_required and len(rows) >= 2:
            # Verify techniques appear in the declared tactic_chain_order sequence
            ordered_seen = [r["technique"] for r in rows]
            tactic_order_ok = self._check_tactic_order(
                ordered_seen, watch.techniques,
            )

        return technique_count, tactic_order_ok

    def _check_tactic_order(
        self,
        observed: List[str],
        expected_order: List[str],
    ) -> bool:
        """Verify observed techniques follow the expected ordering."""
        order_index = {tech: i for i, tech in enumerate(expected_order)}
        last_idx = -1
        for tech in observed:
            idx = order_index.get(tech, -1)
            if idx < last_idx:
                return False
            if idx >= 0:
                last_idx = idx
        return True

    def _classify(
        self,
        pattern: ThreatPattern,
        cdr_count: int,
        tactic_order_ok: bool,
    ) -> tuple[str, str]:
        """Grade the match as posture / suspicious / active."""
        scoring = pattern.scoring

        # theoretical confidence patterns cannot escalate to active
        if pattern.confidence == "theoretical":
            return "posture", scoring.posture_severity

        watch = pattern.cdr_watch
        if cdr_count == 0 or watch is None:
            return "posture", scoring.posture_severity

        coverage_met = (
            cdr_count >= 2
            or (cdr_count / max(1, len(watch.techniques))) >= watch.min_coverage
        )
        order_ok = tactic_order_ok or not watch.tactic_order_required

        if coverage_met and order_ok:
            return "active", scoring.active_severity

        return "suspicious", scoring.posture_severity
