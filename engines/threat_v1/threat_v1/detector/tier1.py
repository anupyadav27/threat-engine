"""
Tier1Matcher — detects toxic combinations on single Resource nodes.

Matches on aggregated boolean flags — no graph traversal needed.
Flags are set by the graph builder (misconfig_loader, vuln_loader, cdr_loader).

Latency target: < 10ms per pattern (single indexed MATCH, no traversal).

Output: list of Tier1Match dicts, one per matching resource.
"""
from __future__ import annotations

import os

import logging
import time
from typing import Any, Dict, List

from neo4j import Driver

from threat_v1.patterns.compiler import PatternCompiler
from threat_v1.patterns.models import ThreatPattern

logger = logging.getLogger(__name__)

# Neo4j query timeout for Tier 1 (ms)
_TIER1_TIMEOUT_MS = 500


class Tier1Match:
    __slots__ = ["pattern_id", "tenant_id", "account_id", "region",
                 "entry_uid", "entry_type", "latency_ms", "severity"]

    def __init__(
        self,
        pattern_id: str,
        tenant_id: str,
        account_id: str,
        region: str,
        entry_uid: str,
        entry_type: str,
        latency_ms: float,
        severity: str = "high",
    ) -> None:
        self.pattern_id = pattern_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.region = region
        self.entry_uid = entry_uid
        self.entry_type = entry_type
        self.latency_ms = latency_ms
        self.severity = severity

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "tenant_id": self.tenant_id,
            "account_id": self.account_id,
            "region": self.region,
            "entry_uid": self.entry_uid,
            "entry_type": self.entry_type,
            "tier": 1,
            "incident_class": "posture",
            "latency_ms": self.latency_ms,
            "severity": self.severity,
        }


class Tier1Matcher:
    """Executes Tier 1 patterns against the Neo4j graph."""

    def __init__(self, neo4j_driver: Driver) -> None:
        self._driver = neo4j_driver
        self._compiler = PatternCompiler()

    def run(
        self,
        pattern: ThreatPattern,
        tenant_id: str,
    ) -> List[Tier1Match]:
        """Execute one Tier 1 pattern. Returns a list of matches."""
        if pattern.tier != 1:
            raise ValueError(f"Tier1Matcher received tier={pattern.tier} pattern")

        cypher, params = self._compiler.compile(pattern, tenant_id)

        t0 = time.perf_counter()
        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(cypher, parameters=params, timeout=_TIER1_TIMEOUT_MS)
            rows = list(result)
        latency_ms = (time.perf_counter() - t0) * 1000

        matches = [
            Tier1Match(
                pattern_id=r["pattern_id"],
                tenant_id=r["tenant_id"],
                account_id=r.get("account_id", ""),
                region=r.get("region", ""),
                entry_uid=r["entry_uid"],
                entry_type=r.get("entry_type", ""),
                latency_ms=latency_ms,
                severity=pattern.severity_base,
            )
            for r in rows
        ]

        logger.debug(
            "Tier1 pattern %s: %d matches in %.1f ms",
            pattern.id, len(matches), latency_ms,
        )
        return matches
