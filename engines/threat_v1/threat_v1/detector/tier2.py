"""
Tier2Matcher — detects partial attack paths (chain forming, early warning).

Fires when min_hops_for_tier2 of the required hops in a Tier 3 pattern are
observed, even if the crown jewel target has not been reached. Produces an
early-warning incident classified as posture/MEDIUM.

Also used to run Tier 2 patterns that are explicitly authored at tier=2.

Latency target: < 500ms per pattern.
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

_TIER2_TIMEOUT_MS = 5000  # 5s hard timeout in Neo4j driver


class Tier2Match:
    __slots__ = ["pattern_id", "tenant_id", "account_id", "region",
                 "entry_uid", "hop_uids", "latency_ms"]

    def __init__(
        self,
        pattern_id: str,
        tenant_id: str,
        account_id: str,
        region: str,
        entry_uid: str,
        hop_uids: List[str],
        latency_ms: float,
    ) -> None:
        self.pattern_id = pattern_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.region = region
        self.entry_uid = entry_uid
        self.hop_uids = hop_uids
        self.latency_ms = latency_ms

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "tenant_id": self.tenant_id,
            "account_id": self.account_id,
            "region": self.region,
            "entry_uid": self.entry_uid,
            "hop_uids": self.hop_uids,
            "tier": 2,
            "incident_class": "suspicious",
            "latency_ms": self.latency_ms,
        }


class Tier2Matcher:
    """Executes Tier 2 patterns against the Neo4j graph."""

    def __init__(self, neo4j_driver: Driver) -> None:
        self._driver = neo4j_driver
        self._compiler = PatternCompiler()

    def run(
        self,
        pattern: ThreatPattern,
        tenant_id: str,
    ) -> List[Tier2Match]:
        """Execute one Tier 2 pattern. Returns a list of partial-path matches."""
        if pattern.tier not in (2, 3):
            raise ValueError(
                f"Tier2Matcher received tier={pattern.tier} pattern — "
                "expected 2 or 3 (Tier 3 used for early-warning partial match)"
            )

        cypher, params = self._compiler.compile(pattern, tenant_id)

        t0 = time.perf_counter()
        with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
            result = session.run(cypher, parameters=params, timeout=_TIER2_TIMEOUT_MS)
            rows = list(result)
        latency_ms = (time.perf_counter() - t0) * 1000

        matches: List[Tier2Match] = []
        for r in rows:
            hop_uids = [
                r[f"hop{i}_uid"]
                for i in range(len(pattern.hops))
                if r.get(f"hop{i}_uid")
            ]
            matches.append(
                Tier2Match(
                    pattern_id=r["pattern_id"],
                    tenant_id=r["tenant_id"],
                    account_id=r.get("account_id", ""),
                    region=r.get("region", ""),
                    entry_uid=r["entry_uid"],
                    hop_uids=hop_uids,
                    latency_ms=latency_ms,
                )
            )

        logger.debug(
            "Tier2 pattern %s: %d matches in %.1f ms",
            pattern.id, len(matches), latency_ms,
        )
        return matches
