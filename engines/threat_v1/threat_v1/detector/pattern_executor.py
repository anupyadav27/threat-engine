"""
PatternExecutor — orchestrates pattern execution across all tiers.

Called from run_scan.py after graph build completes. Runs after the graph
builder has populated Neo4j with resource, finding, and CDR nodes.

Execution flow per scan:
  1. Load active patterns from PatternRegistry
  2. For each pattern (ordered Tier 1 → Tier 2 → Tier 3):
     a. Run under PerformanceGuard (timeout + result cap)
     b. Collect match dicts
  3. Deduplicate all matches via IncidentDeduper
  4. Build story_text for each incident
  5. Write incidents via IncidentWriter (advisory locked)
  6. Apply lifecycle transitions (resolve stale active incidents)

Patterns are executed per-CSP: the executor filters by the account's CSP
so AWS patterns don't fire against Azure resources.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from neo4j import Driver

from threat_v1.correlator.deduper import IncidentDeduper, RolledUpIncident
from threat_v1.correlator.story_builder import StoryBuilder
from threat_v1.correlator.writer import IncidentWriter, LifecycleTransitioner
from threat_v1.detector.performance_guard import PerformanceGuard
from threat_v1.detector.tier1 import Tier1Matcher
from threat_v1.detector.tier2 import Tier2Matcher
from threat_v1.detector.tier3 import Tier3Matcher
from threat_v1.patterns.models import ThreatPattern
from threat_v1.patterns.registry import PatternRegistry

logger = logging.getLogger(__name__)


class PatternExecutor:
    """Orchestrates the full pattern execution pipeline for one (tenant, account) pair."""

    def __init__(
        self,
        threat_conn: Any,
        neo4j_driver: Driver,
    ) -> None:
        self._threat_conn = threat_conn
        self._driver = neo4j_driver

        self._registry = PatternRegistry(threat_conn)
        self._guard = PerformanceGuard(threat_conn)
        self._t1 = Tier1Matcher(neo4j_driver)
        self._t2 = Tier2Matcher(neo4j_driver)
        self._t3 = Tier3Matcher(neo4j_driver)
        self._deduper = IncidentDeduper()
        self._story = StoryBuilder(neo4j_driver)
        self._writer = IncidentWriter(threat_conn)
        self._lifecycle = LifecycleTransitioner(threat_conn)

    def execute(
        self,
        tenant_id: str,
        account_id: str,
        scan_run_id: str,
        csp: str,
    ) -> Dict[str, int]:
        """Run all active patterns for this tenant/account/CSP.

        Returns:
            Dict with patterns_run, total_matches, incidents_written.
        """
        patterns = self._registry.load_active_patterns(
            tenant_id=tenant_id,
            csp_filter=csp.lower(),
        )

        if not patterns:
            logger.info(
                "No active patterns for csp=%s tenant=%s", csp, tenant_id,
            )
            return {"patterns_run": 0, "total_matches": 0, "incidents_written": 0}

        all_matches: List[Dict[str, Any]] = []

        # Run Tier 1 (fastest — no traversal)
        for pattern in [p for p in patterns if p.tier == 1]:
            matches = self._run_pattern(pattern, tenant_id)
            all_matches.extend(m.as_dict() for m in matches)

        # Run Tier 2
        for pattern in [p for p in patterns if p.tier == 2]:
            matches = self._run_pattern(pattern, tenant_id)
            all_matches.extend(m.as_dict() for m in matches)

        # Run Tier 3 (slowest — full path + CDR grading)
        for pattern in [p for p in patterns if p.tier == 3]:
            matches = self._run_pattern(pattern, tenant_id)
            all_matches.extend(m.as_dict() for m in matches)

        if not all_matches:
            logger.info(
                "No pattern matches for tenant=%s account=%s csp=%s",
                tenant_id, account_id, csp,
            )
            return {
                "patterns_run": len(patterns),
                "total_matches": 0,
                "incidents_written": 0,
            }

        # Deduplicate
        incidents = self._deduper.deduplicate(all_matches)

        # Attach title from pattern description
        title_map = {p.id: p.description for p in patterns if p.description}
        for inc in incidents:
            inc.title = title_map.get(inc.primary_pattern_id, inc.primary_pattern_id)

        # Attach story_text
        for inc in incidents:
            try:
                inc_dict = inc.as_dict()
                inc_dict["story_text"] = self._story.build(inc)
            except Exception as exc:
                logger.warning("StoryBuilder failed for %s: %s", inc.dedup_key, exc)

        # Write to DB
        written = self._writer.write_batch(incidents, scan_run_id)

        # Lifecycle: resolve stale active incidents
        self._lifecycle.resolve_stale_active(tenant_id, account_id, scan_run_id)

        logger.info(
            "PatternExecutor complete: %d patterns, %d matches, %d incidents — "
            "tenant=%s account=%s csp=%s",
            len(patterns), len(all_matches), written,
            tenant_id, account_id, csp,
        )
        return {
            "patterns_run": len(patterns),
            "total_matches": len(all_matches),
            "incidents_written": written,
        }

    def _run_pattern(
        self,
        pattern: ThreatPattern,
        tenant_id: str,
    ) -> List[Any]:
        """Run a single pattern under the PerformanceGuard."""
        if pattern.tier == 1:
            matcher_fn = self._t1.run
        elif pattern.tier == 2:
            matcher_fn = self._t2.run
        else:
            matcher_fn = self._t3.run

        # Pass pattern and tenant_id as positional args to avoid kwarg name collision
        # with run_with_guard's own tenant_id parameter.
        return self._guard.run_with_guard(
            pattern.id,
            tenant_id,
            matcher_fn,
            pattern,
            tenant_id,
        )
