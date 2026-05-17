"""
PatternRegistry — loads active threat patterns for a tenant.

Patterns come from two sources:
  1. threat_scenario_patterns table (DB copy, synced from YAML catalog at deploy time)
  2. Filtered by threat_pattern_suppressions (per-tenant suppression, never global disable)

Loading from DB (not from YAML files at runtime) ensures:
  - Patterns survive container restarts without filesystem reads
  - Per-tenant suppressions can be applied without touching shared YAML files
  - Version tracking is possible (version column in DB)

The YAML catalog is the source of truth; the DB is the runtime copy.
A deployment step (Sprint 5) syncs catalog/ → threat_scenario_patterns.

CP1-05 enforcement: this class NEVER sets active=false on threat_scenario_patterns.
Suppression is always per-tenant in threat_pattern_suppressions.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set

import yaml
from pydantic import ValidationError

from threat_v1.patterns.models import ThreatPattern

logger = logging.getLogger(__name__)


class PatternRegistry:
    """Loads and caches active patterns for a given tenant."""

    def __init__(self, threat_conn: Any) -> None:
        self._threat_conn = threat_conn

    def load_active_patterns(
        self,
        tenant_id: str,
        csp_filter: Optional[str] = None,
        tier_filter: Optional[int] = None,
    ) -> List[ThreatPattern]:
        """Return all active non-suppressed patterns for this tenant.

        Args:
            tenant_id: Tenant scope for suppression lookups.
            csp_filter: Optional CSP name to filter patterns (e.g. 'aws').
            tier_filter: Optional tier (1/2/3) to filter patterns.

        Returns:
            List of validated ThreatPattern objects.
        """
        suppressed_ids = self._fetch_suppressed_ids(tenant_id)
        rows = self._fetch_active_patterns(csp_filter, tier_filter)

        patterns: List[ThreatPattern] = []
        for row in rows:
            pat_id = row.get("pattern_key", "")
            if pat_id in suppressed_ids:
                logger.debug("Pattern %s suppressed for tenant %s", pat_id, tenant_id)
                continue

            pattern = self._parse_row(row)
            if pattern is not None and not pattern.is_deprecated:
                patterns.append(pattern)

        logger.info(
            "PatternRegistry loaded %d active patterns for tenant %s (suppressed=%d)",
            len(patterns),
            tenant_id,
            len(suppressed_ids),
        )
        return patterns

    def _fetch_active_patterns(
        self,
        csp_filter: Optional[str],
        tier_filter: Optional[int],
    ) -> List[Dict[str, Any]]:
        """Query threat_scenario_patterns for active non-deprecated patterns."""
        cur = self._threat_conn.cursor()

        conditions = ["active = true", "deprecated_at IS NULL"]
        params: List[Any] = []

        if csp_filter:
            conditions.append("(csps @> %s::jsonb OR csps = '[]'::jsonb)")
            params.append(json.dumps([csp_filter.lower()]))

        if tier_filter is not None:
            conditions.append("tier = %s")
            params.append(tier_filter)

        where = " AND ".join(conditions)
        cur.execute(
            f"""
            SELECT pattern_id, pattern_key, pattern_yaml, tier, severity_base, confidence,
                   csps, mitre_techniques, mitre_tactics, deprecated_at, version
            FROM threat_scenario_patterns
            WHERE {where}
            ORDER BY tier ASC, pattern_key ASC
            """,
            params,
        )
        rows = cur.fetchall()
        cur.close()
        return list(rows)

    def _fetch_suppressed_ids(self, tenant_id: str) -> Set[str]:
        """Return pattern_ids suppressed for this tenant."""
        cur = self._threat_conn.cursor()
        cur.execute(
            """
            SELECT DISTINCT pattern_key
            FROM threat_pattern_suppressions
            WHERE tenant_id = %s
              AND (expires_at IS NULL OR expires_at > NOW())
            """,
            (tenant_id,),
        )
        rows = cur.fetchall()
        cur.close()
        return {row["pattern_key"] for row in rows}

    def _parse_row(self, row: Dict[str, Any]) -> Optional[ThreatPattern]:
        """Parse a DB row's pattern_yaml into a ThreatPattern model."""
        pat_id = row.get("pattern_id", "<unknown>")
        pattern_yaml = row.get("pattern_yaml")

        if not pattern_yaml:
            logger.warning("Pattern %s has empty pattern_yaml — skipping", pat_id)
            return None

        try:
            data = yaml.safe_load(pattern_yaml)
            return ThreatPattern.model_validate(data)
        except (yaml.YAMLError, ValidationError) as exc:
            logger.warning(
                "Pattern %s failed validation: %s — skipping",
                pat_id, exc,
            )
            return None

    @classmethod
    def load_from_yaml_dir(cls, yaml_dir: str) -> List[ThreatPattern]:
        """Load patterns directly from YAML files (used in CI + tests)."""
        import pathlib

        patterns: List[ThreatPattern] = []
        # Skip macOS AppleDouble resource-fork files (._filename) that match *.yaml
        for path in sorted(p for p in pathlib.Path(yaml_dir).rglob("*.yaml") if not p.name.startswith("._")):
            try:
                data = yaml.safe_load(path.read_text())
                pattern = ThreatPattern.model_validate(data)
                patterns.append(pattern)
            except (yaml.YAMLError, ValidationError) as exc:
                logger.warning("Pattern file %s failed: %s", path, exc)
        return patterns
