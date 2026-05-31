"""
SeverityScorer + IncidentDeduper (S2-07).

SeverityScorer:
  Configurable severity formula — auditable, not hardcoded.
  Input: list of match dicts from Tier 1/2/3 matchers.
  Output: final severity string + incident_class.

IncidentDeduper:
  Roll-up key: (tenant_id, entry_resource_uid, target_resource_uid)
  Groups matches BEFORE computing dedup_key.
  Primary pattern = highest tier in the group.
  dedup_key = sha256(pattern_id|tenant_id|entry_uid|target_uid)
  evidence matched_patterns[] records ALL matched patterns in the group.

Escalation rules:
  posture → suspicious: first CDR technique observed on path
  suspicious → active: second CDR technique OR min_coverage met
  confidence=theoretical patterns must NOT produce incident_class='active'.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _max_severity(a: str, b: str) -> str:
    ai = _SEVERITY_ORDER.index(a) if a in _SEVERITY_ORDER else 0
    bi = _SEVERITY_ORDER.index(b) if b in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[max(ai, bi)]


@dataclass
class RolledUpIncident:
    """Deduplicated incident ready for IncidentWriter."""

    dedup_key: str
    tenant_id: str
    account_id: str
    region: str
    entry_uid: str
    target_uid: Optional[str]
    primary_pattern_id: str
    matched_patterns: List[str]
    tier: int
    incident_class: str
    severity: str
    hop_uids: List[str] = field(default_factory=list)
    cdr_technique_count: int = 0
    title: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dedup_key": self.dedup_key,
            "tenant_id": self.tenant_id,
            "account_id": self.account_id,
            "region": self.region,
            "entry_uid": self.entry_uid,
            "target_uid": self.target_uid,
            "primary_pattern_id": self.primary_pattern_id,
            "matched_patterns": self.matched_patterns,
            "tier": self.tier,
            "incident_class": self.incident_class,
            "severity": self.severity,
            "hop_uids": self.hop_uids,
            "cdr_technique_count": self.cdr_technique_count,
        }


def _dedup_key(
    pattern_id: str,
    tenant_id: str,
    entry_uid: str,
    target_uid: Optional[str],
) -> str:
    """sha256(pattern_id|tenant_id|entry_uid|target_uid)."""
    target = target_uid or ""
    raw = f"{pattern_id}|{tenant_id}|{entry_uid}|{target}"
    return hashlib.sha256(raw.encode()).hexdigest()


class SeverityScorer:
    """Determines final severity for a rolled-up incident group."""

    def score(
        self,
        matches: List[Dict[str, Any]],
    ) -> tuple[str, str]:
        """Return (incident_class, severity) for a group of matches.

        Escalation rules:
          - All posture, 0 CDR → posture / max(posture_severity across patterns)
          - Any suspicious (1 CDR technique) → suspicious / HIGH
          - Any active (≥2 CDR or coverage met) → active / CRITICAL
          - But: theoretical confidence patterns stay posture
        """
        incident_class = "posture"
        severity = "low"

        for m in matches:
            m_class = m.get("incident_class", "posture")
            m_severity = m.get("severity", "low")
            severity = _max_severity(severity, m_severity)

            if m_class == "active" and incident_class != "active":
                incident_class = "active"
            elif m_class == "suspicious" and incident_class == "posture":
                incident_class = "suspicious"

        return incident_class, severity


class IncidentDeduper:
    """Groups and deduplicates pattern matches into RolledUpIncidents."""

    def __init__(self) -> None:
        self._scorer = SeverityScorer()

    def deduplicate(
        self,
        matches: List[Dict[str, Any]],
    ) -> List[RolledUpIncident]:
        """Group matches by (tenant_id, entry_uid, target_uid), then deduplicate.

        Returns one RolledUpIncident per unique (entry, target) pair.
        """
        groups: Dict[tuple, List[Dict[str, Any]]] = {}

        for m in matches:
            key = (
                m.get("tenant_id", ""),
                m.get("entry_uid", ""),
                m.get("target_uid") or "",
            )
            groups.setdefault(key, []).append(m)

        incidents: List[RolledUpIncident] = []

        for (tenant_id, entry_uid, target_uid_str), group in groups.items():
            target_uid = target_uid_str or None

            # Primary pattern = highest tier (highest tier number = most severe)
            primary = max(group, key=lambda m: (m.get("tier", 1), m.get("severity", "low")))
            primary_pattern_id = primary.get("pattern_id", "")

            matched_patterns = list({m.get("pattern_id", "") for m in group})
            max_tier = max(m.get("tier", 1) for m in group)
            max_cdr = max(m.get("cdr_technique_count", 0) for m in group)
            hop_uids = primary.get("hop_uids", [])
            account_id = primary.get("account_id", "")
            region = primary.get("region", "")

            incident_class, severity = self._scorer.score(group)

            dk = _dedup_key(primary_pattern_id, tenant_id, entry_uid, target_uid)

            incidents.append(
                RolledUpIncident(
                    dedup_key=dk,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    region=region,
                    entry_uid=entry_uid,
                    target_uid=target_uid,
                    primary_pattern_id=primary_pattern_id,
                    matched_patterns=matched_patterns,
                    tier=max_tier,
                    incident_class=incident_class,
                    severity=severity,
                    hop_uids=hop_uids,
                    cdr_technique_count=max_cdr,
                )
            )

        logger.info(
            "IncidentDeduper: %d matches → %d unique incidents",
            len(matches), len(incidents),
        )
        return incidents
