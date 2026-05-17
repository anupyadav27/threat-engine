"""
StoryBuilder — generates human-readable narrative from an incident's hop chain (S2-09).

Two variants:
  posture: no actor line — describes the misconfiguration path
  suspicious/active: includes observed techniques, event count, time window

Template interpolation uses resource metadata from the Neo4j graph —
NEVER raw resource_uid in user-facing text. Resource type + region + account
are used instead.

PII constraint (CP1-02): actor_principal is NEVER included in story_text.
Only the actor_hash is referenced in the evidence model.
"""
from __future__ import annotations

import os

import logging
from typing import Any, Dict, List, Optional

from neo4j import Driver

from threat_v1.correlator.deduper import RolledUpIncident

logger = logging.getLogger(__name__)

_POSTURE_TEMPLATE = (
    "A {entry_type} in {entry_region} ({entry_account}) has a configuration gap "
    "that could allow an attacker to {chain_summary}. "
    "{hop_count} resources form the attack path."
)

_ACTIVE_TEMPLATE = (
    "An actor has been observed on this attack path. "
    "{cdr_technique_count} MITRE ATT&CK technique(s) detected on resources in "
    "{entry_region} ({entry_account}) within the observation window. "
    "Attack chain: {entry_type} → {chain_summary}."
)

_SUSPICIOUS_TEMPLATE = (
    "Partial attack chain activity detected. "
    "{cdr_technique_count} MITRE ATT&CK technique(s) observed on the path "
    "originating from {entry_type} in {entry_region} ({entry_account}). "
    "Full escalation not yet confirmed — monitor for additional signals."
)

_CHAIN_SUMMARIES = {
    "privilege_escalation": "escalate privileges to a higher-trust identity",
    "credential_access": "access cloud credentials or secrets",
    "lateral_movement": "move laterally to adjacent cloud resources",
    "data_access": "access sensitive data stores",
    "exfiltration": "exfiltrate data to an external destination",
    "execution": "execute arbitrary code in cloud workloads",
    "persistence": "maintain persistent access to the environment",
    "initial_access": "gain initial access to the cloud environment",
    "impact": "cause operational impact (deletion, ransomware, disruption)",
    "collection": "collect sensitive data from cloud storage",
    "defense_evasion": "evade detection and monitoring",
    "discovery": "enumerate cloud resources and identities",
}


class StoryBuilder:
    """Builds human-readable story_text for incidents."""

    def __init__(self, neo4j_driver: Driver) -> None:
        self._driver = neo4j_driver

    def build(self, incident: RolledUpIncident) -> str:
        """Generate story_text for the incident. Returns the narrative string."""
        meta = self._fetch_resource_meta(incident.entry_uid, incident.tenant_id)
        entry_type = meta.get("resource_type", "Resource")
        entry_region = meta.get("region", "unknown-region")
        entry_account = meta.get("account_id", "unknown-account")

        hop_count = len(incident.hop_uids) + (1 if incident.target_uid else 0)

        chain_summary = self._chain_summary(incident.primary_pattern_id)

        if incident.incident_class == "active":
            story = _ACTIVE_TEMPLATE.format(
                cdr_technique_count=incident.cdr_technique_count,
                entry_region=entry_region,
                entry_account=entry_account,
                entry_type=entry_type,
                chain_summary=chain_summary,
            )
        elif incident.incident_class == "suspicious":
            story = _SUSPICIOUS_TEMPLATE.format(
                cdr_technique_count=incident.cdr_technique_count,
                entry_region=entry_region,
                entry_account=entry_account,
                entry_type=entry_type,
            )
        else:
            story = _POSTURE_TEMPLATE.format(
                entry_type=entry_type,
                entry_region=entry_region,
                entry_account=entry_account,
                chain_summary=chain_summary,
                hop_count=hop_count,
            )

        return story

    def _fetch_resource_meta(
        self, resource_uid: str, tenant_id: str
    ) -> Dict[str, Any]:
        """Fetch resource display metadata from Neo4j."""
        try:
            with self._driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
                result = session.run(
                    """
                    MATCH (r:Resource {resource_uid: $uid, tenant_id: $tid})
                    RETURN r.resource_type AS resource_type,
                           r.region AS region,
                           r.account_id AS account_id
                    LIMIT 1
                    """,
                    uid=resource_uid,
                    tid=tenant_id,
                )
                row = result.single()
                return dict(row) if row else {}
        except Exception as exc:
            logger.warning("StoryBuilder failed to fetch meta for %s: %s", resource_uid, exc)
            return {}

    def _chain_summary(self, pattern_id: str) -> str:
        """Derive a human-readable chain summary from the pattern id."""
        pid_lower = pattern_id.lower()
        for key, summary in _CHAIN_SUMMARIES.items():
            if key.replace("_", "") in pid_lower or key in pid_lower:
                return summary
        return "access a high-value cloud resource"
