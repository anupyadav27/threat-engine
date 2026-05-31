"""
Attack Path Engine — MITRE ATT&CK Attack Vector Classifier.

Maps each attack path to:
  1. MITRE ATT&CK techniques per hop (based on edge/relation type).
  2. Attack vector type — T1 (single hop), T2 (two-hop), T3 (three-or-more hops).
  3. Confidence level — confirmed | likely | speculative.

Design:
  - EDGE_TO_TECHNIQUE: relation_type → list of (technique_id, tactic, description).
  - T1/T2/T3 are NOT strict depth filters — they describe the ATTACK PATTERN:
      T1: Single misconfiguration → crown jewel exposed directly.
      T2: Public resource + credential/lateral step → crown jewel.
      T3: Public → lateral movement → privilege escalation → crown jewel (3+ hops).
  - Confidence levels:
      confirmed  → CDR detection matches at least one hop technique.
      likely     → CDR detection present on path (any hop), or EPSS > 0.50 CVE.
      speculative → topology-only, no CDR confirmation, no high-EPSS CVE.

MITRE ATT&CK for Cloud reference: https://attack.mitre.org/matrices/enterprise/cloud/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("attack-path.attack_vector")


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique record
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    """One MITRE ATT&CK technique associated with a path hop."""

    technique_id: str          # e.g. "T1190"
    technique_name: str        # e.g. "Exploit Public-Facing Application"
    tactic: str                # e.g. "initial-access"
    tactic_name: str           # e.g. "Initial Access"
    description: str = ""      # brief description for UI display


# ---------------------------------------------------------------------------
# Edge-type → MITRE technique mapping
# The key is the relation_type from inventory_relationships (lowercased).
# Multiple techniques may apply to one edge type.
# ---------------------------------------------------------------------------

EDGE_TO_TECHNIQUE: Dict[str, List[MitreTechnique]] = {

    # ── Validator-generated attack edges ─────────────────────────────────────
    # These are the primary edges written by the VAL-01 validator layer and
    # picked up by BFS as is_attack_edge=TRUE rows in asset_relationships.

    "can_reach": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "initial-access",
                       "Initial Access", "Resource reachable via network — internet or lateral pivot"),
        MitreTechnique("T1021", "Remote Services", "lateral-movement",
                       "Lateral Movement", "Attacker pivots to a reachable resource"),
    ],
    "can_read": [
        MitreTechnique("T1530", "Data from Cloud Storage Object", "collection",
                       "Collection", "IAM policy grants read access to a sensitive data resource"),
    ],
    "can_invoke": [
        MitreTechnique("T1648", "Serverless Execution", "execution",
                       "Execution", "IAM policy grants invoke access to a serverless function"),
        MitreTechnique("T1059", "Command and Scripting Interpreter", "execution",
                       "Execution", "Attacker can trigger remote code execution via invocation"),
    ],
    "can_decrypt": [
        MitreTechnique("T1486", "Data Encrypted for Impact", "impact",
                       "Impact", "IAM policy grants KMS decrypt — attacker can access encrypted data"),
        MitreTechnique("T1552", "Unsecured Credentials", "credential-access",
                       "Credential Access", "KMS access enables credential decryption"),
    ],
    "can_write": [
        MitreTechnique("T1485", "Data Destruction", "impact",
                       "Impact", "IAM policy grants write access — potential data tampering or destruction"),
    ],
    "can_use_identity": [
        MitreTechnique("T1098", "Account Manipulation", "persistence",
                       "Persistence", "Resource can use an IAM identity for lateral movement"),
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "Attacker leverages a cloud identity for access"),
    ],
    "can_assume": [
        MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation",
                       "Privilege Escalation", "Resource can assume a privileged IAM role"),
    ],
    "assumes": [
        MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation",
                       "Privilege Escalation", "Principal assumes a role with broader permissions"),
    ],
    "worker_node_of": [
        MitreTechnique("T1611", "Escape to Host", "privilege-escalation",
                       "Privilege Escalation", "EC2 worker node of K8s cluster — node compromise escalates to cluster"),
    ],

    # ── Public exposure edges ─────────────────────────────────────────────────
    "exposed_via": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "initial-access",
                       "Initial Access", "Public-facing resource exploitable from the internet"),
    ],
    "reachable_from": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "initial-access",
                       "Initial Access", "Resource reachable from internet without authentication"),
    ],

    # Lateral movement edges
    "accesses": [
        MitreTechnique("T1530", "Data from Cloud Storage Object", "collection",
                       "Collection", "Resource can read data from cloud storage"),
    ],
    "reads": [
        MitreTechnique("T1530", "Data from Cloud Storage Object", "collection",
                       "Collection", "Resource has read access to a storage resource"),
    ],
    "writes": [
        MitreTechnique("T1485", "Data Destruction", "impact",
                       "Impact", "Resource has write/delete access — potential data destruction"),
    ],
    "contains": [
        MitreTechnique("T1021", "Remote Services", "lateral-movement",
                       "Lateral Movement", "Resource contains or hosts another resource"),
    ],
    "routes_to": [
        MitreTechnique("T1021", "Remote Services", "lateral-movement",
                       "Lateral Movement", "Traffic is routed from one resource to another"),
    ],
    "lateral_movement": [
        MitreTechnique("T1021", "Remote Services", "lateral-movement",
                       "Lateral Movement", "Explicit lateral movement relationship"),
    ],

    # Credential / privilege edges
    "has_role": [
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "Resource has an IAM role attached"),
        MitreTechnique("T1098", "Account Manipulation", "persistence",
                       "Persistence", "IAM role can be abused for privilege escalation"),
    ],
    "has_profile": [
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "EC2 instance has an instance profile with attached IAM role"),
    ],
    "linked_to": [
        MitreTechnique("T1078", "Valid Accounts", "lateral-movement",
                       "Lateral Movement", "Resource is linked to another — pivot via shared identity or config"),
    ],
    "attached_to": [
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "Resource is attached to a privileged resource"),
    ],
    "can_assume": [
        MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation",
                       "Privilege Escalation", "Resource can assume another role"),
    ],
    "can_access": [
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "Resource has direct access to another resource"),
    ],
    "member_of": [
        MitreTechnique("T1078", "Valid Accounts", "privilege-escalation",
                       "Privilege Escalation", "Principal is a member of a privileged group"),
    ],
    "privilege_escalation": [
        MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation",
                       "Privilege Escalation", "Explicit privilege escalation edge"),
    ],

    # Secret / credential access
    "uses": [
        MitreTechnique("T1552", "Unsecured Credentials", "credential-access",
                       "Credential Access", "Resource uses credentials from another resource"),
    ],
    "depends_on": [
        MitreTechnique("T1552", "Unsecured Credentials", "credential-access",
                       "Credential Access", "Resource depends on a credential or config source"),
    ],

    # Encryption / data protection edges
    "encrypted_by": [
        MitreTechnique("T1486", "Data Encrypted for Impact", "impact",
                       "Impact", "Data encrypted by a KMS key — key compromise enables decryption"),
    ],

    # Container / execution edges
    "executes_on": [
        MitreTechnique("T1610", "Deploy Container", "execution",
                       "Execution", "Workload executes on a compute resource"),
    ],
    "mounts": [
        MitreTechnique("T1611", "Escape to Host", "privilege-escalation",
                       "Privilege Escalation", "Container mounts host path — potential escape vector"),
    ],
    "execution": [
        MitreTechnique("T1059", "Command and Scripting Interpreter", "execution",
                       "Execution", "Explicit execution relationship"),
    ],

    # Data flow
    "data_flow": [
        MitreTechnique("T1537", "Transfer Data to Cloud Account", "exfiltration",
                       "Exfiltration", "Data flows between resources — potential exfiltration path"),
    ],
    "data_access": [
        MitreTechnique("T1530", "Data from Cloud Storage Object", "collection",
                       "Collection", "Direct data access relationship"),
    ],

    # Generic exposure
    "exposure": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "initial-access",
                       "Initial Access", "Resource exposed to external traffic"),
    ],
}

# Default technique when relation_type has no mapping
_DEFAULT_TECHNIQUE = MitreTechnique(
    "T1078", "Valid Accounts", "lateral-movement",
    "Lateral Movement", "Generic lateral movement between cloud resources",
)


# ---------------------------------------------------------------------------
# T1 / T2 / T3 attack vector pattern definitions
# ---------------------------------------------------------------------------

def _classify_pattern(
    depth: int,
    edge_types: List[str],
    tactic_sequence: List[str],
    has_cdr_confirmation: bool,
) -> str:
    """Classify path into T1 / T2 / T3 attack vector type.

    T1 — Single-step exposure (1 hop). Crown jewel directly reachable from
         internet-exposed resource via one misconfiguration or access edge.
         Example: Public S3 bucket, public RDS instance, open API gateway.

    T2 — Two-hop chain. Internet-facing resource used as a pivot point to
         reach the crown jewel via a credential or access edge.
         Example: EC2 (public IP) → has_role (IAM) → S3 read access.

    T3 — Multi-hop chain (3+ hops). Full attack kill-chain with initial access,
         lateral movement, and a final data access or exfiltration step.
         Example: ALB → EC2 → IAM role assumption → KMS key → encrypted S3 bucket.
    """
    if depth <= 1:
        return "T1"
    if depth == 2:
        return "T2"
    return "T3"


# ---------------------------------------------------------------------------
# Confidence level assignment
# ---------------------------------------------------------------------------

def _classify_confidence(
    path_node_uids: List[str],
    findings_lookup: Dict[str, Any],
    posture_lookup: Dict[str, Any],
) -> str:
    """Assign confidence level based on CDR detections and CVE evidence.

    confirmed  → CDR detection found on at least one hop node.
    likely     → CDR actor active on any node, or a node has EPSS > 0.50 CVE.
    speculative → topology-only evidence, no active threat signals.
    """
    for uid in path_node_uids:
        hop_findings = findings_lookup.get(uid, {})
        # Confirmed: active CDR threat detection on this hop
        if hop_findings.get("threat_detections"):
            return "confirmed"

    for uid in path_node_uids:
        posture = posture_lookup.get(uid)
        if posture and getattr(posture, "has_active_cdr_actor", False):
            return "likely"

        hop_findings = findings_lookup.get(uid, {})
        for cve in hop_findings.get("cves", []):
            epss = cve.get("epss_score") or 0.0
            if epss >= 0.50:
                return "likely"

    return "speculative"


# ---------------------------------------------------------------------------
# Technique extraction per hop
# ---------------------------------------------------------------------------

def _techniques_for_path(edge_types: List[str]) -> List[MitreTechnique]:
    """Return one technique per hop (deduped by technique_id).

    For each edge type in the path, pick the highest-risk technique
    (prefer exfiltration > impact > lateral-movement > other).
    """
    seen: set = set()
    result: List[MitreTechnique] = []
    tactic_risk: Dict[str, int] = {
        "exfiltration": 7, "impact": 6, "lateral-movement": 5,
        "privilege-escalation": 4, "credential-access": 3,
        "collection": 2, "execution": 2, "persistence": 1,
        "initial-access": 1, "defense-evasion": 1,
    }

    for rel_type in edge_types:
        candidates = EDGE_TO_TECHNIQUE.get(rel_type.lower(), [_DEFAULT_TECHNIQUE])
        # Sort by tactic risk descending — pick the scariest applicable technique
        best = max(candidates, key=lambda t: tactic_risk.get(t.tactic, 0))
        if best.technique_id not in seen:
            seen.add(best.technique_id)
            result.append(best)

    return result


# ---------------------------------------------------------------------------
# Public dataclass returned to callers
# ---------------------------------------------------------------------------

@dataclass
class AttackVector:
    """MITRE ATT&CK classification for one attack path."""

    vector_type: str                             # T1 | T2 | T3
    confidence: str                              # confirmed | likely | speculative
    techniques: List[MitreTechnique] = field(default_factory=list)
    tactic_sequence: List[str] = field(default_factory=list)  # ordered list of unique tactics

    def technique_ids(self) -> List[str]:
        return [t.technique_id for t in self.techniques]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_type": self.vector_type,
            "confidence": self.confidence,
            "techniques": [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "tactic_name": t.tactic_name,
                    "description": t.description,
                }
                for t in self.techniques
            ],
            "tactic_sequence": self.tactic_sequence,
        }


def classify_attack_vector(
    path_node_uids: List[str],
    edge_types: List[str],
    depth: int,
    posture_lookup: Dict[str, Any],
    findings_lookup: Dict[str, Any],
) -> AttackVector:
    """Classify one attack path and return its AttackVector.

    Args:
        path_node_uids:   Ordered list of resource UIDs in the path.
        edge_types:       Ordered list of relation types between nodes.
        depth:            Number of hops (len(edge_types)).
        posture_lookup:   Pre-fetched PostureRow dict (uid → PostureRow).
        findings_lookup:  Pre-fetched findings dict (uid → {misconfigs, cves, threat_detections}).

    Returns:
        AttackVector with vector_type, confidence, techniques, tactic_sequence.
    """
    techniques = _techniques_for_path(edge_types)
    tactic_sequence = list(dict.fromkeys(t.tactic for t in techniques))  # ordered, deduped

    has_cdr = any(
        bool(findings_lookup.get(uid, {}).get("threat_detections"))
        for uid in path_node_uids
    )

    vector_type = _classify_pattern(depth, edge_types, tactic_sequence, has_cdr)
    confidence = _classify_confidence(path_node_uids, findings_lookup, posture_lookup)

    return AttackVector(
        vector_type=vector_type,
        confidence=confidence,
        techniques=techniques,
        tactic_sequence=tactic_sequence,
    )
