"""
Attack Path Engine — Pydantic models.

RawPath:    output of Neo4j or PostgreSQL BFS (one row per path found).
PostureRow: subset of resource_security_posture used by scorer and deduplicator.
ScoredPath: RawPath + scoring results + MITRE ATT&CK classification.
Path:       ScoredPath + deduplication / grouping metadata.
ChokePoint: result of choke-point detection.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RawPath(BaseModel):
    """One raw path returned by the Neo4j reverse BFS query (AP-P2-03).

    Fields match the RETURN clause of REVERSE_BFS_CYPHER exactly.
    """

    crown_jewel_uid: str
    entry_point_uid: str
    node_uids: List[str] = Field(default_factory=list)
    node_types: List[str] = Field(default_factory=list)
    edge_types: List[str] = Field(default_factory=list)
    hop_categories: List[str] = Field(default_factory=list)
    depth: int = 0
    max_epss: Optional[float] = None
    misconfig_count: int = 0
    threat_count: int = 0
    top_cves: List[Dict[str, Any]] = Field(default_factory=list)

    # Per-hop evidence collected by Phase-2 OPTIONAL MATCH clauses
    hop_evidence: List[Dict[str, Any]] = Field(default_factory=list)

    # Set by pg_graph from entry_categories passed by run_scan.py.
    # One of: INTERNET_ENTRY | IDENTITY_ENTRY | CICD_ENTRY | THIRD_PARTY_ENTRY |
    #         INTERNAL_WORKLOAD_ENTRY | ENDPOINT_AGENT_ENTRY
    entry_point_category: str = "INTERNET_ENTRY"


class PostureRow(BaseModel):
    """Subset of resource_security_posture used by the scorer and deduplicator.

    Pre-fetched into a dict[resource_uid → PostureRow] by run_scan.py.
    The scorer and deduplicator receive this dict — they do NOT query the DB.
    """

    resource_uid: str = ""
    resource_type: str = ""          # e.g. "s3.bucket", "eks.cluster", "ec2.instance"
    entry_point_type: str = ""       # internet | vpn | onprem | peer_account | vendor | k8s_external
    is_internet_exposed: bool = False
    max_epss: Optional[float] = None
    critical_misconfig_count: int = 0
    high_misconfig_count: int = 0
    waf_protected: bool = False
    mfa_required: bool = False
    has_permission_boundary: bool = False
    has_active_cdr_actor: bool = False
    crown_jewel_type: str = ""
    data_classification: Optional[str] = None   # pii | financial | credentials | internal | public
    blast_radius_count: int = 0
    encryption_type: Optional[str] = None       # aes256 | kms | none | null
    is_encrypted_at_rest: bool = True            # False = known unencrypted storage
    network_exposure_score: int = -1             # 0=fully isolated, 1-100=exposure level, -1=unknown
    is_crown_jewel: bool = False
    is_on_attack_path: bool = False
    attack_path_count: int = 0
    is_choke_point: bool = False


class ScoredPath(RawPath):
    """RawPath with scoring results and MITRE ATT&CK classification appended by scorer.py."""

    probability_score: float = 0.0
    impact_score: float = 0.0
    path_score: int = 0                     # round(min(100, P × I × 100))
    severity: str = "low"                   # critical | high | medium | low
    chain_type: str = ""                    # e.g. "Internet → Data"
    entry_point_type: str = ""              # internet | vpn | onprem | peer_account | vendor | k8s_external
    crown_jewel_type: str = ""              # data | secrets | identity | infra_control | ai_model | code | data_warehouse | encryption_control
    data_classification: Optional[str] = None
    has_active_cdr_actor: bool = False      # lifted from posture signals

    # MITRE ATT&CK classification (populated by attack_vector.py)
    attack_vector_type: str = ""            # T1 | T2 | T3
    confidence_level: str = "speculative"  # confirmed | likely | speculative
    mitre_techniques: List[str] = Field(default_factory=list)    # ["T1190", "T1078", ...]
    tactic_sequence: List[str] = Field(default_factory=list)     # ["initial-access", "lateral-movement", ...]

    # Orca-style explanation (populated by path_explainer.py for top-N paths)
    explanation: Optional[Dict[str, Any]] = None

    # Business impact category derived from crown_jewel_type + access_capability.
    # One of: DataExposure | SecretExposure | PrivilegeTakeover |
    #         InfrastructureTakeover | BusinessDisruption | ServiceControl
    attack_impact_type: str = ""

    # Formal attack objective from attack_objective_catalog (OBJ-02).
    # One of: DATA_THEFT | DATA_DESTRUCTION | SECRET_THEFT | DECRYPTION |
    #         PRIVILEGE_ESCALATION | CLUSTER_TAKEOVER | ACCOUNT_TAKEOVER |
    #         AI_MODEL_ACCESS | CODE_ACCESS
    objective_type: str = ""

    # TRUE  = final edge capability satisfies the objective's required_capability.
    # FALSE = topology-only path (network reach to target without confirmed credential edge).
    # None  = objective not evaluated (no catalog entry for this resource_type).
    objective_satisfied: Optional[bool] = None


class Path(ScoredPath):
    """ScoredPath with deduplication / grouping metadata appended by deduplicator.py."""

    # Phase 1 (exact dedup)
    path_id: str = ""                       # sha256("|".join(node_uids))

    # Phase 3 (exposure-key grouping)
    group_id: Optional[str] = None         # first 16 chars of sha256(exposure_key)
    group_size: int = 1
    is_representative: bool = True
    choke_node_uid: Optional[str] = None   # penultimate node in group tail
    absorbed_count: int = 0               # how many shorter paths this path absorbed

    # Exposure key components (set by deduplicator, exposed in BFF)
    # "Who can reach my crown jewel, via what capability?"
    effective_access_principal: Optional[str] = None  # node_uids[-2]: last principal before target
    access_capability: Optional[str] = None           # edge_types[-1]: e.g. "can_read", "can_decrypt"


class ChokePoint(BaseModel):
    """A node identified as a choke point by choke_point_detector.py."""

    node_uid: str
    paths_blocked_if_fixed: int            # count of distinct group_ids this node appears in
    avg_path_score: float = 0.0            # average score of representative paths in those groups
