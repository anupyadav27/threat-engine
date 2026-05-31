"""
Attack Path Engine — P×I Scorer.

Implements the exact scoring formulas from architecture doc sections 5.2 and 5.3.

probability_score(path, posture_lookup, findings_lookup) -> float
  Computes P: per-hop exploitability multipliers.
  CDR threat_detections from security_findings and MITRE tactic risk now applied
  per-hop (replaces the old post-loop CDR elevation and separate confidence_level).
  P encodes both exploitability AND detection certainty in one number.

impact_score(path, posture_lookup) -> float
  Computes I: crown jewel type weight × data classification × blast radius × encryption gap.

path_score = round(min(100, P × I × 100))

Severity buckets:
  critical >= 80
  high     60-79
  medium   40-59
  low      < 40

Security notes:
  - posture_lookup is a dict[resource_uid → PostureRow] passed in by run_scan.py
  - findings_lookup is a dict[resource_uid → {threat_detections, misconfigs, cves}]
  - scorer does NOT accept raw DB connections
  - probability never reaches 0.0 (each discount is multiplicative, not zeroing)
  - confidence_level is not a separate field — CDR/MITRE signals are folded into P
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..models.attack_path import PostureRow, RawPath, ScoredPath

logger = logging.getLogger("attack-path.scorer")

# ---------------------------------------------------------------------------
# Entry point base probabilities (architecture doc section 5.2)
# ---------------------------------------------------------------------------
_ENTRY_BASE_P: Dict[str, float] = {
    # Network-facing entry points
    "internet":          0.90,
    "onprem":            0.70,
    "datacenter":        0.70,
    "vpn":               0.60,
    "k8s_external":      0.50,
    "vendor":            0.50,
    "peer_account":      0.40,
    # Identity / credential entry points
    "identity":          0.75,   # IAM user with no MFA + active access keys
    "cicd":              0.70,   # GitHub Actions / CI/CD OIDC role (external trust)
    "third_party":       0.65,   # Cross-account SaaS integration role
    "endpoint_agent":    0.65,   # SSM-managed EC2 (StartSession = shell access)
    # Internal pivot entry points
    "compute":           0.60,   # Compromised pod / internal workload
}
_DEFAULT_BASE_P = 0.50

# ---------------------------------------------------------------------------
# Crown jewel type impact weights (architecture doc section 5.3)
# ---------------------------------------------------------------------------
_CJ_TYPE_IMPACT: Dict[str, float] = {
    "data":              1.00,
    "secrets":           0.95,
    "identity":          0.90,
    "infra_control":     0.85,
    "encryption_control": 0.85,
    "data_warehouse":    0.80,
    "ai_model":          0.75,
    "code":              0.70,
}
_DEFAULT_CJ_IMPACT = 0.70

# ---------------------------------------------------------------------------
# MITRE tactic risk multipliers — applied per hop when CDR detects a technique
# Higher-risk tactics (Exfiltration, Impact, Lateral Movement) raise P more
# than reconnaissance or discovery tactics.
# ---------------------------------------------------------------------------
_MITRE_TACTIC_BOOST: Dict[str, float] = {
    "exfiltration":          1.60,
    "impact":                1.50,
    "lateral-movement":      1.45,
    "privilege-escalation":  1.40,
    "persistence":           1.35,
    "credential-access":     1.35,
    "defense-evasion":       1.25,
    "command-and-control":   1.25,
    "collection":            1.20,
    "execution":             1.20,
    "initial-access":        1.15,
    "discovery":             1.10,
    "reconnaissance":        1.05,
}

# ---------------------------------------------------------------------------
# Data classification multipliers (architecture doc section 5.3)
# ---------------------------------------------------------------------------
_DATA_CLASS_MULT: Dict[str, float] = {
    "pii":         1.20,
    "financial":   1.20,
    "credentials": 1.20,
    "internal":    1.00,
    "public":      0.80,
}

# ---------------------------------------------------------------------------
# Business impact type taxonomy — what happens when an attacker reaches the target
# ---------------------------------------------------------------------------
_IMPACT_TYPE_WEIGHT: Dict[str, float] = {
    "DataExposure":           1.00,   # Customer data, PII, financial records exfiltrated
    "SecretExposure":         0.95,   # Secrets, API keys, KMS keys compromised
    "PrivilegeTakeover":      0.90,   # IAM role / admin account fully controlled
    "InfrastructureTakeover": 0.85,   # AWS account admin / root compromised
    "BusinessDisruption":     0.85,   # Production cluster taken down (availability impact)
    "ServiceControl":         0.80,   # K8s/EKS API control (deploy malware, exfil from pods)
}

# Map crown_jewel_type → base impact type when access_capability is not definitive
_CJ_TYPE_TO_IMPACT: Dict[str, str] = {
    "data":               "DataExposure",
    "data_warehouse":     "DataExposure",
    "ai_model":           "DataExposure",
    "secrets":            "SecretExposure",
    "encryption_control": "SecretExposure",
    "identity":           "PrivilegeTakeover",
    "infra_control":      "InfrastructureTakeover",
    "code":               "ServiceControl",
}

# EKS / K8s resource type prefixes — distinguish ServiceControl vs BusinessDisruption
_K8S_PREFIXES = ("eks.", "k8s.", "kubernetes.", "aks.", "gke.", "oke.", "container.cluster")

# Access capabilities that imply destructive / availability impact → BusinessDisruption
_DESTRUCTIVE_CAPS = frozenset({"can_delete", "can_disrupt", "can_terminate", "can_stop"})

# Entry category → display label for chain_type strings
_ENTRY_CAT_LABELS: Dict[str, str] = {
    "INTERNET_ENTRY":          "Internet",
    "IDENTITY_ENTRY":          "Identity",
    "CICD_ENTRY":              "CI/CD",
    "THIRD_PARTY_ENTRY":       "Third Party",
    "INTERNAL_WORKLOAD_ENTRY": "Internal Workload",
    "ENDPOINT_AGENT_ENTRY":    "Endpoint Agent",
}

# Impact type → human-friendly display label
_IMPACT_TYPE_DISPLAY: Dict[str, str] = {
    "DataExposure":           "Data Exposure",
    "SecretExposure":         "Secret Exposure",
    "PrivilegeTakeover":      "Privilege Takeover",
    "InfrastructureTakeover": "Infrastructure Takeover",
    "BusinessDisruption":     "Business Disruption",
    "ServiceControl":         "Service Control",
}

# entry_point_category → key in _ENTRY_BASE_P
_CAT_TO_EP_TYPE: Dict[str, str] = {
    "INTERNET_ENTRY":          "internet",
    "IDENTITY_ENTRY":          "identity",
    "CICD_ENTRY":              "cicd",
    "THIRD_PARTY_ENTRY":       "third_party",
    "INTERNAL_WORKLOAD_ENTRY": "compute",
    "ENDPOINT_AGENT_ENTRY":    "endpoint_agent",
}


def _compute_impact_type(
    crown_jewel_type: str,
    crown_jewel_uid: str,
    access_capability: str,
    posture_lookup: Dict[str, "PostureRow"],
) -> str:
    """Derive business impact type from technical crown jewel class and access capability.

    Rules (in priority order):
      1. EKS / K8s clusters: destructive capability → BusinessDisruption; else ServiceControl.
      2. crown_jewel_type lookup → _CJ_TYPE_TO_IMPACT.
      3. Default: DataExposure.
    """
    cj_type = (crown_jewel_type or "").lower()
    cap = (access_capability or "").lower()
    cp = posture_lookup.get(crown_jewel_uid or "")
    rtype = (cp.resource_type if cp else "").lower()

    if any(rtype.startswith(pfx) for pfx in _K8S_PREFIXES):
        return "BusinessDisruption" if cap in _DESTRUCTIVE_CAPS else "ServiceControl"

    return _CJ_TYPE_TO_IMPACT.get(cj_type, "DataExposure")


# ---------------------------------------------------------------------------
# Edge semantic probability boosts — applied when the outgoing edge from a hop
# is a confirmed permission/trust relationship rather than inferred topology.
# IAM and encryption edges carry higher certainty: the permission DOES exist (it
# was read from the IAM DB or encryption DB), so the attacker CAN traverse it.
# ---------------------------------------------------------------------------
_EDGE_SEMANTIC_BOOST: Dict[str, float] = {
    # Confirmed IAM trust — attacker who controls the source CAN assume the target role
    "assumes":               1.25,
    "can_assume":            1.25,
    # Explicit policy grant — confirmed resource-level permission
    "grants_access_to":      1.25,
    "can_access":            1.20,
    "has_policy":            1.20,
    # Identity chain hops
    "member_of":             1.10,
    "linked_to":             1.10,
    # KMS key grant → data_exfil is a confirmed decrypt path
    "grants_decrypt_to":     1.35,
    # Cross-account peering — direct network path exists
    "peered_with_external":  1.20,
    # Worker node → EKS cluster control plane
    "worker_node_of":        1.15,
    # Direct infrastructure attachment — confirmed physical data access
    "mounted_by":            1.10,
}


def probability_score(
    path: RawPath,
    posture_lookup: Dict[str, PostureRow],
    findings_lookup: Optional[Dict] = None,
) -> float:
    """Compute the probability dimension of the P×I score.

    Multipliers applied per hop in order:
      1. Base probability from entry point type.
      2. Per-hop posture signals: EPSS boosters, misconfig boosters, control discounts.
      3. Per-hop CDR signals from security_findings (threat_detections):
           - Any CDR detection on a hop → ×1.50 (active exploitation evidence)
           - MITRE tactic risk multiplier (Exfiltration → ×1.60, Lateral Movement → ×1.45, etc.)
      4. Clamp to [0.0001, 1.0].

    CDR/MITRE signals are folded into P directly — no separate confidence_level field.
    A path with active CDR detections will naturally score higher than a speculative path.

    Args:
        path:             RawPath from the Neo4j BFS.
        posture_lookup:   Pre-fetched posture signals keyed by resource_uid.
        findings_lookup:  security_findings grouped by resource_uid
                          {uid: {threat_detections: [...], misconfigs: [...], cves: [...]}}.
                          None-safe — scoring degrades gracefully to posture-only.

    Returns:
        float in (0, 1].  Never 0.0 — minimum is 0.0001.
    """
    findings_lookup = findings_lookup or {}

    # Step 1: Entry point base probability
    entry_uid = path.entry_point_uid or ""
    entry_posture = posture_lookup.get(entry_uid)
    entry_type = (entry_posture.entry_point_type if entry_posture else "") or ""

    # entry_point_category (set by pg_graph) takes priority for new entry types —
    # maps directly to the expanded _ENTRY_BASE_P keys.
    entry_cat = getattr(path, "entry_point_category", "") or ""
    if entry_cat and entry_cat in _CAT_TO_EP_TYPE:
        entry_type = _CAT_TO_EP_TYPE[entry_cat]
    elif not entry_type and path.node_types:
        entry_type = path.node_types[0]

    p = _ENTRY_BASE_P.get(entry_type.lower(), _DEFAULT_BASE_P)

    # Step 2+3+4: Per-hop loop — posture signals + CDR/MITRE signals + edge semantics
    edge_types = list(path.edge_types or [])

    for hop_idx, uid in enumerate(path.node_uids):
        posture = posture_lookup.get(uid)

        # ── Posture signals ────────────────────────────────────────────────
        if posture:
            # EPSS — CVE exploitability
            epss = posture.max_epss
            if epss is not None:
                if epss > 0.70:
                    p *= 1.15   # high-EPSS CVE on this hop raises exploitation likelihood
                elif epss >= 0.30:
                    p *= 1.08   # moderate EPSS

            # Misconfig severity
            if posture.critical_misconfig_count > 0:
                p *= 1.12
            elif posture.high_misconfig_count > 0:
                p *= 1.06

            # Security control discounts (defender presence lowers P)
            if posture.waf_protected:
                p *= 0.80
            if posture.mfa_required:
                p *= 0.50
            if posture.has_permission_boundary:
                p *= 0.70

        # ── CDR / MITRE signals from security_findings ────────────────────
        hop_findings = findings_lookup.get(uid, {})
        threat_detections = hop_findings.get("threat_detections", [])

        if threat_detections:
            # Any active CDR detection on this hop → strong evidence of exploitation
            p = min(1.0, p * 1.50)

            # Apply per-technique MITRE tactic boost (take the highest across detections)
            max_tactic_boost = 1.0
            for det in threat_detections:
                tactic = (det.get("mitre_tactic") or "").lower().replace("_", "-").replace(" ", "-")
                boost = _MITRE_TACTIC_BOOST.get(tactic, 1.10)
                if boost > max_tactic_boost:
                    max_tactic_boost = boost
            p = min(1.0, p * max_tactic_boost)

        # ── Edge semantic boost — outgoing edge from this hop ─────────────
        # edge_types[i] is the edge from node_uids[i] → node_uids[i+1].
        # IAM/encryption edges carry confirmed permissions (read from DB), so
        # the attacker CAN traverse them — no guessing needed.
        if hop_idx < len(edge_types):
            outgoing_edge = edge_types[hop_idx].lower()
            edge_boost = _EDGE_SEMANTIC_BOOST.get(outgoing_edge, 1.0)
            if edge_boost != 1.0:
                p = min(1.0, p * edge_boost)

    # Step 5: probability never reaches 0.0
    return max(0.0001, p)


def impact_score(path: RawPath, posture_lookup: Dict[str, PostureRow]) -> float:
    """Compute the impact dimension of the P×I score.

    Architecture doc section 5.3.

    Args:
        path:            RawPath from the Neo4j BFS.
        posture_lookup:  Pre-fetched posture signals keyed by resource_uid.

    Returns:
        float > 0.0.  May exceed 1.0 (final score is capped by min(100,...)).
    """
    crown_uid = path.crown_jewel_uid or ""
    crown_posture = posture_lookup.get(crown_uid)
    crown_type = (crown_posture.crown_jewel_type if crown_posture else "") or ""

    # Derive business impact type for richer weight lookup
    access_cap = path.edge_types[-1] if path.edge_types else ""
    impact_type = _compute_impact_type(crown_type, crown_uid, access_cap, posture_lookup)

    # Impact type weight takes precedence; fall back to technical crown_jewel_type weight
    i = _IMPACT_TYPE_WEIGHT.get(impact_type, _CJ_TYPE_IMPACT.get(crown_type, _DEFAULT_CJ_IMPACT))

    if crown_posture:
        # Data classification multiplier
        dc = crown_posture.data_classification or ""
        i *= _DATA_CLASS_MULT.get(dc, 1.0)

        # Blast radius multiplier (if > 50 resources reachable from crown jewel)
        if crown_posture.blast_radius_count > 50:
            i *= 1.30

        # Encryption gap multiplier
        enc = crown_posture.encryption_type or ""
        if enc.lower() in ("none", ""):
            i *= 1.10

    return max(0.0001, i)


def compute_path_score(p: float, i: float) -> int:
    """Compute final integer path score: round(min(100, P × I × 100))."""
    return round(min(100, p * i * 100))


def severity_bucket(score: int) -> str:
    """Map integer score to severity string.

    Returns:
        "CRITICAL" (>= 80), "HIGH" (60-79), "MEDIUM" (40-59), or "LOW" (< 40).
    """
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _chain_type(path: RawPath, posture_lookup: Dict[str, PostureRow]) -> str:
    """Build a human-readable chain type label like 'Identity → Secret Exposure'.

    Entry label priority:
      1. entry_point_category (set by pg_graph from attack_entry_point_category in posture)
      2. posture entry_point_type
      3. hop_categories[0] from BFS

    Crown label: business impact type derived from crown_jewel_type + access_capability.
    e.g., "Data Exposure", "Privilege Takeover", "Service Control".
    """
    entry_uid = path.entry_point_uid or ""
    ep = posture_lookup.get(entry_uid)

    # Priority 1: entry_point_category → ENTRY_CAT_LABELS
    entry_cat = getattr(path, "entry_point_category", "") or ""
    if entry_cat and entry_cat in _ENTRY_CAT_LABELS:
        entry_label = _ENTRY_CAT_LABELS[entry_cat]
    elif ep and ep.entry_point_type:
        entry_label = ep.entry_point_type.lower().capitalize()
    elif path.hop_categories:
        entry_label = path.hop_categories[0].capitalize()
    else:
        entry_label = "Unknown"

    # Crown label: business impact type
    crown_uid = path.crown_jewel_uid or ""
    cp = posture_lookup.get(crown_uid)
    crown_type = (cp.crown_jewel_type if cp else "") or ""
    access_cap = path.edge_types[-1] if path.edge_types else ""
    impact_type = _compute_impact_type(crown_type, crown_uid, access_cap, posture_lookup)
    crown_label = _IMPACT_TYPE_DISPLAY.get(impact_type, crown_type.replace("_", " ").title())

    return f"{entry_label} → {crown_label}"


def _derive_objective(
    crown_jewel_uid: str,
    cj_type: str,
    access_capability: str,
    posture_lookup: Dict[str, "PostureRow"],
    objective_catalog: Dict[str, Dict[str, Any]],
    fallback_table: Dict[tuple, Dict[str, str]],
) -> tuple:
    """Return (objective_type, objective_satisfied) for a path.

    Lookup order:
      1. objective_catalog keyed by (provider, resource_type) from posture_lookup.
      2. fallback_table keyed by (crown_jewel_type, access_capability).
      3. fallback_table keyed by (crown_jewel_type, '*') wildcard.
      4. Default: DATA_THEFT / None.

    objective_satisfied is True when the path's final edge capability matches
    the objective's required_capability, False when it does not (topology-only
    reach without the confirmatory credential edge).
    """
    cap_lower = (access_capability or "").lower()

    # Primary: catalog lookup by (provider, resource_type)
    cp = posture_lookup.get(crown_jewel_uid or "")
    if cp and objective_catalog:
        provider = (cp.resource_type.split(".")[0] if "." in (cp.resource_type or "") else "")
        # Try to extract provider from posture row — stored in resource_type prefix or uid prefix
        # Crown jewel uid format: arn:aws:... → provider='aws'; //gcp.com/... → provider='gcp'
        uid = crown_jewel_uid or ""
        if uid.startswith("arn:aws"):
            provider = "aws"
        elif uid.startswith("//"):
            provider = "gcp"
        elif "/subscriptions/" in uid:
            provider = "azure"
        elif "acs:" in uid or "aliyuncs" in uid:
            provider = "alicloud"
        elif "ocid1." in uid:
            provider = "oci"
        elif "crn:" in uid:
            provider = "ibm"

        rtype = (cp.resource_type or "").lower().replace(".", "_").replace("-", "_")
        catalog_key = (provider, rtype)
        if catalog_key in objective_catalog:
            entry = objective_catalog[catalog_key]
            obj_type = entry["objective_type"]
            req_cap  = entry["required_capability"]
            satisfied = cap_lower == req_cap.lower() if req_cap else None
            return obj_type, satisfied

    # Fallback: (crown_jewel_type, access_capability) exact match
    fb_key = (cj_type, cap_lower)
    if fb_key in fallback_table:
        entry = fallback_table[fb_key]
        satisfied = cap_lower == entry["required_capability"].lower()
        return entry["objective_type"], satisfied

    # Fallback wildcard: (crown_jewel_type, '*')
    fb_wild = (cj_type, "*")
    if fb_wild in fallback_table:
        entry = fallback_table[fb_wild]
        satisfied = cap_lower == entry["required_capability"].lower()
        return entry["objective_type"], satisfied

    return "DATA_THEFT", None


def score_paths(
    raw_paths: list,
    posture_lookup: Dict[str, PostureRow],
    findings_lookup: Optional[Dict] = None,
    objective_catalog: Optional[Dict[tuple, Dict[str, Any]]] = None,
    fallback_table: Optional[Dict[tuple, Dict[str, str]]] = None,
) -> list:
    """Score all raw paths and return a list of ScoredPath objects.

    Args:
        raw_paths:         RawPath objects from BFS.
        posture_lookup:    uid → PostureRow dict.
        findings_lookup:   uid → {misconfigs, cves, threat_detections}.
        objective_catalog: (provider, resource_type) → {objective_type, required_capability}.
                           Built from attack_objective_catalog table by run_scan.py.
        fallback_table:    (crown_jewel_type, access_capability|'*') → {objective_type, required_capability}.
                           Built from attack_objective_fallback table by run_scan.py.
    """
    findings_lookup  = findings_lookup  or {}
    objective_catalog = objective_catalog or {}
    fallback_table    = fallback_table    or {}
    scored = []

    for raw in raw_paths:
        p = probability_score(raw, posture_lookup, findings_lookup)
        i = impact_score(raw, posture_lookup)
        score = compute_path_score(p, i)
        sev = severity_bucket(score)
        chain = _chain_type(raw, posture_lookup)

        # Determine CDR presence for this path
        has_cdr = any(
            (posture_lookup.get(uid) or PostureRow()).has_active_cdr_actor
            for uid in raw.node_uids
        )

        # Data classification from crown jewel posture
        crown_uid = raw.crown_jewel_uid or ""
        cp = posture_lookup.get(crown_uid)
        data_class = cp.data_classification if cp else None

        # Derive entry_point_type: posture lookup first, fall back to hop_categories[0]
        ep_posture = posture_lookup.get(raw.entry_point_uid or "")
        ep_type = (ep_posture.entry_point_type if ep_posture else "") or (
            raw.hop_categories[0] if raw.hop_categories else ""
        )
        # Promote 'virtual' to 'internet' when the entry resource or its first real
        # hop is internet-exposed (handles Neo4j VirtualNode account/region origins).
        if not ep_type or ep_type == "virtual":
            if ep_posture and ep_posture.is_internet_exposed:
                ep_type = "internet"
            elif len(raw.node_uids) > 1:
                first_real = posture_lookup.get(raw.node_uids[1])
                if first_real and first_real.is_internet_exposed:
                    ep_type = "internet"

        # Derive crown_jewel_type from posture lookup
        cp2 = posture_lookup.get(raw.crown_jewel_uid or "")
        cj_type = (cp2.crown_jewel_type if cp2 else "") or ""

        # Derive business impact type for display and BFF grouping
        access_cap_raw = raw.edge_types[-1] if raw.edge_types else ""
        attack_impact_type = _compute_impact_type(
            cj_type, raw.crown_jewel_uid or "", access_cap_raw, posture_lookup
        )

        # Derive formal attack objective from catalog (OBJ-03)
        obj_type, obj_satisfied = _derive_objective(
            crown_uid, cj_type, access_cap_raw,
            posture_lookup, objective_catalog, fallback_table,
        )

        # OBJ-05: topology-only paths (objective_satisfied=False) get downgraded
        # to speculative confidence — they prove network reach but not the final
        # credential edge needed to complete the objective.
        sp = ScoredPath(
            **raw.model_dump(),
            probability_score=p,
            impact_score=i,
            path_score=score,
            severity=sev,
            chain_type=chain,
            entry_point_type=ep_type,
            crown_jewel_type=cj_type,
            data_classification=data_class,
            has_active_cdr_actor=has_cdr,
            attack_impact_type=attack_impact_type,
            objective_type=obj_type,
            objective_satisfied=obj_satisfied,
        )
        scored.append(sp)
    return scored
