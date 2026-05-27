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
from typing import Dict, Optional

from ..models.attack_path import PostureRow, RawPath, ScoredPath

logger = logging.getLogger("attack-path.scorer")

# ---------------------------------------------------------------------------
# Entry point base probabilities (architecture doc section 5.2)
# ---------------------------------------------------------------------------
_ENTRY_BASE_P: Dict[str, float] = {
    "internet":     0.90,
    "onprem":       0.70,
    "datacenter":   0.70,
    "vpn":          0.60,
    "vendor":       0.50,
    "k8s_external": 0.50,
    "peer_account": 0.40,
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
    if not entry_type and path.node_types:
        entry_type = path.node_types[0]
    p = _ENTRY_BASE_P.get(entry_type.lower(), _DEFAULT_BASE_P)

    # Step 2+3: Per-hop loop — posture signals + CDR/MITRE signals
    for uid in path.node_uids:
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

    # Step 4: probability never reaches 0.0
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

    # Crown jewel type base impact
    crown_type = (crown_posture.crown_jewel_type if crown_posture else "") or ""
    i = _CJ_TYPE_IMPACT.get(crown_type, _DEFAULT_CJ_IMPACT)

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
        "critical" (>= 80), "high" (60-79), "medium" (40-59), or "low" (< 40).
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _chain_type(path: RawPath, posture_lookup: Dict[str, PostureRow]) -> str:
    """Build a human-readable chain type label like 'Internet → Data'.

    Entry label priority: posture entry_point_type → hop_categories[0] from BFS.
    hop_categories[0] is derived by the BFS Cypher from node labels (internet/virtual/compute)
    and is always more accurate than node_types[0] (which gives raw class names like VirtualNode).

    Crown label: posture crown_jewel_type only — no fallback. If the crown jewel
    is not in posture_lookup the label is left empty so chain_type shows the gap
    rather than masking it with a misleading default like "Asset".
    """
    entry_uid = path.entry_point_uid or ""
    ep = posture_lookup.get(entry_uid)
    if ep and ep.entry_point_type:
        entry_label = ep.entry_point_type.lower().capitalize()
    elif path.hop_categories:
        entry_label = path.hop_categories[0].capitalize()
    else:
        entry_label = "Unknown"

    crown_uid = path.crown_jewel_uid or ""
    cp = posture_lookup.get(crown_uid)
    crown_label = (cp.crown_jewel_type or "").replace("_", " ").title() if cp else ""

    return f"{entry_label} → {crown_label}"


def score_paths(
    raw_paths: list,
    posture_lookup: Dict[str, PostureRow],
    findings_lookup: Optional[Dict] = None,
) -> list:
    """Score all raw paths and return a list of ScoredPath objects."""
    findings_lookup = findings_lookup or {}
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
        )
        scored.append(sp)
    return scored
