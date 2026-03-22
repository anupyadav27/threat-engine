"""BFF view: /threats/{threat_id} detail page.

Consolidates threat detail, affected assets, misconfig findings, analysis
(blast radius, attack chain, risk breakdown), and remediation into a single
UI-ready response.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_threat, _safe_lower

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _build_exposure(threat: dict, analysis: dict) -> dict:
    """Derive exposure flags from threat data and analysis.

    Merges the threat-level exposure signals with the analysis-computed
    risk breakdown (from threat_analysis table) so the UI gets richer
    exposure context.
    """
    finding_data = threat.get("finding_data") or {}
    risk_breakdown = analysis.get("risk_breakdown") or analysis.get("risk_factors") or {}

    internet_exposed = bool(
        finding_data.get("internet_exposed")
        or threat.get("internet_exposed", False)
        or risk_breakdown.get("internet_exposed", False)
    )
    public_access = bool(
        finding_data.get("public_access")
        or threat.get("public_access", False)
        or risk_breakdown.get("public_access", False)
    )

    # Build reasons from analysis risk_breakdown
    internet_reason = ""
    public_reason = ""
    if isinstance(risk_breakdown, dict):
        factors = risk_breakdown.get("factors") or risk_breakdown.get("risk_factors") or []
        if isinstance(factors, list):
            for f in factors:
                desc = f.get("description") or f.get("factor", "")
                if "internet" in desc.lower() or "exposed" in desc.lower():
                    internet_reason = desc
                elif "public" in desc.lower():
                    public_reason = desc

    return {
        "internetExposed": internet_exposed,
        "internetExposedReason": internet_reason,
        "publicAccess": public_access,
        "publicAccessReason": public_reason,
        "trustExposure": bool(
            finding_data.get("trust_exposure")
            or threat.get("trust_exposure", False)
        ),
        "sensitiveData": bool(
            finding_data.get("sensitive_data")
            or threat.get("sensitive_data", False)
        ),
        "riskScore": analysis.get("risk_score"),
        "verdict": analysis.get("verdict"),
        "riskBreakdown": risk_breakdown,
    }


def _build_mitre(threat: dict) -> dict:
    """Extract ALL MITRE ATT&CK techniques and tactics from a threat."""
    finding_data = threat.get("finding_data") or {}
    techniques = threat.get("mitre_techniques") or finding_data.get("mitre_techniques") or []
    tactics = threat.get("mitre_tactics") or finding_data.get("mitre_tactics") or []

    # Parse all techniques (not just the first)
    all_techniques = []
    for t in techniques:
        if isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id", "")
            tname = t.get("technique_name") or t.get("name", tid)
        else:
            tid = str(t)
            tname = tid
        if tid:
            all_techniques.append({
                "id": tid,
                "name": tname,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if tid else "",
            })

    # Parse all tactics
    all_tactics = []
    for t in tactics:
        if isinstance(t, dict):
            all_tactics.append(t.get("tactic_name") or t.get("name", ""))
        else:
            all_tactics.append(str(t))
    all_tactics = [t for t in all_tactics if t]

    # Primary technique/tactic for backwards compat
    tech_id = all_techniques[0]["id"] if all_techniques else ""
    tech_name = all_techniques[0]["name"] if all_techniques else ""
    tactic_name = all_tactics[0] if all_tactics else ""

    return {
        "techniqueId": tech_id,
        "techniqueName": tech_name,
        "tacticName": tactic_name,
        "description": finding_data.get("mitre_description", ""),
        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/" if tech_id else "",
        "allTechniques": all_techniques,
        "allTactics": all_tactics,
    }


def _build_attack_path(threat: dict, analysis: dict) -> dict:
    """Extract attack path info from threat data and analysis.

    Prefers the analysis attack_chain (from threat_analysis table) which
    contains the full computed chain.  Falls back to threat-level fields.
    """
    # Try analysis attack_chain first (JSONB from threat_analysis)
    attack_chain = analysis.get("attack_chain")
    if attack_chain:
        if isinstance(attack_chain, list):
            return {"exists": True, "steps": attack_chain}
        if isinstance(attack_chain, dict):
            steps = attack_chain.get("steps") or attack_chain.get("chain", [])
            return {"exists": bool(steps), "steps": steps}

    # Fallback to threat-level data
    attack_path = threat.get("attack_path") or threat.get("attack_paths") or {}
    if isinstance(attack_path, list):
        steps = attack_path
        exists = bool(steps)
    elif isinstance(attack_path, dict):
        steps = attack_path.get("steps", [])
        exists = attack_path.get("exists", bool(steps))
    else:
        steps = []
        exists = False
    return {"exists": exists, "steps": steps}


def _build_blast_radius(threat: dict, analysis: dict) -> dict:
    """Derive blast radius from analysis data or threat data.

    The analysis endpoint returns blast_radius as JSONB with:
    reachable_count, critical_assets, affected_services.
    """
    # Prefer analysis blast_radius (from threat_analysis table)
    blast = analysis.get("blast_radius")
    if blast and isinstance(blast, dict):
        return {
            "reachableCount": (
                blast.get("reachable_count")
                or blast.get("total", 0)
            ),
            "criticalCount": (
                blast.get("critical_count")
                or len(blast.get("critical_assets", []))
            ),
            "criticalAssets": blast.get("critical_assets", []),
            "affectedServices": blast.get("affected_services", []),
        }

    # Fallback to threat-level blast_radius
    blast = threat.get("blast_radius") or {}
    if isinstance(blast, dict):
        return {
            "reachableCount": blast.get("reachable_count") or blast.get("total", 0),
            "criticalCount": blast.get("critical_count", 0),
            "criticalAssets": blast.get("critical_assets", []),
            "affectedServices": blast.get("affected_services", []),
        }
    return {"reachableCount": 0, "criticalCount": 0, "criticalAssets": [], "affectedServices": []}


def _build_risk_breakdown(analysis: dict) -> dict:
    """Extract risk score breakdown from analysis data."""
    if not analysis:
        return {}
    risk_score = analysis.get("risk_score")
    risk_breakdown = analysis.get("risk_breakdown") or analysis.get("risk_factors") or {}
    return {
        "score": risk_score,
        "breakdown": risk_breakdown,
    }


def _build_evidence(threat: dict) -> list:
    """Extract evidence entries from threat detection data."""
    evidence = threat.get("evidence")
    if evidence is None:
        return []
    if isinstance(evidence, list):
        return evidence
    if isinstance(evidence, dict):
        # Single evidence object -> wrap in list
        return [evidence]
    return []


def _build_timeline(threat: dict, normalized: dict, analysis: dict) -> list:
    """Build a synthetic timeline from available timestamps."""
    events = []
    detected = normalized.get("detected") or threat.get("detected_at") or threat.get("first_seen_at")
    last_seen = normalized.get("lastSeen") or threat.get("last_seen_at")
    created = threat.get("created_at")

    if detected:
        events.append({"timestamp": detected, "event": "Threat detected", "type": "detection"})
    if created and created != detected:
        events.append({"timestamp": created, "event": "Finding created", "type": "creation"})
    if last_seen and last_seen != detected:
        events.append({"timestamp": last_seen, "event": "Last observed", "type": "observation"})

    # Add analysis timestamps if available
    analysis_created = analysis.get("created_at") or analysis.get("analyzed_at")
    if analysis_created and analysis_created not in (detected, created, last_seen):
        events.append({"timestamp": analysis_created, "event": "Analysis completed", "type": "analysis"})

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


@router.get("/threats/{threat_id}")
async def view_threat_detail(
    threat_id: str,
    tenant_id: str = Query(...),
):
    """BFF view for threat detail page — single endpoint for the entire page.

    Fans out to five engine endpoints in parallel and merges results into a
    single response containing the normalized threat, exposure flags, MITRE
    detail, affected resources, supporting misconfig findings, attack path,
    blast radius, risk breakdown, evidence, remediation, and timeline.
    """

    results = await fetch_many([
        ("threat", f"/api/v1/threat/threats/{threat_id}", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/analysis/{threat_id}", {"tenant_id": tenant_id}),
        # Use the new detection-aware endpoint that cross-queries the check DB
        ("threat", f"/api/v1/threat/detections/{threat_id}/check-findings", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/remediation", {"tenant_id": tenant_id}),
    ])

    threat_raw, analysis_raw, misconfig_raw, remediation_raw = results

    # Safely handle None responses
    if not isinstance(threat_raw, dict):
        threat_raw = {}
    if not isinstance(analysis_raw, dict):
        analysis_raw = {}
    if not isinstance(misconfig_raw, (dict, list)):
        misconfig_raw = {}
    if not isinstance(remediation_raw, dict):
        remediation_raw = {}

    # Normalize the core threat (from threat_detections table)
    normalized = normalize_threat(threat_raw)

    # Add extra detail fields from detection data
    normalized["description"] = threat_raw.get("description", "")
    normalized["resourceType"] = threat_raw.get("resource_type", "")
    normalized["resourceUid"] = threat_raw.get("resource_uid", "")
    normalized["lastSeen"] = threat_raw.get("last_seen_at") or threat_raw.get("updated_at")
    normalized["threatCategory"] = threat_raw.get("threat_category") or threat_raw.get("category", "")
    normalized["ruleId"] = threat_raw.get("rule_id", "")
    normalized["mitreTechnique"] = normalized.get("mitre_technique", "")
    normalized["mitreTactic"] = normalized.get("mitre_tactic", "")
    normalized["context"] = threat_raw.get("context") or {}

    # Override risk score with analysis-computed score if available
    analysis_risk = analysis_raw.get("risk_score")
    if analysis_risk is not None:
        normalized["riskScore"] = analysis_risk
        normalized["risk_score"] = analysis_risk

    # Merge analysis recommendations into normalized threat
    analysis_recs = analysis_raw.get("recommendations") or []
    if analysis_recs:
        normalized["recommendations"] = analysis_recs
        normalized["remediationSteps"] = analysis_recs

    # Supporting check findings (from new detection-aware endpoint)
    if isinstance(misconfig_raw, list):
        supporting = misconfig_raw
    else:
        supporting = (
            safe_get(misconfig_raw, "findings", [])
            or safe_get(misconfig_raw, "misconfig_findings", [])
        )

    # Remediation — merge engine remediation with analysis recommendations
    rem_steps = (
        safe_get(remediation_raw, "steps", [])
        or safe_get(remediation_raw, "remediation_steps", [])
        or remediation_raw.get("remediation", [])
    )
    if isinstance(rem_steps, str):
        rem_steps = [rem_steps]
    # Append analysis recommendations if remediation endpoint returned nothing
    if not rem_steps and analysis_recs:
        rem_steps = analysis_recs
    sla = safe_get(remediation_raw, "sla", {})
    if not isinstance(sla, dict):
        sla = {}

    # Affected resources — from evidence, analysis, or the threat's own resource
    affected = []
    evidence_data = threat_raw.get("evidence") or {}
    if isinstance(evidence_data, dict):
        affected = evidence_data.get("affected_assets", [])
    # Also check analysis for affected resources
    if not affected:
        analysis_blast = analysis_raw.get("blast_radius") or {}
        if isinstance(analysis_blast, dict):
            affected = analysis_blast.get("critical_assets", [])
    # If still empty, build a minimal entry from the threat's own resource
    if not affected and threat_raw.get("resource_uid"):
        affected = [{
            "resource_uid": threat_raw.get("resource_uid", ""),
            "resource_type": threat_raw.get("resource_type", ""),
            "resource_id": threat_raw.get("resource_id", ""),
            "account_id": threat_raw.get("account_id", ""),
            "region": threat_raw.get("region", ""),
        }]

    return {
        "threat": normalized,
        "exposure": _build_exposure(threat_raw, analysis_raw),
        "mitre": _build_mitre(threat_raw),
        "evidence": _build_evidence(threat_raw),
        "affectedResources": affected,
        "supportingFindings": supporting,
        "attackPath": _build_attack_path(threat_raw, analysis_raw),
        "blastRadius": _build_blast_radius(threat_raw, analysis_raw),
        "riskBreakdown": _build_risk_breakdown(analysis_raw),
        "remediation": {"steps": rem_steps, "sla": sla},
        "timeline": _build_timeline(threat_raw, normalized, analysis_raw),
    }
