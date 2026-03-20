"""BFF view: /threats/{threat_id} detail page.

Consolidates threat detail, affected assets, misconfig findings, and remediation
into a single UI-ready response.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_threat, _safe_lower

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _build_exposure(threat: dict) -> dict:
    """Derive exposure flags from threat data."""
    finding_data = threat.get("finding_data") or {}
    return {
        "internetExposed": bool(
            finding_data.get("internet_exposed")
            or threat.get("internet_exposed", False)
        ),
        "publicAccess": bool(
            finding_data.get("public_access")
            or threat.get("public_access", False)
        ),
        "trustExposure": bool(
            finding_data.get("trust_exposure")
            or threat.get("trust_exposure", False)
        ),
        "sensitiveData": bool(
            finding_data.get("sensitive_data")
            or threat.get("sensitive_data", False)
        ),
    }


def _build_mitre(threat: dict) -> dict:
    """Extract MITRE ATT&CK detail from a single threat."""
    finding_data = threat.get("finding_data") or {}
    techniques = threat.get("mitre_techniques") or finding_data.get("mitre_techniques") or []
    tactics = threat.get("mitre_tactics") or finding_data.get("mitre_tactics") or []

    tech_id = ""
    tech_name = ""
    if techniques:
        first = techniques[0]
        if isinstance(first, dict):
            tech_id = first.get("technique_id") or first.get("id", "")
            tech_name = first.get("technique_name") or first.get("name", tech_id)
        else:
            tech_id = str(first)
            tech_name = tech_id

    tactic_name = ""
    if tactics:
        first_t = tactics[0]
        if isinstance(first_t, dict):
            tactic_name = first_t.get("tactic_name") or first_t.get("name", "")
        else:
            tactic_name = str(first_t)

    return {
        "techniqueId": tech_id,
        "techniqueName": tech_name,
        "tacticName": tactic_name,
        "description": finding_data.get("mitre_description", ""),
        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/" if tech_id else "",
    }


def _build_attack_path(threat: dict) -> dict:
    """Extract attack path info if present in threat data."""
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


def _build_blast_radius(threat: dict) -> dict:
    """Derive blast radius from threat data."""
    blast = threat.get("blast_radius") or {}
    if isinstance(blast, dict):
        return {
            "reachableCount": blast.get("reachable_count") or blast.get("total", 0),
            "criticalCount": blast.get("critical_count", 0),
            "affectedServices": blast.get("affected_services", []),
        }
    return {"reachableCount": 0, "criticalCount": 0, "affectedServices": []}


def _build_timeline(threat: dict, normalized: dict) -> list:
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

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


@router.get("/threats/{threat_id}")
async def view_threat_detail(
    threat_id: str,
    tenant_id: str = Query(...),
):
    """BFF view for threat detail page — single endpoint for the entire page.

    Fans out to four engine endpoints in parallel and merges results into a
    single response containing the normalized threat, exposure flags, MITRE
    detail, affected resources, supporting misconfig findings, attack path,
    blast radius, remediation, and timeline.
    """

    results = await fetch_many([
        ("threat", f"/api/v1/threat/{threat_id}", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/assets", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/misconfig-findings", {"tenant_id": tenant_id}),
        ("threat", f"/api/v1/threat/{threat_id}/remediation", {"tenant_id": tenant_id}),
    ])

    threat_raw, assets_raw, misconfig_raw, remediation_raw = results

    # Safely handle None responses
    if not isinstance(threat_raw, dict):
        threat_raw = {}
    if not isinstance(assets_raw, (dict, list)):
        assets_raw = {}
    if not isinstance(misconfig_raw, (dict, list)):
        misconfig_raw = {}
    if not isinstance(remediation_raw, dict):
        remediation_raw = {}

    # Normalize the core threat
    normalized = normalize_threat(threat_raw)

    # Add extra detail fields
    normalized["description"] = threat_raw.get("description", "")
    normalized["resourceType"] = threat_raw.get("resource_type", "")
    normalized["resourceUid"] = threat_raw.get("resource_uid", "")
    normalized["lastSeen"] = threat_raw.get("last_seen_at") or threat_raw.get("updated_at")
    normalized["threatCategory"] = threat_raw.get("threat_category") or threat_raw.get("category", "")
    normalized["ruleId"] = threat_raw.get("rule_id", "")
    normalized["mitreTechnique"] = normalized.get("mitre_technique", "")
    normalized["mitreTactic"] = normalized.get("mitre_tactic", "")

    # Affected resources
    if isinstance(assets_raw, list):
        affected = assets_raw
    else:
        affected = safe_get(assets_raw, "assets", []) or safe_get(assets_raw, "resources", [])

    # Supporting misconfig findings
    if isinstance(misconfig_raw, list):
        supporting = misconfig_raw
    else:
        supporting = (
            safe_get(misconfig_raw, "findings", [])
            or safe_get(misconfig_raw, "misconfig_findings", [])
        )

    # Remediation
    rem_steps = (
        safe_get(remediation_raw, "steps", [])
        or safe_get(remediation_raw, "remediation_steps", [])
        or remediation_raw.get("remediation", [])
    )
    if isinstance(rem_steps, str):
        rem_steps = [rem_steps]
    sla = safe_get(remediation_raw, "sla", {})
    if not isinstance(sla, dict):
        sla = {}

    return {
        "threat": normalized,
        "exposure": _build_exposure(threat_raw),
        "mitre": _build_mitre(threat_raw),
        "affectedResources": affected,
        "supportingFindings": supporting,
        "attackPath": _build_attack_path(threat_raw),
        "blastRadius": _build_blast_radius(threat_raw),
        "remediation": {"steps": rem_steps, "sla": sla},
        "timeline": _build_timeline(threat_raw, normalized),
    }
