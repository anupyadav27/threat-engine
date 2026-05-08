"""BFF view: GET /api/v1/views/threat-scenario/{scenario_id}

Scenario Detail Panel — fans out to threat engine (primary + analysis +
check-findings + remediation) and risk engine in parallel, then reshapes
into the 4-chapter narrative structure consumed by ScenarioDetailPanel.jsx.

Security (STRIDE / OWASP SAMM):
  - scenario_id is validated as alphanumeric + hyphens (no path traversal)
  - X-Auth-Context forwarded verbatim to every upstream call
  - credential_ref is explicitly stripped from all contributing findings
  - threats:read permission enforced at the gateway middleware layer

Endpoint:
    GET /api/v1/views/threat-scenario/{scenario_id}
    Query params: tenant_id (required)
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from ._auth import resolve_tenant_id
from ._cache import TTL_THREATS, auth_level_from_header, cache_key, cached_view
from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Input validation ──────────────────────────────────────────────────────────

_SCENARIO_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


def _validate_scenario_id(scenario_id: str) -> None:
    """Reject scenario_id values that are not safe path segments.

    Raises HTTP 400 if scenario_id contains characters that could enable
    path traversal or injection (OWASP: Input Validation).
    """
    if not _SCENARIO_ID_RE.match(scenario_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid scenario_id format. Must be alphanumeric with hyphens/underscores only.",
        )


# ── Normalisation helpers ─────────────────────────────────────────────────────

_SIGNAL_ORDER = ["misconfig", "identity", "vulnerability", "network", "ai_security"]

_SIGNAL_FROM_CATEGORY: Dict[str, str] = {
    "IAMCredentialExposure": "identity",
    "ExcessivePermissions": "identity",
    "DataExposure": "misconfig",
    "PublicAccess": "misconfig",
    "NetworkExposure": "network",
    "VulnerabilityExploit": "vulnerability",
    "AIModelRisk": "ai_security",
}


def _human_age(ts: Optional[str]) -> str:
    """Return a human-readable time distance from an ISO timestamp."""
    if not ts:
        return "—"
    try:
        then = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = int((now - then).total_seconds())
        if diff < 60:
            return "just now"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"
    except Exception:
        return "—"


def _normalise_mitre(raw: Any) -> List[Dict[str, str]]:
    """Normalise mitre_techniques to [{id, name, url}] form."""
    if not raw:
        return []
    out = []
    for t in (raw if isinstance(raw, list) else []):
        if isinstance(t, str):
            out.append(
                {
                    "id": t,
                    "name": "",
                    "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/" if t else "",
                }
            )
        elif isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id") or ""
            tname = t.get("name") or t.get("technique_name") or tid
            out.append(
                {
                    "id": tid,
                    "name": tname,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if tid else "",
                }
            )
    return [r for r in out if r["id"]]


def _strip_credential_ref(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Remove credential_ref from a finding dict (STRIDE: Info Disclosure)."""
    cleaned = {k: v for k, v in finding.items() if k != "credential_ref"}
    return cleaned


def _derive_signal_type(finding: Dict[str, Any]) -> str:
    """Derive signal_type from finding fields."""
    # Explicit field first
    st = finding.get("signal_type") or finding.get("finding_type") or ""
    if st in _SIGNAL_ORDER:
        return st
    # Fallback from threat_category
    cat = finding.get("threat_category") or finding.get("category") or ""
    return _SIGNAL_FROM_CATEGORY.get(cat, "misconfig")


def _build_contributing_findings(raw_findings: Any) -> List[Dict[str, Any]]:
    """
    Reshape raw check/threat findings into the contributing_findings schema.

    Strips credential_ref from every finding.  Orders by signal type priority.
    """
    if isinstance(raw_findings, dict):
        items = (
            raw_findings.get("findings")
            or raw_findings.get("check_findings")
            or raw_findings.get("supporting_findings")
            or []
        )
    elif isinstance(raw_findings, list):
        items = raw_findings
    else:
        items = []

    results = []
    for f in items:
        if not isinstance(f, dict):
            continue
        f = _strip_credential_ref(f)
        signal_type = _derive_signal_type(f)

        finding_id = (
            f.get("finding_id")
            or f.get("id")
            or f.get("check_finding_id")
            or ""
        )

        mitre_raw = f.get("mitre_technique") or f.get("mitre_techniques") or []
        if isinstance(mitre_raw, str):
            mitre_raw = [mitre_raw]
        mitre_list = _normalise_mitre(mitre_raw)
        mitre_obj = mitre_list[0] if mitre_list else None

        results.append(
            {
                "finding_id": finding_id,
                "signal_type": signal_type,
                "rule_id": f.get("rule_id") or f.get("check_id") or "",
                "rule_name": f.get("rule_name") or f.get("check_name") or f.get("title") or "",
                "cve_id": f.get("cve_id") or f.get("cve") or None,
                "resource_name": (
                    f.get("resource_name")
                    or (f.get("resource_uid") or "").split("/")[-1].split(":")[-1]
                    or ""
                ),
                "resource_type": f.get("resource_type") or "",
                "severity": (f.get("severity") or "medium").lower(),
                "mitre_technique": mitre_obj,
                "plain_english": (
                    f.get("plain_english")
                    or f.get("description")
                    or f.get("rationale")
                    or ""
                ),
                "raw_evidence": f.get("raw_evidence") or f.get("evidence") or f.get("context") or {},
                "fix_guidance": (
                    f.get("fix_guidance")
                    or f.get("remediation")
                    or f.get("recommendation")
                    or ""
                ),
                "first_seen_at": f.get("first_seen_at") or f.get("detected_at") or "",
                "permissions_used": f.get("permissions_used"),
                "permissions_granted": f.get("permissions_granted"),
                "exploit_availability": f.get("exploit_availability"),
            }
        )

    # Sort by signal type priority
    order = {st: i for i, st in enumerate(_SIGNAL_ORDER)}
    results.sort(key=lambda r: order.get(r["signal_type"], 99))
    return results


def _build_blast_radius(threat_raw: Dict, risk_raw: Any) -> Dict[str, Any]:
    """
    Build the blast_radius sub-object for the panel.

    Prefers risk engine data; falls back to threat analysis blast_radius.
    """
    # Try risk engine response
    if isinstance(risk_raw, dict):
        br = risk_raw.get("blast_radius") or risk_raw
        if isinstance(br, dict) and br.get("root_node"):
            return {
                "root_node": br.get("root_node") or {},
                "first_hop": br.get("first_hop") or [],
                "second_hop": br.get("second_hop") or [],
                "third_hop_count": br.get("third_hop_count") or 0,
            }

    # Fallback: build minimal from threat data
    resource_uid = threat_raw.get("resource_uid") or ""
    resource_type = threat_raw.get("resource_type") or ""
    data_class = ""
    evidence = threat_raw.get("evidence") or {}
    if isinstance(evidence, dict):
        data_class = evidence.get("data_classification") or evidence.get("data_class") or ""

    return {
        "root_node": {
            "resource_uid": resource_uid,
            "resource_type": resource_type,
            "data_class": data_class,
        },
        "first_hop": [],
        "second_hop": [],
        "third_hop_count": 0,
    }


def _build_compliance_violations(threat_raw: Dict, analysis_raw: Dict) -> List[Dict]:
    """Extract compliance violations from threat/analysis data."""
    violations = (
        analysis_raw.get("compliance_violations")
        or analysis_raw.get("compliance_impacts")
        or threat_raw.get("compliance_violations")
        or threat_raw.get("compliance_impact")
        or []
    )
    if not isinstance(violations, list):
        return []
    result = []
    for v in violations:
        if isinstance(v, dict):
            result.append(
                {
                    "framework": v.get("framework") or v.get("framework_name") or "",
                    "control_id": v.get("control_id") or v.get("control") or "",
                    "description": v.get("description") or v.get("requirement") or "",
                }
            )
    return result


def _build_remediation_actions(remediation_raw: Dict, analysis_raw: Dict) -> List[Dict]:
    """Build structured remediation_actions from engine response."""
    steps = (
        safe_get(remediation_raw, "steps")
        or safe_get(remediation_raw, "remediation_steps")
        or remediation_raw.get("remediation")
        or analysis_raw.get("recommendations")
        or []
    )
    if isinstance(steps, str):
        steps = [steps]
    if not isinstance(steps, list):
        return []

    out = []
    for i, step in enumerate(steps):
        if isinstance(step, str):
            out.append(
                {
                    "step": i + 1,
                    "urgency": "immediate" if i == 0 else "short_term",
                    "description": step,
                    "owner": "Cloud Ops",
                    "effort": "Medium",
                    "effort_time": "—",
                    "impact": "",
                    "ai_fix_available": False,
                }
            )
        elif isinstance(step, dict):
            out.append(
                {
                    "step": i + 1,
                    "urgency": step.get("urgency") or ("immediate" if i == 0 else "short_term"),
                    "description": step.get("description") or step.get("step") or step.get("action") or "",
                    "owner": step.get("owner") or step.get("responsible_team") or "Cloud Ops",
                    "effort": step.get("effort") or step.get("complexity") or "Medium",
                    "effort_time": step.get("effort_time") or step.get("time_estimate") or "—",
                    "impact": step.get("impact") or step.get("effect") or "",
                    "ai_fix_available": bool(step.get("ai_fix_available") or step.get("has_ai_fix")),
                }
            )
    return out


def _build_resource_metadata(threat_raw: Dict) -> Dict[str, Any]:
    """Build resource_metadata sub-object."""
    resource_uid = threat_raw.get("resource_uid") or ""
    resource_name = (
        threat_raw.get("resource_name")
        or resource_uid.split("/")[-1].split(":")[-1]
        or resource_uid
    )
    finding_data = threat_raw.get("finding_data") or {}
    evidence = threat_raw.get("evidence") or {}
    if isinstance(evidence, str):
        evidence = {}

    tags = (
        finding_data.get("tags")
        or evidence.get("tags")
        or threat_raw.get("tags")
        or {}
    )
    data_classification = (
        finding_data.get("data_classification")
        or evidence.get("data_classification")
        or threat_raw.get("data_classification")
        or []
    )
    if isinstance(data_classification, str):
        data_classification = [data_classification] if data_classification else []

    return {
        "name": resource_name,
        "type": threat_raw.get("resource_type") or "",
        "region": threat_raw.get("region") or "",
        "account_id": threat_raw.get("account_id") or "",
        "tags": tags if isinstance(tags, dict) else {},
        "data_classification": data_classification,
        "estimated_record_count": (
            finding_data.get("estimated_record_count")
            or evidence.get("estimated_record_count")
            or None
        ),
    }


# ── Main endpoint ─────────────────────────────────────────────────────────────


@router.get("/threat-scenario/{scenario_id}")
async def view_threat_scenario_detail(
    request: Request,
    scenario_id: str,
) -> Dict[str, Any]:
    """BFF view for the Scenario Detail Panel drawer.

    Fans out to five engine endpoints in parallel:
      1. threat/threats/{id}          — core detection + narrative columns
      2. threat/analysis/{id}         — blast radius, risk breakdown, attack chain
      3. threat/detections/{id}/check-findings — contributing check findings
      4. threat/{id}/remediation      — remediation steps
      5. risk/scenarios/{id}          — blast radius graph data

    Returns a single response shaped for the 4-chapter drawer:
      Setup → Anatomy → Stakes → Response

    Security:
      - scenario_id validated against safe-character pattern (OWASP Input Validation)
      - X-Auth-Context forwarded verbatim to all upstream calls (STRIDE: Spoofing)
      - credential_ref stripped from all contributing findings (STRIDE: Info Disclosure)
      - threats:read permission required (enforced by gateway middleware)

    Args:
        request: FastAPI request (used to extract auth header)
        scenario_id: Threat detection ID (alphanumeric + hyphens/underscores)

    Returns:
        Dict containing scenario detail in the 4-chapter narrative shape.

    Raises:
        HTTPException 400: If scenario_id fails validation
    """
    _validate_scenario_id(scenario_id)
    tenant_id = resolve_tenant_id(request)

    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key(
        "threat-scenario-detail",
        tenant_id,
        scenario_id,
        role_level=role_level,
    )
    cached = cached_view(ck)
    if cached is not None:
        return cached

    params = {"tenant_id": tenant_id}

    results = await fetch_many(
        [
            ("threat", f"/api/v1/threat/threats/{scenario_id}", params),
            ("threat", f"/api/v1/threat/analysis/{scenario_id}", params),
            ("threat", f"/api/v1/threat/detections/{scenario_id}/check-findings", params),
            ("threat", f"/api/v1/threat/{scenario_id}/remediation", params),
            ("risk",   f"/api/v1/risk/scenarios/{scenario_id}", params),
        ],
        auth_headers=fwd_headers,
    )

    threat_raw, analysis_raw, findings_raw, remediation_raw, risk_raw = results

    # Normalise None responses
    if not isinstance(threat_raw, dict):
        threat_raw = {}
    if not isinstance(analysis_raw, dict):
        analysis_raw = {}
    if not isinstance(findings_raw, (dict, list)):
        findings_raw = {}
    if not isinstance(remediation_raw, dict):
        remediation_raw = {}
    # risk_raw may be None or dict

    # ── Core fields ────────────────────────────────────────────────────────
    resource_uid = threat_raw.get("resource_uid") or ""
    resource_name = (
        threat_raw.get("resource_name")
        or resource_uid.split("/")[-1].split(":")[-1]
        or resource_uid
    )
    raw_sev = (threat_raw.get("severity") or "medium").lower()
    raw_score = (
        analysis_raw.get("risk_score")
        or threat_raw.get("risk_score")
        or threat_raw.get("riskScore")
        or 0
    )

    # ── Narrative columns (written by THREAT-UI-04 narrative engine) ──────
    chain_of_consequence = threat_raw.get("chain_of_consequence") or ""
    stakes_narrative = threat_raw.get("stakes_narrative") or ""
    # Normalise None to empty string so frontend always gets a string
    chain_of_consequence = chain_of_consequence if isinstance(chain_of_consequence, str) else ""
    stakes_narrative = stakes_narrative if isinstance(stakes_narrative, str) else ""

    # ── MITRE techniques ───────────────────────────────────────────────────
    raw_mitre = (
        threat_raw.get("mitre_techniques")
        or threat_raw.get("mitreTechniques")
        or analysis_raw.get("mitre_techniques")
        or []
    )
    mitre_techniques = _normalise_mitre(raw_mitre)

    # ── Signal types from threat_category ─────────────────────────────────
    threat_category = threat_raw.get("threat_category") or threat_raw.get("category") or ""
    signal_types = [_SIGNAL_FROM_CATEGORY.get(threat_category, "misconfig")]

    # ── Contributing findings (sorted, credential_ref stripped) ───────────
    contributing_findings = _build_contributing_findings(findings_raw)

    # Augment signal_types from findings
    for f in contributing_findings:
        st = f.get("signal_type")
        if st and st not in signal_types:
            signal_types.append(st)

    # ── Blast radius ───────────────────────────────────────────────────────
    blast_radius = _build_blast_radius(threat_raw, risk_raw)

    # ── Compliance violations ──────────────────────────────────────────────
    compliance_violations = _build_compliance_violations(threat_raw, analysis_raw)

    # ── Remediation actions ────────────────────────────────────────────────
    remediation_actions = _build_remediation_actions(remediation_raw, analysis_raw)

    # ── Resource metadata ──────────────────────────────────────────────────
    resource_metadata = _build_resource_metadata(threat_raw)

    # ── Timestamps ────────────────────────────────────────────────────────
    first_seen_at = (
        threat_raw.get("first_seen_at")
        or threat_raw.get("detected_at")
        or threat_raw.get("detected")
        or ""
    )
    scan_age = _human_age(
        threat_raw.get("last_seen_at") or threat_raw.get("updated_at") or first_seen_at
    )

    # ── Assemble response (no credential_ref anywhere) ────────────────────
    result = {
        "scenario_id": scenario_id,
        "title": (
            threat_raw.get("description")
            or threat_raw.get("title")
            or f"Threat scenario on {resource_name}"
        ),
        "severity": raw_sev,
        "risk_score": int(raw_score),
        "resource_uid": resource_uid,
        "resource_name": resource_name,
        "resource_type": threat_raw.get("resource_type") or "",
        "csp": (threat_raw.get("csp") or threat_raw.get("provider") or "").lower(),
        "region": threat_raw.get("region") or "",
        "account_id": threat_raw.get("account_id") or "",
        "signal_types": signal_types,
        "mitre_techniques": mitre_techniques,
        "chain_of_consequence": chain_of_consequence,
        "stakes_narrative": stakes_narrative,
        "contributing_findings": contributing_findings,
        "blast_radius": blast_radius,
        "compliance_violations": compliance_violations,
        "remediation_actions": remediation_actions,
        "resource_metadata": resource_metadata,
        "first_seen_at": first_seen_at,
        "scan_age": scan_age,
    }

    cached_view(ck, result, ttl=TTL_THREATS)
    return result
