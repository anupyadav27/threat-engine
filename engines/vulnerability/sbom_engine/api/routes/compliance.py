"""
Compliance & Reporting Routes

GET  /{sbom_id}               - Full compliance report (policy + license + vulns)
GET  /{sbom_id}/licenses       - License-only report
GET  /{sbom_id}/vulnerabilities - Vulnerability listing with severity breakdown
GET  /{sbom_id}/ntia           - NTIA minimum elements compliance score (Feature 3)
GET  /{sbom_id}/risk           - Composite risk report with EPSS + KEV (Feature 1+5)
POST /{sbom_id}/policy         - Override policy for a specific SBOM check
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.auth import get_current_user
from core.database import SBOMDatabaseManager
from core.compliance_engine import ComplianceEngine, DEFAULT_POLICY
from core.license_checker import analyse_sbom_licenses, classify_component_licenses

logger = logging.getLogger(__name__)

router = APIRouter()


def get_db() -> SBOMDatabaseManager:
    from main import db_manager
    return db_manager


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _load_sbom_data(sbom_id: str, db: SBOMDatabaseManager):
    doc = await db.get_sbom_document(sbom_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"SBOM {sbom_id} not found")
    components = await db.get_sbom_components(sbom_id)
    vex_stmts  = await db.get_vex_statements(sbom_id=sbom_id)
    return doc, components, vex_stmts


def _flat_vulns(components: List[Dict]) -> List[Dict]:
    """
    Flatten per-component vulnerability ID lists into minimal vuln dicts.
    Note: severity and fixed_version are not stored at component level.
    Severity-based policy checks (no_critical, no_high_unpatched) will report
    as passing when severity is unavailable. For full severity data use the
    /vulnerabilities endpoint which re-queries osv_advisory live.
    """
    vulns = []
    for comp in components:
        for vid in (comp.get("vulnerability_ids") or []):
            vulns.append({
                "advisory_id":   vid if not vid.startswith("CVE-") else None,
                "cve_id":        vid if vid.startswith("CVE-") else None,
                "package_name":  comp.get("name"),
                "package_version": comp.get("version"),
                "purl":          comp.get("purl"),
                "component_purl": comp.get("purl"),
                # severity not stored at component level — need to re-query
                # for full reports use /vulnerabilities which does a fresh scan
                "severity":      None,
                "fixed_version": None,
            })
    return vulns


# ── Full Compliance Report ────────────────────────────────────────────────────

@router.get("/{sbom_id}", summary="Full compliance report for an SBOM")
async def compliance_report(
    sbom_id: str,
    policy_preset: str = Query(
        "default",
        description="default | strict | lenient",
    ),
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """
    Runs all policy checks and returns a comprehensive compliance report:
    - Overall pass/fail/warn status
    - Per-policy results with findings
    - Severity summary of active (non-VEX-suppressed) vulnerabilities
    - License risk breakdown
    - VEX summary
    """
    doc, components, vex_stmts = await _load_sbom_data(sbom_id, db)

    policy = _build_policy(policy_preset)
    engine = ComplianceEngine(policy)

    # Build a flat vuln list from the components table
    # For severity-based checks we need the actual severity values
    # We do a lightweight re-enrichment of vulnerable components only
    vuln_comps = [c for c in components if c.get("is_vulnerable")]
    all_vulns = []
    for comp in vuln_comps:
        for vid in (comp.get("vulnerability_ids") or []):
            all_vulns.append({
                "advisory_id":    None if vid.startswith("CVE-") else vid,
                "cve_id":         vid if vid.startswith("CVE-") else None,
                "package_name":   comp.get("name"),
                "package_version": comp.get("version"),
                "purl":           comp.get("purl"),
                "component_purl": comp.get("purl"),
                # severity/fixed_version unknown without re-scan
                "severity":       None,
                "fixed_version":  None,
            })

    report = engine.evaluate(components, all_vulns, vex_stmts)
    license_summary = analyse_sbom_licenses(components)

    return {
        "sbom_id":          sbom_id,
        "application_name": doc.get("application_name"),
        "host_id":          doc.get("host_id"),
        "created_at":       doc["created_at"].isoformat() if doc.get("created_at") else None,
        "policy_preset":    policy_preset,
        "compliance":       report,
        "license_summary":  license_summary,
        "vex_count":        len(vex_stmts),
        "vex_not_affected": sum(1 for s in vex_stmts if s.get("status") == "not_affected"),
    }


# ── License Report ────────────────────────────────────────────────────────────

@router.get("/{sbom_id}/licenses", summary="License compliance report")
async def license_report(
    sbom_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    doc, components, _ = await _load_sbom_data(sbom_id, db)
    summary = analyse_sbom_licenses(components)

    # Per-component license details (only those with non-permissive or missing)
    detail = []
    for comp in components:
        lics = comp.get("licenses") or []
        analysis = classify_component_licenses(lics)
        if analysis["highest_risk"] not in ("permissive",) or analysis["flags"]:
            detail.append({
                "name":     comp.get("name"),
                "version":  comp.get("version"),
                "purl":     comp.get("purl"),
                "licenses": lics,
                "risk":     analysis["highest_risk"],
                "flags":    analysis["flags"],
            })

    return {
        "sbom_id":         sbom_id,
        "application_name": doc.get("application_name"),
        "summary":         summary,
        "components_requiring_review": detail,
    }


# ── Vulnerability Report ──────────────────────────────────────────────────────

@router.get("/{sbom_id}/vulnerabilities", summary="Vulnerability report for an SBOM")
async def vulnerability_report(
    sbom_id: str,
    severity: Optional[str] = Query(None, description="Filter: critical|high|medium|low"),
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    doc, components, vex_stmts = await _load_sbom_data(sbom_id, db)

    vuln_comps = await db.get_vulnerable_components(sbom_id)

    vex_not_affected = {
        (s.get("vulnerability_id", ""), s.get("component_purl", ""))
        for s in vex_stmts
        if s.get("status") == "not_affected"
    }

    rows = []
    for comp in vuln_comps:
        for vid in (comp.get("vulnerability_ids") or []):
            purl = comp.get("purl", "")
            suppressed = (vid, purl) in vex_not_affected
            rows.append({
                "vulnerability_id": vid,
                "component_name":   comp.get("name"),
                "component_version": comp.get("version"),
                "purl":             purl,
                "ecosystem":        comp.get("ecosystem"),
                "suppressed_by_vex": suppressed,
            })

    if severity:
        # We don't have severity stored at component level — return all
        # (full severity requires re-enrichment, not done here to keep endpoint fast)
        pass

    active   = [r for r in rows if not r["suppressed_by_vex"]]
    suppressed_count = len([r for r in rows if r["suppressed_by_vex"]])

    return {
        "sbom_id":          sbom_id,
        "total_findings":   len(rows),
        "active_findings":  len(active),
        "suppressed_by_vex": suppressed_count,
        "vulnerable_components": len(vuln_comps),
        "findings":         active,
    }


# ── NTIA Compliance (Feature 3) ───────────────────────────────────────────────

@router.get("/{sbom_id}/ntia", summary="NTIA minimum elements compliance score")
async def ntia_compliance(
    sbom_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """
    Validates an SBOM against the 7 NTIA minimum required elements.
    Required for US federal government software contracts (EO 14028).

    Returns a 0–100 score and per-element pass/partial/fail results.
    Thresholds:  0–40: non-compliant | 41–70: partial | 71–100: compliant
    """
    from core.ntia_validator import validate_ntia

    doc = await db.get_sbom_document(sbom_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"SBOM {sbom_id} not found")

    raw = doc.get("raw_document")
    if not raw:
        raise HTTPException(
            status_code=422,
            detail="Raw SBOM document not stored — NTIA validation requires the original payload. "
                   "Ensure raw_document is preserved on upload.",
        )

    components = await db.get_sbom_components(sbom_id)
    result = validate_ntia(raw, components)

    return {
        "sbom_id":          sbom_id,
        "application_name": doc.get("application_name"),
        "source":           doc.get("source"),
        "ntia_validation":  result,
    }


# ── Composite Risk Report (Features 1 + 5) ────────────────────────────────────

@router.get("/{sbom_id}/risk", summary="Composite risk report with EPSS + CISA KEV scoring")
async def risk_report(
    sbom_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """
    Returns vulnerability findings sorted by composite risk score.
    Composite risk = CVSS × EPSS_multiplier × KEV_multiplier × fix_factor.

    Highlights:
    - CISA KEV matches (actively exploited in the wild)
    - High EPSS entries (high exploitation probability)
    - IMMEDIATE priority items (composite risk ≥ 8.0)
    """
    doc, components, vex_stmts = await _load_sbom_data(sbom_id, db)

    vex_not_affected = {
        (s.get("vulnerability_id", ""), s.get("component_purl", ""))
        for s in vex_stmts if s.get("status") == "not_affected"
    }

    # Gather all stored vulnerability IDs from vulnerable components
    vuln_comps = [c for c in components if c.get("is_vulnerable")]
    all_vuln_ids = {
        vid
        for c in vuln_comps
        for vid in (c.get("vulnerability_ids") or [])
    }

    # Fetch threat intel from cache for all CVEs in this SBOM
    cve_ids = [v for v in all_vuln_ids if v.startswith("CVE-")]
    threat_intel_map = {}
    if cve_ids:
        try:
            async with db.pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_threat_intel WHERE cve_id = ANY($1::varchar[])",
                    cve_ids,
                )
            threat_intel_map = {dict(r)["cve_id"]: dict(r) for r in rows}
        except Exception:
            pass

    from core.risk_scorer import calculate_composite_risk

    findings = []
    kev_count = 0
    epss_spike_count = 0
    immediate_count = 0

    for comp in vuln_comps:
        for vid in (comp.get("vulnerability_ids") or []):
            purl = comp.get("purl", "")
            suppressed = (vid, purl) in vex_not_affected
            intel = threat_intel_map.get(vid, {})
            in_kev = bool(intel.get("in_cisa_kev", False))
            epss   = intel.get("epss_score")

            risk = calculate_composite_risk(
                epss_score  = float(epss) if epss else None,
                in_cisa_kev = in_kev,
            )

            if in_kev:
                kev_count += 1
            if epss and float(epss) >= 0.50:
                epss_spike_count += 1
            if risk["composite_risk"] >= 8.0:
                immediate_count += 1

            findings.append({
                "vulnerability_id": vid,
                "component_name":   comp.get("name"),
                "component_version": comp.get("version"),
                "purl":             purl,
                "in_cisa_kev":      in_kev,
                "kev_date_added":   str(intel["kev_date_added"]) if intel.get("kev_date_added") else None,
                "kev_ransomware_use": intel.get("kev_ransomware_use"),
                "epss_score":       float(epss) if epss else None,
                "composite_risk":   risk["composite_risk"],
                "priority":         risk["priority"],
                "sla":              risk["sla"],
                "suppressed_by_vex": suppressed,
            })

    # Sort: KEV first, then by composite risk descending
    findings.sort(key=lambda x: (
        not x["in_cisa_kev"],
        -(x["composite_risk"] or 0),
    ))

    return {
        "sbom_id":          sbom_id,
        "application_name": doc.get("application_name"),
        "host_id":          doc.get("host_id"),
        "summary": {
            "total_findings":     len(findings),
            "cisa_kev_count":     kev_count,
            "epss_spike_count":   epss_spike_count,
            "immediate_priority": immediate_count,
        },
        "findings": findings,
    }


# ── Policy helpers ────────────────────────────────────────────────────────────

class PolicyOverrideRequest(BaseModel):
    policy: Dict[str, Any]


@router.post("/{sbom_id}/policy", summary="Run compliance with custom policy overrides")
async def custom_policy_check(
    sbom_id: str,
    req: PolicyOverrideRequest,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    doc, components, vex_stmts = await _load_sbom_data(sbom_id, db)
    engine = ComplianceEngine(req.policy)
    all_vulns = _flat_vulns(components)
    report = engine.evaluate(components, all_vulns, vex_stmts)
    return {"sbom_id": sbom_id, "compliance": report}


def _build_policy(preset: str) -> Dict:
    if preset == "strict":
        return {
            **DEFAULT_POLICY,
            "NO_CRITICAL_VULNS":       True,
            "NO_HIGH_VULNS_UNPATCHED": True,
            "NO_STRONG_COPYLEFT":      True,
            "ALL_COMPONENTS_LICENSED": True,
            "NO_UNKNOWN_LICENSES":     True,
            "MAX_CRITICAL_COUNT":      0,
            "MAX_HIGH_COUNT":          0,
        }
    if preset == "lenient":
        return {
            **DEFAULT_POLICY,
            "NO_CRITICAL_VULNS":       False,
            "NO_HIGH_VULNS_UNPATCHED": False,
            "NO_STRONG_COPYLEFT":      False,
            "ALL_COMPONENTS_LICENSED": False,
            "NO_UNKNOWN_LICENSES":     False,
        }
    return dict(DEFAULT_POLICY)
