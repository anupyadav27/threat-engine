"""
Single source of truth for engine -> UI field mapping.

Every normalizer converts raw engine JSON into the exact field names
that the React UI expects. No normalization code should exist in the UI.

Multicloud: All provider defaults use "" (empty string) instead of "AWS"
to avoid silently mislabelling resources from Azure/GCP/OCI/AliCloud/IBM.
"""

from typing import Any, Dict, List, Optional


# ── Helpers ──────────────────────────────────────────────────────────────────

def _first(val: Any) -> Optional[str]:
    """Get first element of a list, or return val if it's already a string."""
    if isinstance(val, list) and val:
        v = val[0]
        if isinstance(v, dict):
            return v.get("value") or v.get("indicator", "")
        return str(v) if v else None
    if isinstance(val, str):
        return val
    return None


def _count_resources(t: dict) -> int:
    """Count affected resources from various API shapes."""
    assets = t.get("affected_assets")
    if isinstance(assets, list):
        return len(assets)
    res = t.get("affected_resources")
    if isinstance(res, int):
        return res
    if isinstance(res, list):
        return len(res)
    return 1


def _safe_upper(val: Optional[str], default: str = "") -> str:
    return (val or default).upper()


def _safe_lower(val: Optional[str], default: str = "") -> str:
    return (val or default).lower()


def _infer_identity_type(uid: str, provider: str = "") -> str:
    if not uid:
        return ""
    prov = provider.lower()
    if "/user/" in uid:
        return "IAM User"
    if "/role/" in uid:
        return "IAM Role"
    if prov == "azure" or "microsoft" in uid.lower():
        return "Service Principal"
    if prov == "gcp" or "@" in uid:
        return "Service Account"
    return "Identity"


def _extract_account_from_assets(t: dict) -> str:
    assets = t.get("affected_assets")
    if isinstance(assets, list) and assets:
        first = assets[0]
        if isinstance(first, dict):
            return first.get("account") or first.get("account_id", "")
    return ""


def _extract_region_from_assets(t: dict) -> str:
    assets = t.get("affected_assets")
    if isinstance(assets, list) and assets:
        first = assets[0]
        if isinstance(first, dict):
            return first.get("region", "")
    return ""


# ── SLA ──────────────────────────────────────────────────────────────────────

SLA_THRESHOLDS = {"critical": 7, "high": 14, "medium": 30, "low": 90}


def compute_sla_status(severity: str, age_days: Optional[int]) -> str:
    if age_days is None:
        return "ok"
    limit = SLA_THRESHOLDS.get(severity, 90)
    if age_days > limit:
        return "breached"
    if age_days > limit * 0.7:
        return "at_risk"
    return "ok"


# ── Threat ───────────────────────────────────────────────────────────────────

def normalize_threat(t: dict) -> dict:
    severity = _safe_lower(t.get("severity"), "medium")
    risk_map = {"critical": 95, "high": 75, "medium": 50, "low": 25}
    provider = t.get("provider", "")
    account = t.get("account_id") or t.get("account", "") or _extract_account_from_assets(t)
    region = t.get("region", "") or _extract_region_from_assets(t)
    return {
        "id": t.get("threat_id") or t.get("finding_id") or t.get("id", ""),
        "title": t.get("title") or t.get("recommendation") or t.get("resource_uid", "Unknown").rsplit("/", 1)[-1],
        "mitre_technique": _first(t.get("mitre_techniques")) or t.get("mitre_technique", ""),
        "mitre_tactic": _first(t.get("mitre_tactics")) or t.get("mitre_tactic", ""),
        "severity": severity,
        "affected_resources": _count_resources(t),
        "provider": _safe_upper(provider),
        "account": account,
        "region": region,
        "environment": t.get("environment", ""),
        "status": t.get("status", "active"),
        "detected": t.get("detected_at") or t.get("first_seen_at"),
        "assignee": t.get("assignee", ""),
        "riskScore": t.get("risk_score") or risk_map.get(severity, 50),
        "risk_score": t.get("risk_score") or risk_map.get(severity, 50),  # backward compat
        "resource_type": t.get("resource_type", ""),
        "remediation_steps": t.get("remediation_steps", []),
    }


def build_mitre_matrix(threats: List[dict]) -> Dict[str, list]:
    """Group normalized threats into MITRE ATT&CK matrix: {tactic: [{id, name, severity, count}]}."""
    matrix: Dict[str, dict] = {}
    for t in threats:
        tactic = t.get("mitre_tactic", "")
        technique = t.get("mitre_technique", "")
        if not tactic or not technique:
            continue
        if tactic not in matrix:
            matrix[tactic] = {}
        if technique not in matrix[tactic]:
            matrix[tactic][technique] = {
                "id": technique,
                "name": technique,
                "severity": t.get("severity", "medium"),
                "count": 0,
            }
        matrix[tactic][technique]["count"] += 1
    return {tactic: list(techs.values()) for tactic, techs in matrix.items()}


# Static technique-to-tactic mapping for threats that have technique but no tactic
TECHNIQUE_TACTIC: Dict[str, str] = {
    "T1078": "Initial Access", "T1110": "Credential Access",
    "T1556": "Credential Access", "T1098": "Persistence",
    "T1201": "Discovery", "T1087": "Discovery", "T1069": "Discovery",
    "T1580": "Discovery", "T1526": "Discovery", "T1538": "Discovery",
    "T1082": "Discovery", "T1190": "Initial Access", "T1133": "Initial Access",
    "T1199": "Initial Access", "T1566": "Initial Access",
    "T1528": "Credential Access", "T1552": "Credential Access",
    "T1539": "Credential Access", "T1537": "Exfiltration",
    "T1567": "Exfiltration", "T1530": "Collection", "T1119": "Collection",
    "T1078.004": "Initial Access", "T1562": "Defense Evasion",
    "T1535": "Defense Evasion", "T1578": "Defense Evasion",
    "T1550": "Lateral Movement", "T1021": "Lateral Movement",
    "T1496": "Impact", "T1485": "Impact", "T1486": "Impact",
    "T1531": "Impact", "T1489": "Impact", "T1498": "Impact",
}


def build_mitre_matrix_from_raw(threats: List[dict]) -> Dict[str, list]:
    """Build MITRE matrix from raw (non-normalized) threats using static mapping."""
    tech_counts: Dict[str, int] = {}
    tech_severity: Dict[str, str] = {}
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for t in threats:
        sev = (t.get("severity") or "medium").lower()
        for tech in (t.get("mitre_techniques") or []):
            tech_id = tech if isinstance(tech, str) else tech.get("id", str(tech))
            tech_counts[tech_id] = tech_counts.get(tech_id, 0) + 1
            if sev_rank.get(sev, 0) > sev_rank.get(tech_severity.get(tech_id, "low"), 0):
                tech_severity[tech_id] = sev

    matrix: Dict[str, List[dict]] = {}
    for tech_id, count in sorted(tech_counts.items(), key=lambda x: -x[1]):
        tactic = TECHNIQUE_TACTIC.get(tech_id, "Uncategorized")
        if tactic not in matrix:
            matrix[tactic] = []
        matrix[tactic].append({
            "id": tech_id, "name": tech_id,
            "severity": tech_severity.get(tech_id, "medium"), "count": count,
        })
    return matrix


def normalize_attack_chain(ap: dict) -> dict:
    return {
        "id": ap.get("id") or ap.get("path_id", ""),
        "name": ap.get("name") or ap.get("path_name", ""),
        "severity": _safe_lower(ap.get("severity") or ap.get("risk_level")),
        "techniques": ap.get("techniques", []),
        "account": ap.get("account") or ap.get("account_id", ""),
        "provider": _safe_upper(ap.get("provider")),
        "affectedResources": ap.get("affected_resources") or len(ap.get("resources", [])),
        "detectionTime": ap.get("detection_time") or ap.get("detected_at"),
    }


def normalize_intel(item: dict) -> dict:
    indicator = item.get("indicator", "")
    if not indicator:
        indicators = item.get("indicators")
        if isinstance(indicators, list) and indicators:
            first = indicators[0]
            if isinstance(first, str):
                indicator = first
            elif isinstance(first, dict):
                indicator = first.get("value") or first.get("indicator", "")
        if not indicator:
            indicator = item.get("intel_type", "")

    relevance = item.get("relevance")
    if relevance is None:
        confidence = item.get("confidence", 0)
        relevance = round(confidence * 100) if isinstance(confidence, (int, float)) and confidence <= 1 else confidence

    return {
        "source": item.get("source", ""),
        "indicator": indicator,
        "type": item.get("type") or item.get("indicator_type", ""),
        "relevance": relevance,
        "matchedAssets": item.get("matched_assets") or item.get("ttp_count", 0),
    }


# ── Compliance ───────────────────────────────────────────────────────────────

def normalize_framework(fw: dict) -> dict:
    total = fw.get("controls_total") or fw.get("total_controls", 0)
    passed = fw.get("controls_passed") or fw.get("passed_controls") or fw.get("passed", 0)
    failed = fw.get("controls_failed") or fw.get("failed_controls") or fw.get("failed", total - passed)
    return {
        "id": fw.get("framework_id") or fw.get("compliance_framework") or fw.get("id", ""),
        "name": fw.get("framework_name") or fw.get("compliance_framework") or fw.get("name", ""),
        "score": fw.get("compliance_score") or fw.get("framework_score") or fw.get("score", 0),
        "controls": total,
        "passed": passed,
        "failed": failed,
        "last_assessed": fw.get("last_assessed") or fw.get("assessed_at"),
    }


def normalize_failing_control(c: dict) -> dict:
    return {
        "control_id": c.get("control_id", ""),
        "title": c.get("title") or c.get("control_name", ""),
        "framework": c.get("framework") or c.get("framework_id", ""),
        "account": c.get("account") or c.get("account_id", ""),
        "region": c.get("region", ""),
        "severity": _safe_lower(c.get("severity")),
        "total_failed": c.get("total_failed", 0),
        "days_open": c.get("days_open", 0),
    }


# ── Inventory ────────────────────────────────────────────────────────────────

def normalize_asset(a: dict) -> dict:
    uid = a.get("resource_uid") or a.get("resource_id", "")
    metadata = a.get("metadata") or {}
    tags = a.get("tags") or {}
    findings = a.get("findings") or {}
    severity = a.get("severity") or a.get("risk_level") or metadata.get("severity", "")
    rt = a.get("resource_type", "")
    if "::" in rt:
        service = rt.split("::")[1].lower() if len(rt.split("::")) > 1 else ""
    elif "/" in rt:
        parts = rt.split("/")
        service = parts[-1].lower() if parts else ""
    else:
        service = a.get("service", "")
    return {
        "resource_id": uid,
        "resource_uid": uid,  # UI uses resource_uid for navigation links
        "resource_name": metadata.get("name") or uid.rsplit("/", 1)[-1],
        "resource_type": rt,
        "service": service,
        "provider": _safe_lower(a.get("provider")),
        "region": a.get("region", ""),
        "account_id": a.get("account_id", ""),
        "status": metadata.get("state") or a.get("status", "active"),
        "risk_score": metadata.get("risk_score") or a.get("risk_score", 0),
        "severity": severity,
        "findings": findings if isinstance(findings, dict) else {},
        "owner": tags.get("Owner", ""),
        "tags": tags,
        "last_scanned": a.get("discovered_at") or a.get("last_scanned"),
        "created_at": a.get("discovered_at") or a.get("created_at"),
        "internet_exposed": a.get("internet_exposed", False),
        "public": a.get("public") or a.get("public_access", False),
    }


# ── IAM ──────────────────────────────────────────────────────────────────────

def normalize_iam_identity(findings_list: List[dict], uid: str) -> dict:
    if not findings_list:
        return {}
    first = findings_list[0]
    severity = _safe_lower(first.get("severity"))
    policy_count = len(findings_list)
    has_mfa_issue = any("mfa" in _safe_lower(f.get("rule_id")) for f in findings_list)
    provider = first.get("provider", "")
    if severity == "critical":
        risk = 90
    elif severity == "high":
        risk = 70
    elif severity == "medium":
        risk = 45
    else:
        risk = min(policy_count * 12, 100)
    return {
        "id": uid,
        "username": first.get("identity_name") or uid.rsplit("/", 1)[-1],
        "type": first.get("identity_type") or _infer_identity_type(uid, provider),
        "provider": _safe_upper(provider),
        "account": first.get("account_id") or first.get("account", ""),
        "region": first.get("region", ""),
        "groups": 0,
        "policies": policy_count,
        "last_login": first.get("created_at"),
        "mfa": not has_mfa_issue,
        "risk_score": risk,
        "status": "active",
    }


def group_iam_findings_to_identities(findings: List[dict]) -> List[dict]:
    by_uid: Dict[str, list] = {}
    for f in findings:
        uid = f.get("identity_name") or f.get("resource_uid") or f.get("finding_id", "unknown")
        by_uid.setdefault(uid, []).append(f)
    return [normalize_iam_identity(flist, uid) for uid, flist in by_uid.items() if flist]


def normalize_iam_role(r: dict) -> dict:
    return {
        "name": r.get("name") or r.get("role_name", ""),
        "type": r.get("type") or r.get("role_type", ""),
        "attached_to": r.get("attached_to") or r.get("principals", 0),
        "permissions": r.get("permissions") or r.get("permission_count", 0),
        "wildcard": r.get("wildcard") or r.get("has_wildcard", False),
        "last_used": r.get("last_used") or r.get("last_activity"),
        "risk_level": r.get("risk_level") or r.get("severity", "low"),
        "provider": _safe_upper(r.get("provider")),
    }


def normalize_access_key(k: dict) -> dict:
    return {
        "user": k.get("user") or k.get("username") or k.get("identity_name", ""),
        "provider": _safe_upper(k.get("provider")),
        "created": k.get("created") or k.get("created_at"),
        "last_used": k.get("last_used") or k.get("last_activity"),
        "age_days": k.get("age_days") or k.get("age", 0),
        "status": k.get("status", "active"),
        "rotation_due": k.get("rotation_due") or k.get("needs_rotation", False),
    }


def normalize_privilege_escalation(e: dict) -> dict:
    return {
        "id": e.get("id") or e.get("finding_id", ""),
        "flow": e.get("flow") or e.get("escalation_path", ""),
        "risk_level": e.get("risk_level") or e.get("severity", "medium"),
        "affected_user": e.get("affected_user") or e.get("identity_name", ""),
        "title": e.get("title", ""),
        "description": e.get("description", ""),
        "remediation": e.get("remediation", ""),
        "provider": _safe_upper(e.get("provider")),
    }


def normalize_service_account(sa: dict) -> dict:
    return {
        "name": sa.get("name") or sa.get("service_account_name", ""),
        "purpose": sa.get("purpose") or sa.get("description", ""),
        "owner": sa.get("owner", ""),
        "keys": sa.get("keys") or sa.get("key_count", 0),
        "permissions": sa.get("permissions") or sa.get("permission_count", 0),
        "status": sa.get("status", "active"),
        "risk_score": sa.get("risk_score", 0),
        "provider": _safe_upper(sa.get("provider")),
    }


# ── DataSec ──────────────────────────────────────────────────────────────────

def normalize_datastore(s: dict) -> dict:
    uid = s.get("resource_uid") or s.get("id", "")
    metadata = s.get("metadata") or {}
    tags = s.get("tags") or {}
    size_bytes = metadata.get("size_bytes")
    size_str = f"{size_bytes / (1024**3):.1f} GB" if size_bytes else ""
    records = metadata.get("record_count")
    return {
        "id": uid,
        "name": metadata.get("name") or uid.rsplit("/", 1)[-1],
        "type": s.get("resource_type") or s.get("type", ""),
        "provider": _safe_upper(s.get("provider")),
        "region": s.get("region", ""),
        "account": s.get("account_id") or s.get("account", ""),
        "size": size_str,
        "records": f"{records:,}" if records else "",
        "classification": metadata.get("data_classification") or s.get("classification", ""),
        "encryption": metadata.get("encryption_status") or s.get("encryption", ""),
        "public_access": metadata.get("public_access") or s.get("public_access", False),
        "owner": tags.get("Owner", ""),
        "last_scanned": s.get("discovered_at"),
    }


def normalize_classification(c: dict) -> dict:
    locations = c.get("locations", [])
    loc_count = len(locations) if isinstance(locations, list) else (locations if isinstance(locations, int) else 0)
    return {
        "name": c.get("pattern_name") or c.get("name") or c.get("data_type", ""),
        "type": c.get("data_type") or c.get("classification", ""),
        "count": c.get("count") or c.get("total", 0),
        "locations": loc_count,
        "confidence": c.get("confidence", 0),
        "auto_classified": c.get("auto_classified", False),
    }


def normalize_dlp_violation(v: dict) -> dict:
    return {
        "id": v.get("id") or v.get("violation_id", ""),
        "type": v.get("type") or v.get("violation_type") or v.get("title", ""),
        "resource": v.get("resource") or v.get("resource_name", ""),
        "data_type": v.get("data_type", ""),
        "severity": _safe_lower(v.get("severity")),
        "action": v.get("action", ""),
        "timestamp": v.get("timestamp") or v.get("detected_at"),
    }


def normalize_residency(r: dict) -> dict:
    return {
        "region": r.get("region", ""),
        "assets": r.get("assets") or r.get("count", 0),
        "compliance": r.get("compliance") or r.get("status", ""),
        "status": r.get("status", ""),
    }


def normalize_access_activity(a: dict) -> dict:
    return {
        "timestamp": a.get("timestamp") or a.get("event_time"),
        "resource": a.get("resource") or a.get("resource_name", ""),
        "user": a.get("user") or a.get("principal", ""),
        "action": a.get("action") or a.get("event_type", ""),
        "location": a.get("location") or a.get("source_ip", ""),
        "anomaly": a.get("anomaly") or a.get("is_anomaly", False),
    }


# ── Scans ────────────────────────────────────────────────────────────────────

def normalize_scan(s: dict, idx: int = 0) -> dict:
    dur_sec = s.get("duration_seconds")
    if dur_sec:
        dur_min = int(dur_sec) // 60
        dur_remainder = int(dur_sec) % 60
        duration = f"{dur_min}m {dur_remainder}s" if dur_min else f"{dur_remainder}s"
    else:
        duration = "--"
    return {
        "id": idx + 1,
        "scan_id": s.get("orchestration_id") or s.get("scan_run_id") or f"scan-{idx}",
        "scan_type": s.get("scan_type") or s.get("type", "Full"),
        "provider": _safe_upper(s.get("provider") or s.get("cloud")),
        "account_id": s.get("account_id") or s.get("tenant_id", ""),
        "account_name": s.get("account_name", ""),
        "status": (s.get("status") or s.get("overall_status") or "completed").lower(),
        "started_at": s.get("started_at") or s.get("created_at"),
        "completed_at": s.get("completed_at"),
        "duration": duration,
        "duration_seconds": dur_sec,
        "resources_scanned": s.get("resources_scanned") or s.get("total_resources", 0),
        "total_findings": s.get("total_findings", 0),
        "critical_findings": s.get("critical_findings", 0),
        "high_findings": s.get("high_findings", 0),
        "trigger_type": s.get("trigger_type") or s.get("triggered_by", "scheduled"),
        "triggered_by": s.get("triggered_by") or s.get("trigger_type", "scheduled"),
    }


# ── Misconfig (Check Findings) ──────────────────────────────────────────────

def normalize_check_finding(f: dict) -> dict:
    severity = _safe_lower(f.get("severity"))
    age_days = f.get("age_days")
    return {
        "id": f.get("finding_id") or f.get("id", ""),
        "rule_id": f.get("rule_id", ""),
        "title": f.get("rule_name") or f.get("title", ""),
        "severity": severity,
        "framework": f.get("framework") or f.get("control_framework", ""),
        "service": f.get("resource_type") or f.get("service", ""),
        "resource_arn": f.get("resource_id") or f.get("resource_arn", ""),
        "remediation": f.get("remediation", ""),
        "provider": _safe_upper(f.get("provider")),
        "account": f.get("account") or f.get("account_id", ""),
        "region": f.get("region", ""),
        "environment": f.get("environment", ""),
        "auto_remediable": f.get("auto_remediable", False),
        "age_days": age_days,
        "sla_status": compute_sla_status(severity, age_days),
        "status": (f.get("status") or "FAIL").upper(),
    }


def build_misconfig_heatmap(findings: List[dict]) -> List[dict]:
    by_account: Dict[str, dict] = {}
    for f in findings:
        acct = f.get("account", "unknown")
        if acct not in by_account:
            by_account[acct] = {"account": acct, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev = f.get("severity", "low")
        if sev in by_account[acct]:
            by_account[acct][sev] += 1
        by_account[acct]["total"] += 1
    return sorted(by_account.values(), key=lambda x: x["total"], reverse=True)


# ── Risk ─────────────────────────────────────────────────────────────────────

def normalize_risk_scenario(s: dict) -> dict:
    return {
        "scenario_name": s.get("scenario_name", ""),
        "threat_category": s.get("threat_category", ""),
        "probability": s.get("probability", 0),
        "expected_loss": s.get("expected_loss", 0),
        "worst_case_loss": s.get("worst_case_loss", 0),
        "risk_rating": _safe_lower(s.get("risk_rating")),
        "threat_event_frequency": s.get("threat_event_frequency", 0),
        "vulnerability": s.get("vulnerability", 0),
        "loss_magnitude": s.get("loss_magnitude", 0),
        "account": s.get("account", ""),
    }


# ── Rules ────────────────────────────────────────────────────────────────────

def normalize_rule(r: dict) -> dict:
    return {
        "rule_id": r.get("rule_id") or r.get("id", ""),
        "name": r.get("name") or r.get("rule_name", ""),
        "description": r.get("description", ""),
        "provider": _safe_upper(r.get("provider")),
        "service": r.get("service", ""),
        "severity": _safe_lower(r.get("severity")),
        "frameworks": r.get("frameworks") or r.get("compliance_frameworks", []),
        "rule_type": r.get("rule_type") or r.get("type", "built-in"),
        "status": r.get("status", "active"),
        "passing_resources": r.get("passing_resources") or r.get("passed", 0),
        "tested_resources": r.get("tested_resources") or r.get("total_resources", 0),
    }


# ── Reports ──────────────────────────────────────────────────────────────────

def normalize_report(r: dict) -> dict:
    return {
        "id": r.get("id") or r.get("report_id", ""),
        "name": r.get("name") or r.get("report_name", ""),
        "template": r.get("template") or r.get("report_type", ""),
        "generated": r.get("generated") or r.get("created_at"),
        "generatedBy": r.get("generatedBy") or r.get("generated_by") or r.get("created_by", ""),
        "format": r.get("format", "PDF"),
        "size": r.get("size", ""),
        "status": r.get("status", "completed"),
    }


def normalize_scheduled_report(sr: dict) -> dict:
    return {
        "id": sr.get("id") or sr.get("schedule_id", ""),
        "name": sr.get("name") or sr.get("report_name", ""),
        "template": sr.get("template") or sr.get("report_type", ""),
        "frequency": sr.get("frequency") or sr.get("schedule", ""),
        "recipients": sr.get("recipients") or sr.get("email_recipients", []),
        "format": sr.get("format", "PDF"),
        "nextRun": sr.get("nextRun") or sr.get("next_run"),
        "lastRun": sr.get("lastRun") or sr.get("last_run"),
        "status": sr.get("status", "active"),
    }


# ── Chart Helpers ────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
}


def severity_chart(distribution: Optional[dict]) -> List[dict]:
    """Convert {critical: N, high: N, ...} -> Recharts-ready [{name, value, color}]."""
    if not distribution:
        return []
    return [
        {"name": sev.title(), "value": distribution.get(sev, 0), "color": color}
        for sev, color in SEVERITY_COLORS.items()
        if distribution.get(sev, 0) > 0
    ]


# ── Global Scope Filters ────────────────────────────────────────────────────

def apply_global_filters(
    items: List[dict],
    provider: Optional[str] = None,
    account: Optional[str] = None,
    region: Optional[str] = None,
) -> List[dict]:
    if not any([provider, account, region]):
        return items
    result = items
    if provider:
        p = provider.upper()
        result = [i for i in result if (i.get("provider") or "").upper() == p]
    if account:
        result = [i for i in result if i.get("account") == account or i.get("account_id") == account]
    if region:
        result = [i for i in result if i.get("region") == region]
    return result
