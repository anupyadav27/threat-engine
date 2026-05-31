#!/usr/bin/env python3
"""
BFF Shape Validator
===================
Validates that each BFF view endpoint returns the exact fields the React UI
reads. Run locally against a port-forwarded gateway, or in CI against the
cluster via a job that port-forwards first.

Usage (local):
    # In one terminal:
    kubectl port-forward svc/engine-api-gateway 8000:80 -n threat-engine-engines
    # In another:
    GATEWAY_URL=http://localhost:8000 TENANT_ID=<your-tenant-id> python3 tests/bff_shape_validator.py

Usage (CI):
    Set GATEWAY_URL and TENANT_ID as CI secrets / env vars.

Exit code: 0 = all pass, 1 = one or more failures.
"""

import os
import sys
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")
TENANT_ID   = os.environ.get("TENANT_ID", "default-tenant")
PROVIDER    = os.environ.get("PROVIDER", "aws")


# ── Minimal HTTP helper (no requests dependency) ────────────────────────────

def get(path: str, params: Optional[Dict[str, str]] = None) -> Tuple[int, Any]:
    """GET path with query params; returns (status_code, parsed_json_or_None)."""
    qs = ""
    if params:
        from urllib.parse import urlencode
        qs = "?" + urlencode(params)
    url = f"{GATEWAY_URL}{path}{qs}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as exc:
        print(f"  CONNECTION ERROR: {exc}")
        return 0, None


# ── Assertion helpers ────────────────────────────────────────────────────────

failures: List[str] = []

def require(condition: bool, msg: str) -> None:
    if not condition:
        failures.append(msg)
        print(f"  FAIL  {msg}")
    else:
        print(f"  ok    {msg}")

def require_keys(obj: Any, keys: List[str], context: str) -> None:
    if not isinstance(obj, dict):
        failures.append(f"{context}: expected dict, got {type(obj).__name__}")
        print(f"  FAIL  {context}: not a dict")
        return
    for k in keys:
        if k not in obj:
            failures.append(f"{context}: missing key '{k}'")
            print(f"  FAIL  {context}: missing key '{k}'")
        else:
            print(f"  ok    {context}: has '{k}'")

def require_list(val: Any, min_len: int, context: str) -> None:
    if not isinstance(val, list):
        failures.append(f"{context}: expected list, got {type(val).__name__}")
        print(f"  FAIL  {context}: not a list")
        return
    if len(val) < min_len:
        failures.append(f"{context}: expected >= {min_len} items, got {len(val)}")
        print(f"  FAIL  {context}: length {len(val)} < {min_len}")
    else:
        print(f"  ok    {context}: length {len(val)} >= {min_len}")


# ── Per-view validators ──────────────────────────────────────────────────────

def validate_dashboard() -> None:
    print("\n=== /dashboard ===")
    status, data = get("/api/v1/views/dashboard", {
        "tenant_id": TENANT_ID,
        "provider": PROVIDER,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    # Top-level keys the React dashboard/page.jsx reads
    require_keys(data, [
        "kpi", "chartCategories", "criticalActions",
        "toxicCombinations", "criticalAlerts", "recentThreats",
        "pageContext",
    ], "dashboard")

    # kpi object — MetricStrip component reads these exact keys
    kpi = data.get("kpi", {})
    require_keys(kpi, [
        "totalAssets", "openFindings", "criticalHighFindings",
        "complianceScore", "activeThreats", "mttr",
        "slaCompliance", "internetExposed",
    ], "dashboard.kpi")

    # chartCategories — array of 4 categories
    cats = data.get("chartCategories", [])
    require_list(cats, 4, "dashboard.chartCategories")

    if len(cats) >= 1:
        # security_posture category
        sp = cats[0]
        require_keys(sp, ["id", "title", "charts"], "chartCategories[0]")
        charts = sp.get("charts", [])
        require_list(charts, 3, "chartCategories[0].charts")
        if len(charts) >= 1:
            donut = charts[0]
            require_keys(donut, ["id", "type", "title", "data"], "severity_donut chart")
            # Each item in donut data must have name + value
            donut_data = donut.get("data", [])
            if isinstance(donut_data, list) and donut_data:
                require_keys(donut_data[0], ["name", "value"], "severity_donut.data[0]")

    if len(cats) >= 3:
        # assets category — cloud_providers cards
        assets = cats[2]
        charts = assets.get("charts", [])
        if len(charts) >= 1:
            cp_chart = charts[0]
            cp_data = cp_chart.get("data", [])
            if isinstance(cp_data, list) and cp_data:
                require_keys(cp_data[0], [
                    "name", "accounts", "resources", "findings", "compliance"
                ], "cloud_providers card")

    # criticalActions — 3-bucket structure
    ca = data.get("criticalActions", {})
    require_keys(ca, ["immediate", "thisWeek", "thisMonth"], "criticalActions")

    # recentThreats — list (can be empty if no scan data)
    require(isinstance(data.get("recentThreats"), list), "recentThreats is list")
    rt = data.get("recentThreats", [])
    if rt:
        require_keys(rt[0], [
            "id", "severity", "title", "provider", "resource"
        ], "recentThreats[0]")


def validate_threats() -> None:
    print("\n=== /threats ===")
    status, data = get("/api/v1/views/threats", {
        "tenant_id": TENANT_ID,
        "provider": PROVIDER,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, [
        "kpi", "threats", "mitre", "trend", "pageContext",
    ], "threats")

    threats = data.get("threats", [])
    require(isinstance(threats, list), "threats is list")
    if threats:
        # normalize_threat() in _transforms.py produces these fields
        require_keys(threats[0], [
            "id", "severity", "title", "provider",
            "resource", "region", "mitre_techniques", "status",
        ], "threats[0]")

    kpi = data.get("kpi", {})
    require_keys(kpi, [
        "total", "critical", "high", "medium", "low",
    ], "threats.kpi")


def validate_compliance() -> None:
    print("\n=== /compliance ===")
    status, data = get("/api/v1/views/compliance", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, [
        "kpi", "frameworks", "controls", "pageContext",
    ], "compliance")

    frameworks = data.get("frameworks", [])
    require_list(frameworks, 1, "compliance.frameworks")
    if frameworks:
        # normalize_framework() in _transforms.py
        require_keys(frameworks[0], [
            "id", "name", "score", "passed", "failed", "total",
        ], "frameworks[0]")

    controls = data.get("controls", [])
    require(isinstance(controls, list), "compliance.controls is list")
    if controls:
        # normalize_failing_control() in _transforms.py
        require_keys(controls[0], [
            "control_id", "title", "severity", "framework_id", "status",
        ], "controls[0]")


def validate_scans() -> None:
    print("\n=== /scans ===")
    status, data = get("/api/v1/views/scans", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    # From bff/scans.py response structure
    require_keys(data, [
        "kpiGroups", "scans", "scheduled", "coverageByProvider", "total",
    ], "scans")

    scans = data.get("scans", [])
    require(isinstance(scans, list), "scans is list")
    if scans:
        require_keys(scans[0], [
            "scan_id", "scan_name", "scan_type", "provider",
            "account_id", "status", "started_at",
            "duration", "total_findings",
        ], "scans[0]")
        # Verify no psycopg2 data leak into scan_id field format
        require(
            isinstance(scans[0].get("scan_id"), str),
            "scans[0].scan_id is a string"
        )

    kpi_groups = data.get("kpiGroups", [])
    require_list(kpi_groups, 2, "scans.kpiGroups")
    if kpi_groups:
        require_keys(kpi_groups[0], ["title", "items"], "kpiGroups[0]")

    # Regression: verify no raw psycopg2 RealDictRow objects leaked
    # (they would serialize as dicts with extra metadata)
    if scans and isinstance(scans[0], dict):
        extra_keys = set(scans[0].keys()) - {
            "id", "scan_id", "scan_name", "scan_type", "provider", "account_id",
            "account_name", "status", "started_at", "completed_at", "duration",
            "duration_seconds", "resources_scanned", "total_findings",
            "critical_findings", "high_findings", "trigger_type", "triggered_by",
            "engines_requested", "engines_completed",
        }
        require(len(extra_keys) == 0, f"scans[0] has no unexpected keys: {extra_keys or 'none'}")


def validate_inventory() -> None:
    print("\n=== /inventory ===")
    status, data = get("/api/v1/views/inventory", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, ["kpi", "assets", "pageContext"], "inventory")
    assets = data.get("assets", [])
    require(isinstance(assets, list), "inventory.assets is list")
    if assets:
        require_keys(assets[0], [
            "resource_uid", "resource_type", "provider", "region", "account_id",
        ], "assets[0]")


def validate_iam() -> None:
    print("\n=== /iam ===")
    status, data = get("/api/v1/views/iam", {
        "tenant_id": TENANT_ID,
        "csp": PROVIDER,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, ["kpiGroups", "findings", "kpi", "pageContext"], "iam")
    findings = data.get("findings", [])
    require(isinstance(findings, list), "iam.findings is list")
    if findings:
        require_keys(findings[0], [
            "severity", "title", "rule_id", "status",
        ], "iam.findings[0]")


def validate_misconfig() -> None:
    print("\n=== /misconfig ===")
    status, data = get("/api/v1/views/misconfig", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, ["kpiGroups", "kpi", "findings", "heatmap", "quickWins", "byService", "pageContext"], "misconfig")
    findings = data.get("findings", [])
    require(isinstance(findings, list), "misconfig.findings is list")
    if findings:
        require_keys(findings[0], [
            "rule_id", "severity", "status",
        ], "misconfig.findings[0]")
    # kpi sub-fields
    kpi = data.get("kpi", {})
    require_keys(kpi, ["total", "critical", "high", "medium", "low"], "misconfig.kpi")


def validate_risk() -> None:
    print("\n=== /risk ===")
    status, data = get("/api/v1/views/risk", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, ["kpiGroups", "riskScore", "riskCategories", "scenarios", "pageContext"], "risk")
    # Verify no purely synthetic MIT-NNN mitigations (FIX-02 removes them)
    roadmap = data.get("mitigationRoadmap", [])
    if isinstance(roadmap, list):
        synthetic = [m for m in roadmap if isinstance(m.get("id"), str) and m["id"].startswith("MIT-")]
        if synthetic:
            print(f"  WARN  risk: {len(synthetic)} synthetic MIT-NNN mitigations — FIX-02 not yet shipped")
        else:
            print(f"  ok    risk: no synthetic MIT-NNN mitigations")


def validate_datasec() -> None:
    print("\n=== /datasec ===")
    status, data = get("/api/v1/views/datasec", {
        "tenant_id": TENANT_ID,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return

    require_keys(data, ["findings", "kpiGroups", "pageContext"], "datasec")
    require(isinstance(data.get("catalog", []), list), "datasec.catalog is list")
    # Verify lineage shape if present
    lineage = data.get("lineage", {})
    if lineage and isinstance(lineage, dict):
        chains = lineage.get("lineage_chains", [])
        require(isinstance(chains, list), "datasec.lineage.lineage_chains is list")


def validate_ai_security() -> None:
    print("\n=== /ai-security ===")
    status, data = get("/api/v1/views/ai-security", {
        "tenant_id": TENANT_ID,
        "csp": PROVIDER,
    })
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["findings", "inventory", "kpiGroups", "pageContext"], "ai-security")
    require(isinstance(data.get("inventory", []), list), "ai-security.inventory is list")


def validate_cdr() -> None:
    print("\n=== /cdr ===")
    status, data = get("/api/v1/views/cdr", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["kpiGroups", "findings", "identities", "pageContext"], "cdr")
    require(isinstance(data.get("findings", []), list),   "cdr.findings is list")
    require(isinstance(data.get("identities", []), list), "cdr.identities is list")


def validate_encryption() -> None:
    print("\n=== /encryption ===")
    status, data = get("/api/v1/views/encryption", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["findings", "keys", "certificates", "kpiGroups", "pageContext"], "encryption")
    require(isinstance(data.get("keys", []),         list), "encryption.keys is list")
    require(isinstance(data.get("certificates", []), list), "encryption.certificates is list")


def validate_database_security() -> None:
    print("\n=== /database-security ===")
    status, data = get("/api/v1/views/database-security", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["findings", "databases", "kpiGroups", "pageContext"], "database-security")
    require(isinstance(data.get("databases", []), list), "database-security.databases is list")


def validate_container_security() -> None:
    print("\n=== /container-security ===")
    status, data = get("/api/v1/views/container-security", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["findings", "clusters", "kpiGroups", "pageContext"], "container-security")
    require(isinstance(data.get("clusters", []), list), "container-security.clusters is list")


def validate_vulnerability() -> None:
    print("\n=== /vulnerability ===")
    status, data = get("/api/v1/views/vulnerability", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["kpiGroups", "agents", "scanSummary", "severityCounts"], "vulnerability")
    agents = data.get("agents", [])
    require(isinstance(agents, list), "vulnerability.agents is list")
    if agents:
        require_keys(agents[0], ["agent_id", "hostname", "status"], "vulnerability.agents[0]")
    scan_summary = data.get("scanSummary", {})
    require_keys(scan_summary, ["totalScans", "totalVulns", "activeAgents"], "vulnerability.scanSummary")


def validate_secops() -> None:
    print("\n=== /secops ===")
    status, data = get("/api/v1/views/secops", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["sastScans", "dastScans", "summary", "kpiGroups"], "secops")
    require(isinstance(data.get("sastScans", []), list), "secops.sastScans is list")
    require(isinstance(data.get("dastScans", []), list), "secops.dastScans is list")
    summary = data.get("summary", {})
    require_keys(summary, ["totalScans", "totalFindings"], "secops.summary")


def validate_suppressions() -> None:
    print("\n=== /suppressions ===")
    status, data = get("/api/v1/views/suppressions", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["suppressions", "rule_suppressions", "finding_suppressions", "total", "kpi", "kpiGroups"], "suppressions")
    require(isinstance(data.get("rule_suppressions", []),    list), "suppressions.rule_suppressions is list")
    require(isinstance(data.get("finding_suppressions", []), list), "suppressions.finding_suppressions is list")


def validate_cloud_accounts() -> None:
    print("\n=== /onboarding/cloud_accounts ===")
    status, data = get("/api/v1/views/onboarding/cloud_accounts", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["accounts"], "onboarding/cloud_accounts")
    accounts = data.get("accounts", [])
    require(isinstance(accounts, list), "cloud_accounts.accounts is list")
    if accounts:
        a = accounts[0]
        has_provider = "provider" in a or "csp" in a
        require(has_provider, "cloud_accounts.accounts[0] has provider/csp")


def validate_network_security() -> None:
    print("\n=== /network-security ===")
    status, data = get("/api/v1/views/network-security", {"tenant_id": TENANT_ID})
    require(status == 200, f"HTTP {status} == 200")
    if not data:
        return
    require_keys(data, ["kpiGroups", "findings", "kpi", "pageContext"], "network-security")
    findings = data.get("findings", [])
    require(isinstance(findings, list), "network-security.findings is list")
    if findings:
        require_keys(findings[0], ["severity", "rule_id", "status"], "network-security.findings[0]")


def validate_tenant_ownership() -> None:
    """
    Verify that requesting a non-existent tenant_id returns 422 or 403,
    not 200 with empty/other-tenant data.
    This test cannot verify cross-tenant isolation without two real tenants —
    it verifies the guard rejects an obviously wrong tenant_id.
    """
    print("\n=== Tenant ownership guard ===")
    fake_tenant = "00000000-0000-0000-0000-000000000000"
    status, data = get("/api/v1/views/dashboard", {
        "tenant_id": fake_tenant,
    })
    # BFF must return 422 (missing required param validation) or 403 (ownership check)
    # or 200 with all zero/empty data (acceptable if no ownership guard yet).
    # After Fix 12 is implemented, this must be 403.
    if status in (403, 422):
        print(f"  ok    fake tenant_id returns {status} (ownership guard active)")
    elif status == 200:
        print(f"  WARN  fake tenant_id returns 200 — ownership guard not yet implemented")
        # Check that data is empty (not another tenant's data)
        if data:
            kpi = data.get("kpi", {})
            total_assets = kpi.get("totalAssets", 0)
            require(
                total_assets == 0,
                f"fake tenant returns zero assets ({total_assets}) — no data leak"
            )
    else:
        require(False, f"fake tenant_id returns unexpected status {status}")


# ── Engine /ui-data shape checks (direct, not via BFF) ──────────────────────
# These run against port-forwarded engine ports.

ENGINE_PORTS = {
    "threat":     int(os.environ.get("THREAT_PORT",     "8020")),
    "compliance": int(os.environ.get("COMPLIANCE_PORT", "8010")),
    "inventory":  int(os.environ.get("INVENTORY_PORT",  "8022")),
    "onboarding": int(os.environ.get("ONBOARDING_PORT", "8008")),
}


def validate_engine_ui_data(engine: str, port: int) -> None:
    """Directly validate an engine's /ui-data endpoint shape."""
    print(f"\n=== engine:{engine} /ui-data ===")
    base = f"http://localhost:{port}"
    path_map = {
        "threat":     "/api/v1/threat/ui-data",
        "compliance": "/api/v1/compliance/ui-data",
        "inventory":  "/api/v1/inventory/ui-data",
        "onboarding": "/api/v1/cloud-accounts",
    }
    params_map = {
        "threat":     {"tenant_id": TENANT_ID, "scan_run_id": "latest", "limit": "10"},
        "compliance": {"tenant_id": TENANT_ID, "scan_id": "latest"},
        "inventory":  {"tenant_id": TENANT_ID, "scan_run_id": "latest"},
        "onboarding": {"tenant_id": TENANT_ID},
    }
    path = path_map.get(engine, "/api/v1/health/live")
    params = params_map.get(engine, {})

    def get_direct(p, q=None):
        from urllib.parse import urlencode
        qs = ("?" + urlencode(q)) if q else ""
        url = f"{base}{p}{qs}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as ex:
            return ex.code, None
        except Exception as exc:
            print(f"  CONNECTION ERROR (engine {engine} on port {port}): {exc}")
            return 0, None

    status, data = get_direct(path, params)
    require(status == 200, f"engine {engine} /ui-data HTTP {status} == 200")
    if not data:
        return

    # Engine-specific shape checks
    if engine == "threat":
        require_keys(data, ["summary", "threats"], "threat/ui-data")
        summary = data.get("summary", {})
        # dashboard.py reads: summary.total_detections, .critical, .high, .medium, .low
        require_keys(summary, ["critical", "high", "medium", "low"], "threat summary")

    elif engine == "compliance":
        # dashboard.py reads: overall_score, frameworks, trends
        require_keys(data, ["overall_score", "frameworks"], "compliance/ui-data")
        fw = data.get("frameworks", [])
        require(isinstance(fw, list), "compliance frameworks is list")
        if fw:
            # dashboard.py reads: fw.score or fw.framework_score, fw.framework_name or fw.name
            item = fw[0]
            has_score = "score" in item or "framework_score" in item or "compliance_score" in item
            has_name  = "name" in item or "framework_name" in item or "compliance_framework" in item
            require(has_score, "compliance framework[0] has a score field")
            require(has_name,  "compliance framework[0] has a name field")

    elif engine == "inventory":
        # dashboard.py reads: summary.total_assets, summary.assets_by_provider
        require_keys(data, ["summary"], "inventory/ui-data")
        summary = data.get("summary", {})
        has_total = "total_assets" in summary or "totalResources" in summary
        require(has_total, "inventory summary has total_assets or totalResources")

    elif engine == "onboarding":
        # dashboard.py reads: accounts[].account_id, .provider or .csp, .last_scan_at
        require_keys(data, ["accounts"], "onboarding/cloud-accounts")
        accounts = data.get("accounts", [])
        require(isinstance(accounts, list), "onboarding accounts is list")
        if accounts:
            a = accounts[0]
            has_provider = "provider" in a or "csp" in a
            require("account_id" in a, "onboarding account has account_id")
            require(has_provider, "onboarding account has provider or csp")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"BFF Shape Validator")
    print(f"Gateway : {GATEWAY_URL}")
    print(f"Tenant  : {TENANT_ID}")
    print(f"Provider: {PROVIDER}")

    # BFF view endpoint checks
    validate_dashboard()
    validate_threats()
    validate_compliance()
    validate_scans()
    validate_inventory()
    validate_iam()
    validate_misconfig()
    validate_risk()
    validate_datasec()
    validate_ai_security()
    validate_cdr()
    validate_encryption()
    validate_database_security()
    validate_container_security()
    validate_vulnerability()
    validate_secops()
    validate_suppressions()
    validate_cloud_accounts()
    validate_network_security()
    validate_tenant_ownership()

    # Direct engine checks (only run if engine ports are reachable)
    run_engine_checks = os.environ.get("RUN_ENGINE_CHECKS", "false").lower() == "true"
    if run_engine_checks:
        for eng, port in ENGINE_PORTS.items():
            validate_engine_ui_data(eng, port)

    # Summary
    print(f"\n{'='*60}")
    if failures:
        print(f"FAILED: {len(failures)} assertion(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
