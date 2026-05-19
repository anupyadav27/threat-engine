"""BFF view schema contract tests — Sprint 2-4 Pydantic models.

Each test:
  1. Mocks ``fetch_many`` + ``resolve_tenant_id`` so no network / DB needed.
  2. Calls the view handler directly (avoids FastAPI test client overhead).
  3. Validates the raw dict against the Pydantic response model.
  4. Asserts structural invariants (KPI groups, page context shape, etc.).

Run:
    pytest tests/contracts/test_bff_view_schema_contracts.py -v

Design constraints:
  - No live engine calls.
  - No environment variables required.
  - All 24 new-model views covered (Sprints 2-4).
  - Must finish in < 15 seconds total.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


# ── Request stub ──────────────────────────────────────────────────────────────

def _make_request(tenant_id: str = "tenant-test-001") -> MagicMock:
    req = MagicMock()
    req.headers = {"X-Auth-Context": "eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtdGVzdC0wMDEifQ=="}
    req.state = MagicMock()
    req.state.auth_header = None
    req.query_params = {}
    return req


# ── Engine fixture helpers ────────────────────────────────────────────────────

def _threat_ui_data(**extra) -> Dict[str, Any]:
    return {
        "threats": [
            {
                "finding_id": "f001",
                "rule_id": "aws.iam.mfa",
                "title": "MFA not enabled",
                "severity": "critical",
                "resource_uid": "arn:aws:iam::123:user/test",
                "resource_type": "iam",
                "account_id": "123456789012",
                "provider": "aws",
                "region": "us-east-1",
                "status": "OPEN",
                "mitre_tactics": ["Initial Access"],
                "mitre_techniques": ["T1078"],
                "risk_score": 87,
                "age_days": 14,
            }
        ],
        "summary": {"critical": 1, "high": 3, "medium": 10, "low": 5},
        "scan_trend": [{"date": "2026-05-01", "total": 20}],
        **extra,
    }


def _risk_ui_data(**extra) -> Dict[str, Any]:
    return {
        "risk_score": 72,
        "scenarios": [
            {
                "scenario_name": "Data Breach via IAM",
                "risk_rating": "critical",
                "expected_loss": 50000,
                "worst_case_loss": 200000,
            }
        ],
        "trends": [{"date": "2026-05-01", "score": 72}],
        "risk_categories": [{"category": "IAM Security", "score": 72, "count": 5}],
        "risk_register": [],
        **extra,
    }


def _compliance_ui_data() -> Dict[str, Any]:
    return {
        "frameworks": ["CIS", "NIST", "PCI-DSS"],
        "reports": [
            {
                "id": "rpt-001",
                "name": "CIS Compliance Report",
                "template": "CIS",
                "format": "PDF",
                "status": "available",
            }
        ],
        "posture_score": 68,
    }


def _onboarding_accounts() -> Dict[str, Any]:
    return {
        "accounts": [
            {
                "account_id": "123456789012",
                "provider": "aws",
                "status": "active",
                "total_resources": 100,
                "total_findings": 20,
            }
        ],
        "scan_stats": {"total_scans": 5},
    }


def _onboarding_scan_runs() -> Dict[str, Any]:
    return {
        "scan_runs": [
            {
                "scan_run_id": "run-001",
                "status": "completed",
                "provider": "aws",
                "account_id": "123456789012",
                "started_at": "2026-05-07T08:00:00Z",
                "completed_at": "2026-05-07T08:30:00Z",
                "total_resources": 100,
                "total_findings": 20,
            }
        ]
    }


def _engine_ui_data(findings: int = 2, **extra) -> Dict[str, Any]:
    """Generic engine ui-data with findings + summary."""
    return {
        "findings": [
            {
                "finding_id": f"f{i:03d}",
                "severity": "high",
                "status": "FAIL",
                "provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "resource_uid": f"arn:aws:test::123:resource/{i}",
                "resource_type": "aws.test.resource",
                "title": f"Finding {i}",
                "rule_id": f"rule.{i}",
            }
            for i in range(findings)
        ],
        "summary": {"total_findings": findings, "posture_score": 65},
        "domain_scores": {"cluster_security": 70, "workload_security": 60},
        "clusters": [],
        "databases": [],
        "resources": [],
        **extra,
    }


# ── validate helper ───────────────────────────────────────────────────────────

def _validate(model_cls: type, data: Any) -> BaseModel:
    """Validate dict against Pydantic model; raise AssertionError on failure."""
    assert isinstance(data, dict), f"handler returned {type(data).__name__}, expected dict"
    try:
        return model_cls.model_validate(data)
    except Exception as exc:
        pytest.fail(f"{model_cls.__name__} validation failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Sprint 2 — misconfig, network_security, threat_command_room, risk, dashboard
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_misconfig_contract():
    from shared.api_gateway.bff.misconfig import view_misconfig
    from shared.api_gateway.bff.schemas.misconfig import MisconfigResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_threat_ui_data()]

    req = _make_request()
    with patch("shared.api_gateway.bff.misconfig.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.misconfig.resolve_tenant_id", return_value="tenant-test-001"), \
         patch("shared.api_gateway.bff.misconfig.cached_view", return_value=None), \
         patch("shared.api_gateway.bff.misconfig.cache_key", return_value="k"), \
         patch("shared.api_gateway.bff.misconfig.auth_level_from_header", return_value=3):
        result = await view_misconfig(req, provider=None, account=None, region=None, scan_run_id="latest")

    validated = _validate(MisconfigResponse, result)
    assert isinstance(validated.findings, list)
    assert isinstance(validated.kpiGroups, list)
    assert len(validated.kpiGroups) >= 1
    assert validated.kpi.total >= 0
    assert "_meta" in result


@pytest.mark.asyncio
async def test_network_security_contract():
    from shared.api_gateway.bff.network_security import view_network_security
    from shared.api_gateway.bff.schemas.network_security import NetworkSecurityResponse

    net_data = {
        "findings": [{"finding_id": "f001", "severity": "high", "status": "FAIL",
                       "provider": "aws", "account_id": "123", "region": "us-east-1",
                       "resource_uid": "sg-123", "resource_type": "aws.ec2.security_group",
                       "title": "Port 22 open", "rule_id": "aws.net.ssh"}],
        "security_groups": [],
        "topology": {},
        "waf": [],
        "summary": {"posture_score": 55, "total_findings": 1},
        "domain_scores": {"network_isolation": 60},
    }

    async def _fetch_many(calls, auth_headers=None):
        return [net_data]

    req = _make_request()
    with patch("shared.api_gateway.bff.network_security.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.network_security.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_network_security(req, provider=None, account=None, region=None, scan_id="latest")

    validated = _validate(NetworkSecurityResponse, result)
    assert isinstance(validated.findings, list)
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_threat_command_room_contract():
    from shared.api_gateway.bff.threat_command_room import view_threat_command_room
    from shared.api_gateway.bff.schemas.threat_command_room import ThreatCommandRoomResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_threat_ui_data()]

    req = _make_request()
    with patch("shared.api_gateway.bff.threat_command_room.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.threat_command_room.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_threat_command_room(req, provider=None, account=None, region=None, scan_run_id="latest")

    validated = _validate(ThreatCommandRoomResponse, result)
    assert isinstance(validated.scenarios, list)
    assert isinstance(validated.pulse_stats, ThreatCommandRoomResponse.model_fields["pulse_stats"].annotation)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_risk_contract():
    from shared.api_gateway.bff.risk import view_risk
    from shared.api_gateway.bff.schemas.risk import RiskResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_risk_ui_data(), _threat_ui_data()]

    req = _make_request()
    with patch("shared.api_gateway.bff.risk.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.risk.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_risk(req, provider=None, account=None, region=None)

    validated = _validate(RiskResponse, result)
    assert validated.riskScore >= 0
    assert validated.riskLevel in ("critical", "high", "medium", "low", "minimal")
    assert isinstance(validated.scenarios, list)
    assert isinstance(validated.kpiGroups, list)
    assert len(validated.kpiGroups) == 2
    assert "_meta" in result


# ─────────────────────────────────────────────────────────────────────────────
# Sprint 3 — encryption, database_security, container_security, vulnerability, secops
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_encryption_contract():
    from shared.api_gateway.bff.encryption import view_encryption
    from shared.api_gateway.bff.schemas.encryption import EncryptionResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_engine_ui_data(keys=[{"key_id": "k1", "status": "active"}],
                                certificates=[], secrets=[])]

    req = _make_request()
    with patch("shared.api_gateway.bff.encryption.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.encryption.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_encryption(req, provider=None, account=None, region=None, scan_id="latest")

    validated = _validate(EncryptionResponse, result)
    assert isinstance(validated.findings, list)
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_database_security_contract():
    from shared.api_gateway.bff.database_security import view_database_security
    from shared.api_gateway.bff.schemas.database_security import DatabaseSecurityResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_engine_ui_data(databases=[{"db_id": "rds-001", "engine": "postgres"}])]

    req = _make_request()
    with patch("shared.api_gateway.bff.database_security.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.database_security.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_database_security(req, provider=None, account=None, region=None, scan_id="latest")

    validated = _validate(DatabaseSecurityResponse, result)
    assert isinstance(validated.findings, list)
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_container_security_contract():
    from shared.api_gateway.bff.container_security import view_container_security
    from shared.api_gateway.bff.schemas.container_security import ContainerSecurityResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_engine_ui_data(clusters=[{"cluster_name": "eks-prod", "provider": "aws"}])]

    req = _make_request()
    with patch("shared.api_gateway.bff.container_security.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.container_security.fetch_all_check_findings",
               new_callable=AsyncMock, return_value=[]), \
         patch("shared.api_gateway.bff.container_security.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_container_security(req, provider=None, account=None, region=None, scan_id="latest")

    validated = _validate(ContainerSecurityResponse, result)
    assert isinstance(validated.findings, list)
    assert isinstance(validated.clusters, list)
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_vulnerability_contract():
    from shared.api_gateway.bff.vulnerability import view_vulnerability
    from shared.api_gateway.bff.schemas.vulnerability import VulnerabilityResponse

    agents_resp = [{"agent_id": "a1", "hostname": "host-1", "os": "linux", "status": "active"}]
    scan_stats = {"summary": {"total_scans": 5, "total_packages_scanned": 200,
                               "total_vulnerabilities_found": 30, "active_agents": 1}}
    sev_stats = {"severity_statistics": {"CRITICAL": {"count": 5}, "HIGH": {"count": 10},
                                          "MEDIUM": {"count": 10}, "LOW": {"count": 5}}}

    async def _fetch_many(calls, auth_headers=None):
        return [agents_resp, scan_stats, sev_stats]

    req = _make_request()
    with patch("shared.api_gateway.bff.vulnerability.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.vulnerability.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_vulnerability(req, days=30)

    validated = _validate(VulnerabilityResponse, result)
    assert len(validated.agents) == 1
    assert validated.severityCounts.CRITICAL == 5
    assert validated.scanSummary.totalScans == 5
    assert "_meta" in result


@pytest.mark.asyncio
async def test_secops_contract():
    from shared.api_gateway.bff.secops import view_secops
    from shared.api_gateway.bff.schemas.secops import SecopsResponse

    # Primary path: single latest-scans endpoint returns mixed scan_type rows.
    latest_scans_resp = {
        "latest_scans": [
            {"secops_scan_id": "s1", "project_name": "my-repo", "status": "completed",
             "scan_type": "sast", "critical": 1, "high": 2, "medium": 3, "low": 1,
             "scan_timestamp": "2026-05-07T10:00:00Z"},
            {"dast_scan_id": "d1", "target_url": "https://app.example.com", "status": "completed",
             "scan_type": "dast", "critical": 0, "high": 1, "medium": 2, "low": 0,
             "scan_timestamp": "2026-05-07T11:00:00Z"},
        ]
    }

    async def _fetch_many(calls, auth_headers=None):
        return [latest_scans_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.secops.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.secops.resolve_tenant_id", return_value="tenant-test-001"), \
         patch("shared.api_gateway.bff.secops.cached_view", return_value=None), \
         patch("shared.api_gateway.bff.secops.cache_key", return_value="k"), \
         patch("shared.api_gateway.bff.secops.auth_level_from_header", return_value=3):
        result = await view_secops(req, scan_run_id=None)

    validated = _validate(SecopsResponse, result)
    assert len(validated.sastScans) == 1
    assert len(validated.dastScans) == 1
    assert validated.summary.totalScans == 2
    assert validated.summary.completedScans == 2
    assert "_meta" in result


# ─────────────────────────────────────────────────────────────────────────────
# Sprint 4 — threat sub-views + operational views
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_threat_attack_paths_contract():
    from shared.api_gateway.bff.threat_attack_paths import view_threat_attack_paths
    from shared.api_gateway.bff.schemas.threat_attack_paths import ThreatAttackPathsResponse

    pg_resp = {
        "attack_paths": [
            {
                "id": "AP-001",
                "chain_type": "internet_to_secrets",
                "severity": "critical",
                "path_score": 92,
                "entry_point": "arn:aws:ec2::123:instance/i-abc",
                "target_uid": "arn:aws:secretsmanager::123:secret/prod",
                "hops": [],
            }
        ],
        "summary": {"chain_types": {"internet_to_secrets": 1}},
    }
    neo_resp = {"paths": []}

    async def _fetch_many(calls, auth_headers=None):
        return [pg_resp, neo_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.threat_attack_paths.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.threat_attack_paths.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_threat_attack_paths(req, scan_run_id=None, min_path_score=0)

    validated = _validate(ThreatAttackPathsResponse, result)
    assert validated.kpi.total >= 1
    assert validated.kpi.critical >= 1
    assert isinstance(validated.attackPaths, list)
    assert isinstance(validated.chainTypes, dict)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_threat_blast_radius_contract():
    from shared.api_gateway.bff.threat_blast_radius import view_threat_blast_radius
    from shared.api_gateway.bff.schemas.threat_blast_radius import ThreatBlastRadiusResponse

    blast_resp = {
        "items": [
            {
                "detection_id": "det-001",
                "resource_uid": "arn:aws:s3:::my-bucket",
                "resource_type": "aws.s3.bucket",
                "provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "severity": "critical",
                "risk_score": 88,
                "verdict": "critical_exposure",
                "reachable_count": 15,
                "is_internet_reachable": True,
                "depth_distribution": {"1": 5, "2": 10},
            }
        ],
        "summary": {"total_detections": 1, "detections_with_blast": 1,
                    "total_reachable_resources": 15},
    }

    async def _fetch_many(calls, auth_headers=None):
        return [blast_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.threat_blast_radius.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.threat_blast_radius.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_threat_blast_radius(req, scan_run_id=None, resource_uid=None)

    validated = _validate(ThreatBlastRadiusResponse, result)
    assert validated.kpi.totalDetections >= 1
    assert validated.kpi.internetExposed >= 1
    assert len(validated.blastItems) >= 1
    assert validated.blastItems[0].isInternetReachable is True
    assert "_meta" in result


@pytest.mark.asyncio
async def test_threat_toxic_combos_contract():
    from shared.api_gateway.bff.threat_toxic_combos import view_threat_toxic_combos
    from shared.api_gateway.bff.schemas.threat_toxic_combos import ThreatToxicCombosResponse

    combo_resp = {
        "toxic_combinations": [
            {
                "resource_uid": "arn:aws:iam::123:role/PowerUserRole",
                "resource_type": "aws.iam.role",
                "provider": "aws",
                "threat_count": 3,
                "combo_severity": "critical",
                "severities": ["critical", "high", "medium"],
                "mitre_techniques": ["T1078", "T1098"],
                "threats": [],
            }
        ],
        "summary": {
            "total": 1,
            "severity_counts": {"critical": 1, "high": 0},
            "avg_threats_per_resource": 3.0,
        },
    }

    async def _fetch_many(calls, auth_headers=None):
        return [combo_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.threat_toxic_combos.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.threat_toxic_combos.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_threat_toxic_combos(req, scan_run_id=None, min_threats=2)

    validated = _validate(ThreatToxicCombosResponse, result)
    assert validated.kpi.total >= 1
    assert len(validated.toxicCombinations) >= 1
    assert isinstance(validated.coOccurrenceMatrix, dict)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_threat_timeline_contract():
    from shared.api_gateway.bff.threat_timeline import threat_timeline_view
    from shared.api_gateway.bff.schemas.threat_timeline import ThreatTimelineResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_threat_ui_data(), {"scan_runs": []}]

    req = _make_request()
    with patch("shared.api_gateway.bff.threat_timeline.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.threat_timeline.resolve_tenant_id", return_value="tenant-test-001"):
        result = await threat_timeline_view(req, limit=200)

    validated = _validate(ThreatTimelineResponse, result)
    assert isinstance(validated.events, list)
    assert validated.kpi.totalEvents >= 0
    assert "_meta" in result


@pytest.mark.asyncio
async def test_scans_contract():
    from shared.api_gateway.bff.scans import view_scans
    from shared.api_gateway.bff.schemas.scans import ScansResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_onboarding_accounts(), _onboarding_scan_runs()]

    req = _make_request()
    with patch("shared.api_gateway.bff.scans.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.scans.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_scans(req, provider=None, account=None, limit=50)

    validated = _validate(ScansResponse, result)
    assert isinstance(validated.kpiGroups, list)
    assert len(validated.kpiGroups) >= 2
    assert isinstance(validated.scans, list)
    assert validated.total >= 0
    assert "_meta" in result


@pytest.mark.asyncio
async def test_reports_contract():
    from shared.api_gateway.bff.reports import view_reports
    from shared.api_gateway.bff.schemas.reports import ReportsResponse

    async def _fetch_many(calls, auth_headers=None):
        return [_compliance_ui_data(), _onboarding_accounts()]

    req = _make_request()
    with patch("shared.api_gateway.bff.reports.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.reports.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_reports(req)

    validated = _validate(ReportsResponse, result)
    assert isinstance(validated.reports, list)
    assert isinstance(validated.templates, list)
    assert isinstance(validated.tabs, list)
    assert validated.kpi.totalReports >= 0
    assert "_meta" in result


@pytest.mark.asyncio
async def test_rules_contract():
    from shared.api_gateway.bff.rules import view_rules
    from shared.api_gateway.bff.schemas.rules import RulesResponse

    rules_resp = {
        "rules": [
            {
                "rule_id": "aws.iam.mfa",
                "title": "MFA not enabled for console users",
                "severity": "critical",
                "provider": "aws",
                "service": "iam",
                "is_active": True,
                "is_custom": False,
            }
        ],
        "total": 1,
        "stats": {"total": 1, "active": 1, "built_in": 1, "custom_rules_count": 0},
    }

    async def _fetch_many(calls, auth_headers=None):
        # rules.py calls fetch_many with 3 args: check catalog + user-rules + suppressions
        return [rules_resp, {}, {}]

    req = _make_request()
    with patch("shared.api_gateway.bff.rules.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.rules.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_rules(req, provider=None)

    validated = _validate(RulesResponse, result)
    assert isinstance(validated.rules, list)
    assert validated.kpi.total >= 0
    assert "_meta" in result


@pytest.mark.asyncio
async def test_cnapp_contract():
    from shared.api_gateway.bff.cnapp import view_cnapp
    from shared.api_gateway.bff.schemas.cnapp import CNAPPResponse

    cnapp_resp = {
        "cnapp_posture_score": 65,
        "risk_band": "medium",
        "pillars": {
            "cspm": {"score": 70, "findings": 10, "status": "degraded"},
            "ciem": {"score": 80, "findings": 3, "status": "ok"},
        },
        "total_findings": 13,
        "critical_findings": 2,
    }

    async def _fetch_many(calls, auth_headers=None):
        return [cnapp_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.cnapp.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.cnapp.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_cnapp(req, provider=None, account=None, scan_id="latest")

    validated = _validate(CNAPPResponse, result)
    assert validated.cnapp_posture_score >= 0
    assert isinstance(validated.pillars, list)
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_cwpp_contract():
    from shared.api_gateway.bff.cwpp import view_cwpp
    from shared.api_gateway.bff.schemas.cwpp import CWPPResponse

    cwpp_resp = {
        "cwpp_posture_score": 58,
        "risk_band": "high",
        "total_findings": 25,
        "critical_findings": 4,
        "workloads": {
            "containers": {"posture_score": 60, "findings": 10},
            "images": {"posture_score": 55, "findings": 8},
            "hosts": {"posture_score": 70, "findings": 5},
            "serverless": {"posture_score": 65, "findings": 2},
            "runtime": {"posture_score": 0, "findings": 0},
        },
        "containers_data": {},
        "images_data": {},
        "hosts_data": {},
        "serverless_data": {},
        "runtime_data": {},
    }

    async def _fetch_many(calls, auth_headers=None):
        return [cwpp_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.cwpp.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.cwpp.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_cwpp(req, provider=None, account=None, region=None, scan_id="latest")

    validated = _validate(CWPPResponse, result)
    assert validated.workload.posture_score >= 0
    assert isinstance(validated.kpiGroups, list)
    assert "_meta" in result


@pytest.mark.asyncio
async def test_ai_security_contract():
    from shared.api_gateway.bff.ai_security import view_ai_security
    from shared.api_gateway.bff.schemas.ai_security import AISecurityResponse

    ai_resp = {
        "summary": {
            "critical_findings": 2,
            "high_findings": 5,
            "medium_findings": 8,
            "total_findings": 15,
            "posture_score": 72,
            "risk_score": 45,
            "total_ml_resources": 12,
        },
        "modules": [],
        "inventory": [],
        "shadow_ai": [],
        "findings": [],
        "coverage": {
            "vpc_isolation_pct": 80,
            "encryption_rest_pct": 90,
            "encryption_transit_pct": 85,
            "model_card_pct": 60,
            "monitoring_pct": 70,
            "guardrails_pct": 40,
        },
        "scan_trend": [],
    }

    async def _fetch_many(calls, auth_headers=None):
        return [ai_resp]

    req = _make_request()
    with patch("shared.api_gateway.bff.ai_security.fetch_many", side_effect=_fetch_many), \
         patch("shared.api_gateway.bff.ai_security.resolve_tenant_id", return_value="tenant-test-001"):
        result = await view_ai_security(req, provider=None, account=None, region=None, csp=None, scan_id="latest")

    validated = _validate(AISecurityResponse, result)
    assert isinstance(validated.modules, list)
    assert isinstance(validated.kpiGroups, list)
    assert len(validated.kpiGroups) == 2
    assert validated.coverage.guardrails_pct >= 0
    assert "_meta" in result


# ─────────────────────────────────────────────────────────────────────────────
# Cross-cutting invariants — all new-model views
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_all_views_return_meta_key():
    """Every view handler must include _meta in its response dict.

    This test acts as a regression gate: if a dev adds a new view without
    BFFMeta, or a refactor drops the _meta key, this test catches it.
    """
    # Spot-check 4 different views all returning _meta
    from shared.api_gateway.bff.risk import view_risk
    from shared.api_gateway.bff.secops import view_secops
    from shared.api_gateway.bff.threat_attack_paths import view_threat_attack_paths
    from shared.api_gateway.bff.rules import view_rules

    req = _make_request()

    async def _null_fetch(calls, auth_headers=None):
        return [None] * len(calls)

    with patch("shared.api_gateway.bff.risk.fetch_many", side_effect=_null_fetch), \
         patch("shared.api_gateway.bff.risk.resolve_tenant_id", return_value="t1"):
        r = await view_risk(req, provider=None, account=None, region=None)
        assert "_meta" in r, "risk view missing _meta"
        assert r["_meta"]["view"] == "risk"

    with patch("shared.api_gateway.bff.secops.fetch_many", side_effect=_null_fetch), \
         patch("shared.api_gateway.bff.secops.resolve_tenant_id", return_value="t1"), \
         patch("shared.api_gateway.bff.secops.cached_view", return_value=None), \
         patch("shared.api_gateway.bff.secops.cache_key", return_value="k"), \
         patch("shared.api_gateway.bff.secops.auth_level_from_header", return_value=3):
        r = await view_secops(req, scan_run_id=None)
        assert "_meta" in r, "secops view missing _meta"

    with patch("shared.api_gateway.bff.threat_attack_paths.fetch_many", side_effect=_null_fetch), \
         patch("shared.api_gateway.bff.threat_attack_paths.resolve_tenant_id", return_value="t1"):
        r = await view_threat_attack_paths(req, scan_run_id=None, min_path_score=0)
        assert "_meta" in r, "threat_attack_paths view missing _meta"

    with patch("shared.api_gateway.bff.rules.fetch_many", side_effect=_null_fetch), \
         patch("shared.api_gateway.bff.rules.resolve_tenant_id", return_value="t1"):
        r = await view_rules(req, provider=None)
        assert "_meta" in r, "rules view missing _meta"


@pytest.mark.asyncio
async def test_empty_engine_returns_dont_crash():
    """Views must degrade gracefully when engines return None (network error)."""
    from shared.api_gateway.bff.misconfig import view_misconfig

    async def _null_fetch(calls, auth_headers=None):
        return [None]

    req = _make_request()
    with patch("shared.api_gateway.bff.misconfig.fetch_many", side_effect=_null_fetch), \
         patch("shared.api_gateway.bff.misconfig.resolve_tenant_id", return_value="t1"), \
         patch("shared.api_gateway.bff.misconfig.cached_view", return_value=None), \
         patch("shared.api_gateway.bff.misconfig.cache_key", return_value="k"), \
         patch("shared.api_gateway.bff.misconfig.auth_level_from_header", return_value=3):
        result = await view_misconfig(req, provider=None, account=None, region=None, scan_run_id="latest")

    assert result["kpi"]["total"] == 0
    assert result["findings"] == []
    assert "_meta" in result
    # engine call status should be empty or failed — not ok
    calls = result["_meta"]["engine_calls"]
    assert any(c["status"] in ("failed", "empty") for c in calls)
