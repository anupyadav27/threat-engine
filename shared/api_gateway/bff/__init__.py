"""
BFF (Backend-For-Frontend) Views Package

Each module defines a FastAPI router for one UI page.
This __init__ merges them into a single ``router`` that main.py
can include with one call.

Architecture:
    bff/
        _shared.py              -- _fetch(), _qs(), engine URLs, helpers
        dashboard.py            -- /views/dashboard  (cross-engine)
        inventory.py            -- /views/inventory
        threats.py              -- /views/threats  (Threat Detection — merged overview + analytics)
        threat_command_room.py      -- /views/threat-command-room  (Command Room landing)
        threat_scenario_detail.py   -- /views/threat-scenario/{id}  (4-chapter drawer)
        threat_detail.py            -- /views/threats/{threat_id}
        threat_attack_paths.py  -- /views/threats/attack-paths
        threat_blast_radius.py  -- /views/threats/blast-radius
        threat_graph.py         -- /views/threats/graph
        threat_toxic_combos.py  -- /views/threats/toxic-combinations
        threat_timeline.py      -- /views/threats/timeline
        threat_posture_delta.py -- /views/threat-posture-delta  (Trends & Posture Delta)
                                   /views/threat-trend           (90-day trend chart data)
        compliance.py           -- /views/compliance
        iam.py                  -- /views/iam
        datasec.py              -- /views/datasec
        encryption.py           -- /views/encryption
        database_security.py    -- /views/database-security
        network_security.py     -- /views/network-security
        misconfig.py            -- /views/misconfig
        risk.py                 -- /views/risk
        scans.py                -- /views/scans
        reports.py              -- /views/reports
        rules.py                -- /views/rules
        secops.py               -- /views/secops  (SAST+DAST scan summary)
        policies.py             -- /views/policies + /views/suppressions (suppression management)
        ai_security.py          -- /views/ai-security
        container_security.py   -- /views/container-security
        cnapp.py                -- /views/cnapp  (unified CNAPP dashboard)
        cwpp.py                 -- /views/cwpp   (workload protection platform)
        vulnerability.py        -- /views/vulnerability (agent scan overview)
        attack_paths.py         -- /views/attack-paths  (Attack Path Engine — stage 6.5)
        billing.py              -- /views/billing  (billing portal — org_admin)
        platform_admin.py       -- /views/platform-admin  (operator dashboard — platform_admin)
        onboarding_schedules.py -- /views/onboarding/schedules + /views/onboarding/schedule-detail
        tenant_switcher.py      -- /views/tenant_switcher  (OrgTenantSwitcher dropdown — org_admin+)
        users_groups.py         -- /views/users + /views/groups (user/group management — org_admin+)
"""

from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .inventory import router as inventory_router
from .compliance import router as compliance_router
from .iam import router as iam_router
from .datasec import router as datasec_router
from .encryption import router as encryption_router
from .database_security import router as database_security_router
from .network_security import router as network_security_router
from .misconfig import router as misconfig_router
from .risk import router as risk_router
from .scans import router as scans_router
from .scan_timing import router as scan_timing_router
from .scan_status import router as scan_status_router
from .reports import router as reports_router
from .rules import router as rules_router
from .scope import router as scope_router
from .cdr import router as cdr_router
from .cdr_identity import router as cdr_identity_router
from .secops import router as secops_router
from .policies import router as policies_router
from .ai_security import router as ai_security_router
from .container_security import router as container_security_router
from .cnapp import router as cnapp_router
from .cwpp import router as cwpp_router
from .vulnerability import router as vulnerability_router
from .onboarding_cloud_accounts import router as onboarding_cloud_accounts_router
from .onboarding_schedules import router as onboarding_schedules_router
from .tenant_switcher import router as tenant_switcher_router
from .billing import router as billing_router
from .billing import _trial_router as billing_trial_router
from .platform_admin import router as platform_admin_router
from .views.finding_detail import router as finding_detail_router
from .views.risk_scenario_detail import router as risk_scenario_detail_router
from .views.vulnerability_agent_detail import router as vulnerability_agent_detail_router
from .users_groups import router as users_groups_router
from .vulnerability_agents import router as vulnerability_agents_router
from .attack_paths import router as attack_paths_router
from .asset_posture import router as asset_posture_router
from .asset_findings import router as asset_findings_router
from .api_security import router as api_security_router
from .chat import router as chat_router
from .threat_technique import router as threat_technique_router
from .di_assets import router as di_assets_router

# Combined router — include this in main.py
router = APIRouter()

for _sub in (
    dashboard_router,
    inventory_router,
    compliance_router,
    iam_router,
    datasec_router,
    encryption_router,
    database_security_router,
    network_security_router,
    misconfig_router,
    risk_router,
    scans_router,
    scan_timing_router,
    scan_status_router,
    reports_router,
    rules_router,
    scope_router,
    cdr_router,
    cdr_identity_router,
    secops_router,
    policies_router,
    ai_security_router,
    container_security_router,
    cnapp_router,
    cwpp_router,
    vulnerability_router,
    vulnerability_agents_router,
    onboarding_cloud_accounts_router,
    onboarding_schedules_router,
    tenant_switcher_router,
    billing_router,
    billing_trial_router,
    platform_admin_router,
    finding_detail_router,
    risk_scenario_detail_router,
    vulnerability_agent_detail_router,
    users_groups_router,
    attack_paths_router,
    asset_posture_router,
    asset_findings_router,
    api_security_router,
    chat_router,
    threat_technique_router,
    di_assets_router,
):
    router.include_router(_sub)
