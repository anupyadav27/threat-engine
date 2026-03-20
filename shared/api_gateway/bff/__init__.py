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
        threats.py              -- /views/threats
        threat_detail.py        -- /views/threats/{threat_id}
        threat_analytics.py     -- /views/threats/analytics
        threat_attack_paths.py  -- /views/threats/attack-paths
        threat_blast_radius.py  -- /views/threats/blast-radius
        threat_graph.py         -- /views/threats/graph
        threat_hunting.py       -- /views/threats/hunting
        threat_internet_exposed.py -- /views/threats/internet-exposed
        threat_toxic_combos.py  -- /views/threats/toxic-combinations
        compliance.py           -- /views/compliance
        iam.py                  -- /views/iam
        datasec.py              -- /views/datasec
        misconfig.py            -- /views/misconfig
        risk.py                 -- /views/risk
        scans.py                -- /views/scans
        reports.py              -- /views/reports
        rules.py                -- /views/rules
"""

from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .inventory import router as inventory_router
from .threats import router as threats_router
from .threat_detail import router as threat_detail_router
from .threat_analytics import router as threat_analytics_router
from .threat_attack_paths import router as threat_attack_paths_router
from .threat_blast_radius import router as threat_blast_radius_router
from .threat_graph import router as threat_graph_router
from .threat_hunting import router as threat_hunting_router
from .threat_internet_exposed import router as threat_internet_exposed_router
from .threat_toxic_combos import router as threat_toxic_combos_router
from .compliance import router as compliance_router
from .iam import router as iam_router
from .datasec import router as datasec_router
from .misconfig import router as misconfig_router
from .risk import router as risk_router
from .scans import router as scans_router
from .reports import router as reports_router
from .rules import router as rules_router

# Combined router — include this in main.py
router = APIRouter()

# NOTE: Sub-page routers (threat_analytics, threat_attack_paths, etc.) must be
# registered BEFORE the threat_detail router because FastAPI matches routes in
# registration order and /threats/{threat_id} would otherwise swallow
# /threats/analytics, /threats/attack-paths, etc.
for _sub in (
    dashboard_router,
    inventory_router,
    threats_router,
    threat_analytics_router,
    threat_attack_paths_router,
    threat_blast_radius_router,
    threat_graph_router,
    threat_hunting_router,
    threat_internet_exposed_router,
    threat_toxic_combos_router,
    threat_detail_router,
    compliance_router,
    iam_router,
    datasec_router,
    misconfig_router,
    risk_router,
    scans_router,
    reports_router,
    rules_router,
):
    router.include_router(_sub)
