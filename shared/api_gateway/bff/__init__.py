"""
BFF (Backend-For-Frontend) Views Package

Each module defines a FastAPI router for one UI page.
This __init__ merges them into a single ``router`` that main.py
can include with one call.

Architecture:
    bff/
        _shared.py      -- _fetch(), _qs(), engine URLs, helpers
        dashboard.py    -- /views/dashboard  (cross-engine)
        inventory.py    -- /views/inventory
        threats.py      -- /views/threats
        compliance.py   -- /views/compliance
        iam.py          -- /views/iam
        datasec.py      -- /views/datasec
        misconfig.py    -- /views/misconfig
        risk.py         -- /views/risk
        scans.py        -- /views/scans
        reports.py       -- /views/reports
        rules.py        -- /views/rules
"""

from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .inventory import router as inventory_router
from .threats import router as threats_router
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

for _sub in (
    dashboard_router,
    inventory_router,
    threats_router,
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
