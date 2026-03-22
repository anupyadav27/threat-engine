"""
VEX (Vulnerability Exploitability eXchange) Routes

POST /          - Create or update a VEX statement
GET  /          - List VEX statements (filter by sbom_id, vulnerability_id, purl)
GET  /{vuln_id} - All VEX statements for a specific vulnerability ID
DELETE /{id}    - Delete a VEX statement by DB id
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from core.auth import get_current_user
from core.database import SBOMDatabaseManager

logger = logging.getLogger(__name__)

router = APIRouter()

VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

VEX_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_privilege",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}


def get_db() -> SBOMDatabaseManager:
    from main import db_manager
    return db_manager


# ── Models ────────────────────────────────────────────────────────────────────

class VEXRequest(BaseModel):
    vulnerability_id: str              # CVE-xxx or GHSA-xxx or OSV-xxx
    status: str                        # not_affected | affected | fixed | under_investigation
    component_purl: Optional[str] = None
    component_name: Optional[str] = None
    sbom_id: Optional[str] = None
    justification: Optional[str] = None   # valid only for not_affected
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    created_by: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v not in VEX_STATUSES:
            raise ValueError(f"status must be one of {sorted(VEX_STATUSES)}")
        return v

    @field_validator("justification")
    @classmethod
    def validate_justification(cls, v):
        if v and v not in VEX_JUSTIFICATIONS:
            raise ValueError(f"justification must be one of {sorted(VEX_JUSTIFICATIONS)}")
        return v


# ── Create / Update VEX ───────────────────────────────────────────────────────

@router.post("/", summary="Create or update a VEX statement")
async def create_vex(
    req: VEXRequest,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """
    Upsert a VEX statement for a (vulnerability_id, component_purl) pair.

    Use status='not_affected' with an appropriate justification to suppress
    false-positive vulnerability findings in compliance reports and SBOM output.

    VEX justifications for 'not_affected':
    - code_not_present          : vulnerable code path not included in build
    - code_not_reachable        : no execution path reaches the vulnerable function
    - requires_configuration    : only exploitable in non-default configuration
    - requires_privilege        : requires elevated privileges to trigger
    - protected_by_compiler     : compiler mitigation prevents exploit
    - protected_at_runtime      : runtime mitigation (ASLR, DEP, etc.)
    - protected_at_perimeter    : network controls prevent exploitation
    - protected_by_mitigating_control: other compensating controls
    """
    if req.status == "not_affected" and not req.justification:
        logger.warning(
            f"VEX 'not_affected' for {req.vulnerability_id} submitted without justification"
        )

    if req.status in ("fixed", "not_affected") and not req.action_statement:
        req.action_statement = f"Status set to '{req.status}' by {req.created_by or 'unknown'}"

    vex_id = await db.save_vex_statement(req.model_dump())
    return {"id": vex_id, "vulnerability_id": req.vulnerability_id, "status": req.status}


# ── List VEX statements ───────────────────────────────────────────────────────

@router.get("/", summary="List VEX statements")
async def list_vex(
    sbom_id: Optional[str] = Query(None),
    vulnerability_id: Optional[str] = Query(None),
    component_purl: Optional[str] = Query(None),
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    stmts = await db.get_vex_statements(
        sbom_id=sbom_id,
        vulnerability_id=vulnerability_id,
        component_purl=component_purl,
    )
    return {"total": len(stmts), "statements": stmts}


# ── Get VEX by vulnerability ID ───────────────────────────────────────────────

@router.get("/{vulnerability_id}", summary="VEX statements for a vulnerability")
async def get_vex_for_vuln(
    vulnerability_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    stmts = await db.get_vex_statements(vulnerability_id=vulnerability_id)
    return {
        "vulnerability_id": vulnerability_id,
        "total":            len(stmts),
        "statements":       stmts,
    }


# ── Delete VEX ────────────────────────────────────────────────────────────────

@router.delete("/{vex_id}", summary="Delete a VEX statement")
async def delete_vex(
    vex_id: int,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM sbom_vex_statements WHERE id = $1", vex_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail=f"VEX statement {vex_id} not found")
    return {"deleted": vex_id}
