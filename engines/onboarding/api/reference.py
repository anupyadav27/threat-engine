"""
Reference data endpoints — providers and account_types.
These serve as the authoritative catalog for both the UI wizard and other engines.

GET /api/v1/providers       — all active providers with metadata
GET /api/v1/account-types   — all active account_types with engine lists
"""
import os
import sys
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger

try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop():
            return None
        return _noop

from engine_onboarding.database.reference_operations import (
    get_all_providers,
    get_all_account_types,
)

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/onboarding", tags=["reference"])


class ProviderOut(BaseModel):
    provider:          str
    display_name:      str
    category:          str
    credential_models: List[str]
    description:       Optional[str] = None
    logo_key:          Optional[str] = None
    display_order:     int


class AccountTypeOut(BaseModel):
    account_type:      str
    display_name:      str
    description:       Optional[str] = None
    engines_triggered: List[str]
    display_order:     int


@router.get(
    "/providers",
    response_model=List[ProviderOut],
    dependencies=[Depends(require_permission("onboarding:read"))],
    summary="List all active cloud/DB/VCS/agent providers",
)
def list_providers():
    """
    Returns all active providers from the account_providers reference table.
    Includes category, valid credential_models, and display metadata.
    Used by the onboarding wizard to populate provider dropdowns dynamically.
    """
    try:
        return get_all_providers()
    except Exception as exc:
        logger.error(f"list_providers failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load providers")


@router.get(
    "/account-types",
    response_model=List[AccountTypeOut],
    dependencies=[Depends(require_permission("onboarding:read"))],
    summary="List all active account types with engine mappings",
)
def list_account_types():
    """
    Returns all active account_types from the account_types reference table.
    Includes the engines_triggered list so callers know which scan engines
    run for each account type.
    Used by the onboarding wizard and other engines for routing decisions.
    """
    try:
        return get_all_account_types()
    except Exception as exc:
        logger.error(f"list_account_types failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load account types")
