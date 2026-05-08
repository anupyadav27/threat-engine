"""Finding detail Pydantic models — re-exported from views/_schemas.py.

This module is the canonical import path for finding-detail types in Phase 0.
The implementation lives in ``views/_schemas.py`` and is imported verbatim here
so existing code using ``from views._schemas import ...`` continues to work
while new code uses ``from bff.schemas.findings import ...``.
"""

from __future__ import annotations

# Re-export every public symbol from the existing implementation.
from ..views._schemas import (  # noqa: F401
    ComplianceBlock,
    ComplianceMappingItem,
    EngineExtensions,
    EngineSlug,
    FindingDetailResponse,
    FindingHeader,
    RelatedFinding,
    RelatedFindingsBlock,
    RemediationBlock,
    RemediationStep,
    StandardColumns,
    StatusUpdateRequest,
)

__all__ = [
    "ComplianceBlock",
    "ComplianceMappingItem",
    "EngineExtensions",
    "EngineSlug",
    "FindingDetailResponse",
    "FindingHeader",
    "RelatedFinding",
    "RelatedFindingsBlock",
    "RemediationBlock",
    "RemediationStep",
    "StandardColumns",
    "StatusUpdateRequest",
]
