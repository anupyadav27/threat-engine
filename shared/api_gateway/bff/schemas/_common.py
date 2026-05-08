"""BFF contract base types — CSP-neutral, multi-tenant.

This module is the single source of truth for types shared across ALL 24 BFF
view schemas.  It extends the envelope helpers in ``_common_schemas.py`` with
the CSP-neutral finding base model and the multi-CSP provider type.

Import from here (not from ``_common_schemas.py``) in new schema files.
Existing handlers that already import from ``_common_schemas`` do not need to
change — that module remains untouched for backward compatibility.

Key types
---------
CSPProvider          Literal for all 7 supported cloud providers
BaseFindingItem      Required base for every per-finding list item model
SeverityCounts       KPI count breakdown with optional by_provider split
BFFErrorResponse     Standard error envelope (503, 403, etc.)
PaginatedList        Generic paginated response wrapper
ScanRunRef           Lightweight scan-run metadata reference
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Re-export building blocks from the existing common schemas so callers only
# need one import path.
from .._common_schemas import (  # noqa: F401
    FilterField,
    KpiGroup,
    KpiItem,
    PageContext,
    PageTab,
    _BaseViewResponse,
)


# ── Cloud provider enumeration ────────────────────────────────────────────────

CSPProvider = Literal["aws", "azure", "gcp", "oci", "alicloud", "ibm", "k8s"]


# ── Sensitive-key scrubber (shared regex) ─────────────────────────────────────
# Narrow to actual credential-material field names; allows legitimate metadata
# fields like secrets_encrypted (bool), secret_arn (ARN), secret_name (label).
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(credential_ref|credential_type|raw_event"
    r"|secret_access_key|secret_value|secret_key|secret_string)(_|$)"
    r"|(^credentials?$)",
    re.IGNORECASE,
)


def _walk_keys(value: Any) -> List[str]:
    found: List[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                found.append(k)
            found.extend(_walk_keys(v))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_keys(item))
    return found


# ── Severity counts (CSP-aware) ───────────────────────────────────────────────


class SeverityCounts(BaseModel):
    """Severity breakdown for a group of findings.

    ``by_provider`` is populated only for multi-CSP aggregation pages
    (dashboard, compliance, risk).  Single-CSP pages leave it empty.
    """

    model_config = ConfigDict(extra="allow")

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    by_provider: Dict[str, "SeverityCounts"] = Field(default_factory=dict)


SeverityCounts.model_rebuild()


# ── Base finding item (CSP-neutral) ───────────────────────────────────────────


class BaseFindingItem(BaseModel):
    """Required base for ALL per-CSP finding list item models.

    Field naming rules (ADR-006):
      - ``resource_uid``  — NOT arn / instance_id / compartment_id
      - ``account_id``    — NOT subscription_id / project_id
      - ``region``        — NOT availability_zone
      - ``provider``      — required on every item; drives CSP icon in the UI
      - ``provider_metadata`` — opaque dict for CSP-specific fields that don't
                                normalize across providers

    Credential fields are declared ``exclude=True`` so they are never
    serialized into the HTTP response.
    """

    model_config = ConfigDict(extra="allow")

    finding_id: str
    resource_uid: str
    resource_type: str
    provider: CSPProvider
    region: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    status: str
    account_id: Optional[str] = None
    scan_run_id: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    # Excluded from serialization — must never reach the UI
    credential_ref: Optional[str] = Field(default=None, exclude=True)
    credential_type: Optional[str] = Field(default=None, exclude=True)
    # CSP-specific opaque blob
    provider_metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _scrub_sensitive_keys(self) -> "BaseFindingItem":
        dumped = self.model_dump(mode="python")
        for key in _walk_keys(dumped):
            if _SENSITIVE_KEY_RE.search(key):
                raise ValueError(
                    f"sensitive key '{key}' in {type(self).__name__}"
                )
        return self


# ── Standard BFF error envelope ───────────────────────────────────────────────


class BFFErrorResponse(BaseModel):
    """Structured error envelope for all BFF 4xx/5xx responses.

    Every handler that catches an upstream failure must return this model
    (never a raw dict or a plain string).
    """

    page: str
    error_code: str
    message: str
    detail: Optional[str] = None
    degraded_engines: List[str] = Field(default_factory=list)


# ── Scan run reference ────────────────────────────────────────────────────────


class ScanRunRef(BaseModel):
    """Lightweight reference to a completed scan run."""

    scan_run_id: str
    provider: Optional[CSPProvider] = None
    account_id: Optional[str] = None
    completed_at: Optional[datetime] = None
    total_findings: Optional[int] = None


# ── Generic paginated list ────────────────────────────────────────────────────

_T = TypeVar("_T", bound=BaseModel)


class PaginatedList(BaseModel, Generic[_T]):
    """Generic paginated response container.

    Use as the ``items`` field type in any view that returns a scrollable
    table rather than a fixed-size KPI aggregate.

    Example:
        class MisconfigResponse(BaseModel):
            items: PaginatedList[MisconfigItem]
    """

    model_config = ConfigDict(extra="allow")

    items: List[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50
    has_more: bool = False


# ── Public surface ─────────────────────────────────────────────────────────────

__all__ = [
    # Provider type
    "CSPProvider",
    # Finding base
    "BaseFindingItem",
    # KPI helpers
    "SeverityCounts",
    # Error + pagination
    "BFFErrorResponse",
    "PaginatedList",
    "ScanRunRef",
    # Re-exported envelope helpers (single import point for new schemas)
    "KpiItem",
    "KpiGroup",
    "PageTab",
    "PageContext",
    "FilterField",
    "_BaseViewResponse",
]
