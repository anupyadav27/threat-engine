"""Pydantic response models for the universal-finding BFF (JNY-06).

CP-2 amendments closed:
  - B1: EngineSlug uses LONG canonical slugs only.
  - B3: defense-in-depth model_validator scrubs credential/secret/raw_event keys
        from the entire serialized response (over and above Field(exclude=True)).
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


EngineSlug = Literal[
    "check",
    "threat",
    "iam",
    "network-security",
    "datasec",
    "encryption",
    "container-security",
    "dbsec",
    "ai-security",
    "cdr",
    "secops",
]


# Keys that must NEVER appear anywhere in the serialized output.
# Narrow to actual credential-material fields; allows metadata like
# secrets_encrypted (bool), secret_arn (ARN ref), secret_name (label).
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(credential_ref|credential_type|raw_event"
    r"|secret_access_key|secret_value|secret_key|secret_string)(_|$)"
    r"|(^credentials?$)",
    re.IGNORECASE,
)
# Denylist for EngineExtensions to block prototype-pollution-style smuggling.
_EXTENSION_DENYLIST = {"__proto__", "constructor", "prototype"}


def _walk_keys(value: Any) -> List[str]:
    """Yield every string key found anywhere in a nested dict/list structure."""
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


class StandardColumns(BaseModel):
    """The mandatory 14 columns echoed from every finding table.

    `credentialRef` and `credentialType` are excluded from serialization
    via Field(exclude=True). The model_validator on FindingDetailResponse
    enforces the same rule across the full payload as defense-in-depth.
    """

    tenantId: str
    scanRunId: Optional[str] = None
    credentialRef: Optional[str] = Field(default=None, exclude=True)
    credentialType: Optional[str] = Field(default=None, exclude=True)
    findingId: str
    accountId: Optional[str] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    resourceUid: Optional[str] = None
    resourceType: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    firstSeenAt: Optional[datetime] = None
    lastSeenAt: Optional[datetime] = None


class FindingHeader(BaseModel):
    findingId: str
    engine: EngineSlug
    ruleId: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    resourceUid: Optional[str] = None
    resourceType: Optional[str] = None
    resourceName: Optional[str] = None
    provider: Optional[str] = None
    accountId: Optional[str] = None
    region: Optional[str] = None
    firstSeenAt: Optional[datetime] = None
    lastSeenAt: Optional[datetime] = None
    riskScore: Optional[int] = None
    standardColumns: StandardColumns
    findingData: Dict[str, Any] = Field(default_factory=dict)


class RelatedFinding(BaseModel):
    engine: EngineSlug
    findingId: str
    severity: Optional[str] = None
    ruleId: Optional[str] = None
    title: Optional[str] = None
    status: Optional[str] = None


class RelatedFindingsBlock(BaseModel):
    available: bool
    perEngineAvailability: Dict[str, bool] = Field(default_factory=dict)
    restrictedEngines: List[str] = Field(default_factory=list)
    items: List[RelatedFinding] = Field(default_factory=list)


class ComplianceMappingItem(BaseModel):
    framework: str
    controlId: str
    controlName: Optional[str] = None
    status: Optional[str] = None


class ComplianceBlock(BaseModel):
    available: bool
    controlMappings: List[ComplianceMappingItem] = Field(default_factory=list)


class RemediationStep(BaseModel):
    order: int
    action: str
    detail: Optional[str] = None


class RemediationBlock(BaseModel):
    available: bool
    steps: List[RemediationStep] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    estimatedEffort: Optional[str] = None
    slaPriority: Optional[str] = None
    guidance: Optional[str] = None
    markdown: Optional[str] = None
    runbook_url: Optional[str] = None


class EngineExtensions(BaseModel):
    """Plugin slot — engines may register additional tab payloads.

    Allows extra fields, but the denylist validator blocks
    prototype-pollution-style key names.
    """

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _block_denylist_keys(self) -> "EngineExtensions":
        extras = getattr(self, "__pydantic_extra__", None) or {}
        bad = [k for k in extras if k in _EXTENSION_DENYLIST]
        if bad:
            raise ValueError(
                f"engineExtensions contains denylisted keys: {sorted(bad)}"
            )
        return self


class StatusUpdateRequest(BaseModel):
    status: Literal[
        "OPEN", "IN_PROGRESS", "RESOLVED", "SUPPRESSED", "FALSE_POSITIVE"
    ]
    note: Optional[str] = None


class FindingDetailResponse(BaseModel):
    finding: FindingHeader
    # UI accesses `header.*` — expose as alias at top level
    header: Optional[FindingHeader] = None
    # FE calls /api/v1/asset-context/{uid} separately; BFF returns None here.
    resourceContext: Optional[Dict[str, Any]] = None
    relatedFindings: RelatedFindingsBlock
    compliance: ComplianceBlock
    remediation: RemediationBlock
    engineExtensions: EngineExtensions = Field(default_factory=EngineExtensions)
    # Tab management fields the UI needs
    tabPermissions: Optional[Dict[str, Any]] = Field(default_factory=dict)
    degradedEngines: Optional[List[str]] = Field(default_factory=list)
    restrictedEngines: Optional[List[str]] = Field(default_factory=list)
    # Tab content aliases for UI convenience
    evidence: Optional[Dict[str, Any]] = None
    related: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    supporting: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    partial: Optional[bool] = None
    allTabs: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _scrub_sensitive_keys(self) -> "FindingDetailResponse":
        """Defense-in-depth: scan the serialized output for any keys matching
        credential|secret|raw_event (case-insensitive) and reject if found.

        This is on top of `Field(exclude=True)` on StandardColumns and protects
        against accidental leakage via `findingData` JSONB pass-through or
        `engineExtensions` extra fields.
        """
        # by_alias=False, exclude_none=False is fine — we only inspect keys.
        dumped = self.model_dump(mode="python")
        for key in _walk_keys(dumped):
            if _SENSITIVE_KEY_RE.search(key):
                raise ValueError(
                    f"sensitive key '{key}' present in serialized FindingDetailResponse"
                )
        return self
