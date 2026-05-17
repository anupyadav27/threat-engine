"""
Pydantic models for the threat pattern DSL (REQUIREMENTS §5.3).

These models are the authoritative schema for YAML pattern files in
catalog/threat_patterns/. PatternRegistry validates every loaded pattern
against this schema before it is used by PatternCompiler.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class NodeConditions(BaseModel):
    """Conditions that must hold on a matched node."""

    check_rules_failing: List[str] = Field(default_factory=list)
    is_crown_jewel: Optional[bool] = None
    internet_exposed: Optional[bool] = None
    has_critical_cve: Optional[bool] = None
    is_admin_role: Optional[bool] = None
    cdr_actor_seen: Optional[bool] = None

    model_config = {"extra": "allow"}


class NodeSpec(BaseModel):
    """Describes a node to match in the graph."""

    node_type: str = "Resource"
    resource_types: List[str] = Field(default_factory=list)
    conditions: NodeConditions = Field(default_factory=NodeConditions)


class HopSpec(BaseModel):
    """One traversal step in a multi-hop pattern."""

    edge_type: str
    target: NodeSpec


class CDRWatch(BaseModel):
    """CDR signal requirements for Tier 3 active escalation."""

    techniques: List[str] = Field(default_factory=list)
    window_minutes: int = 60
    min_coverage: float = 0.5
    tactic_order_required: bool = False


class Scoring(BaseModel):
    """Severity output when this pattern fires."""

    posture_severity: Literal["critical", "high", "medium", "low"] = "high"
    active_severity: Literal["critical", "high", "medium", "low"] = "critical"
    path_length_bonus: bool = False


class TestCase(BaseModel):
    description: str
    expected_tier: Optional[int] = None
    expected_severity: Optional[str] = None


class PatternTests(BaseModel):
    positive: Optional[TestCase] = None
    negative: Optional[TestCase] = None


SeverityLiteral = Literal["critical", "high", "medium", "low"]
ConfidenceLiteral = Literal["confirmed", "theoretical", "emerging"]


class ThreatPattern(BaseModel):
    """Full schema for one threat detection pattern YAML file."""

    id: str
    version: int = 1
    deprecated_at: Optional[str] = None
    description: str = ""

    tier: Literal[1, 2, 3]
    severity_base: SeverityLiteral
    confidence: ConfidenceLiteral = "confirmed"

    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tactic_chain_order: List[str] = Field(default_factory=list)

    csps: List[str] = Field(default_factory=list)

    entry: NodeSpec
    hops: List[HopSpec] = Field(default_factory=list)
    target: Optional[NodeSpec] = None

    min_hops_for_tier2: Optional[int] = None

    cdr_watch: Optional[CDRWatch] = None
    scoring: Scoring = Field(default_factory=Scoring)
    tests: Optional[PatternTests] = None

    @field_validator("id")
    @classmethod
    def id_format(cls, v: str) -> str:
        import re
        if not re.match(r"^PAT-([A-Z0-9]+-)?T[123]-\d{3}$", v):
            raise ValueError(
                f"Pattern id '{v}' must match PAT-[CSP-]T<tier>-<NNN> format"
            )
        return v

    @field_validator("tier")
    @classmethod
    def tier_matches_id(cls, v: int, info: Any) -> int:
        pat_id = (info.data or {}).get("id", "")
        if pat_id and f"-T{v}-" not in pat_id:
            raise ValueError(
                f"tier={v} does not match tier token in id='{pat_id}'"
            )
        return v

    @property
    def is_deprecated(self) -> bool:
        return self.deprecated_at is not None

    @property
    def csp_list(self) -> List[str]:
        return [c.lower() for c in self.csps]
