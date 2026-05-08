"""
Data models for the contract-checking agent.

Represents the 4-layer contract chain:
  UI (JSX field accesses)
    → BFF (Python handler return keys)
      → Engine (Pydantic response_model fields)
        → DB (SQL column names)
"""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel


class LayerContract(BaseModel):
    """Fields extracted from one layer of the stack."""
    layer: Literal["ui", "bff", "engine", "db"]
    fields: list[str]          # flat or dot-notation paths, e.g. "pulse_stats.critical_count"
    source_files: list[str]    # files inspected
    notes: list[str] = []      # parser warnings or caveats


class FieldMismatch(BaseModel):
    """A single contract violation found between two adjacent layers."""
    layer_from: str            # e.g. "ui"
    layer_to: str              # e.g. "bff"
    field_path: str            # e.g. "pulse_stats.critical_count"
    issue: Literal[
        "missing_in_target",   # target layer doesn't declare this field
        "type_mismatch",       # field exists but declared type differs
        "renamed",             # probably the same field under a different name
        "optional_vs_required",# ui uses ?. but field is required downstream
        "extra_allow_gap",     # passes through only because model has extra='allow'
    ]
    severity: Literal["breaking", "warning", "info"]
    suggestion: str            # concrete fix recommendation


class ContractReport(BaseModel):
    """Full end-to-end contract report for one BFF view."""
    view_name: str
    layers: list[LayerContract] = []
    mismatches: list[FieldMismatch] = []
    coverage_score: float = 100.0   # 0–100
    breaking_count: int = 0
    warning_count: int = 0
    summary: str = ""               # 2–3 sentence narrative for humans
