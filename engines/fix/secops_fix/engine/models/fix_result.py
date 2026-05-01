"""
Fix result model — output of rule_matcher + fix_generator for one finding.
"""

from typing import Optional
from pydantic import BaseModel


class FixResult(BaseModel):
    finding_id: int
    secops_scan_id: str
    rule_id: Optional[str]               # original rule_id from finding
    matched_rule_id: Optional[str]       # rule_id from secops_rule_metadata that matched
    match_layer: Optional[str]           # exact / cwe / regex / unmatched
    file_path: Optional[str]
    line_number: Optional[int]
    language: Optional[str]
    severity: str
    original_code: Optional[str]         # offending line from source file
    suggested_fix: Optional[str]         # rewritten safe line
    fix_explanation: str                 # human-readable why + how
    compliant_example: Optional[str]     # from rule metadata examples.compliant
    references: Optional[list] = None
    can_auto_patch: bool = False         # True if we can safely rewrite the line
