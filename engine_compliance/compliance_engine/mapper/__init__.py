"""
Compliance Mapper Module

Maps security check rule_ids to compliance framework controls.
"""

from .framework_loader import FrameworkLoader
from .rule_mapper import RuleMapper

__all__ = ["FrameworkLoader", "RuleMapper"]

