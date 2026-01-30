"""
Report Generator Module

Generates different types of compliance reports.
"""

from .executive_dashboard import ExecutiveDashboard
from .framework_report import FrameworkReport
from .resource_drilldown import ResourceDrilldown

__all__ = ["ExecutiveDashboard", "FrameworkReport", "ResourceDrilldown"]

