from typing import Dict, Any

# Thin indirection layer to reduce coupling with utility paths
from ..utility.base_reporting import (
    CheckResult,
    CheckStatus,
    CheckSeverity,
    BaseReporter,
    create_reporter,
)

__all__ = [
    "CheckResult",
    "CheckStatus",
    "CheckSeverity",
    "BaseReporter",
    "create_reporter",
] 