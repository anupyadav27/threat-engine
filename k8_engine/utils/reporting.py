from typing import Dict, Any

try:
    # Prefer absolute import if utility.base_reporting is in sys.path
    from utility.base_reporting import (
        CheckResult,
        CheckStatus,
        CheckSeverity,
        BaseReporter,
        create_reporter,
    )
except Exception:
    # Fallback minimal shim to keep engine working without external dependency
    from dataclasses import dataclass, field
    from enum import Enum
    from datetime import datetime
    import json

    class CheckStatus(str, Enum):
        PASS = "PASS"
        FAIL = "FAIL"
        SKIP = "SKIP"
        ERROR = "ERROR"

    class CheckSeverity(str, Enum):
        LOW = "LOW"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"

    @dataclass
    class CheckResult:
        check_id: str
        check_name: str
        status: CheckStatus
        status_extended: str
        resource_id: str
        resource_name: str
        resource_type: str
        severity: CheckSeverity = CheckSeverity.MEDIUM
        cluster_name: str | None = None
        metadata: Dict[str, Any] = field(default_factory=dict)
        execution_time: float | None = None

    class BaseReporter:
        def __init__(self, cluster_info: Dict[str, Any] | None = None):
            self.cluster_info = cluster_info or {}
            self._results: list[CheckResult] = []
        def add_results(self, results: list[CheckResult]):
            self._results.extend(results)
        def generate_json_report(self, path: str):
            payload = {
                "metadata": {"generated_at": datetime.utcnow().isoformat() + "Z", "cluster": self.cluster_info},
                "checks": [r.__dict__ for r in self._results],
            }
            with open(path, "w") as fh:
                json.dump(payload, fh, indent=2)
        def generate_text_report(self) -> str:
            return f"Total checks: {len(self._results)}"

    def create_reporter(cluster_info: Dict[str, Any] | None = None) -> BaseReporter:
        return BaseReporter(cluster_info=cluster_info)

__all__ = [
    "CheckResult",
    "CheckStatus",
    "CheckSeverity",
    "BaseReporter",
    "create_reporter",
] 