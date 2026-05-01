"""
K8s network-security provider.

Layer 1 (check_findings via network_security=true) handles all rule-based
K8s network findings (NetworkPolicy, namespace isolation, etc.).
This provider handles topology analysis only — deferred.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .base import BaseNetworkProvider
from .alicloud import _EMPTY_METRICS

logger = logging.getLogger(__name__)


class K8sNetworkProvider(BaseNetworkProvider):
    """K8s topology analysis — deferred; Layer 1 covers all rule findings."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        logger.info("K8s topology analysis: deferred (Layer 1 check findings cover rules)")
        return {
            "status": "skipped",
            "reason": "K8s network topology deferred — Layer 1 check findings cover rules",
            "findings": [],
            "topology_snapshots": [],
            "report_metrics": _EMPTY_METRICS,
            "scan_duration_ms": 0,
        }
