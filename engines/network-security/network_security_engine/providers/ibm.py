"""
IBM Cloud network-security provider — stub.

Full IBM VPC/Security-Group analysis is not yet implemented.
Returns an empty result so run_scan.py marks the scan completed with 0 findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .base import BaseNetworkProvider
from .alicloud import _EMPTY_METRICS  # reuse shared empty metrics template

logger = logging.getLogger(__name__)


class IBMNetworkProvider(BaseNetworkProvider):
    """Stub — IBM Cloud network analysis not yet implemented."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        logger.info("IBM Cloud network analysis not yet implemented — returning 0 findings")
        return {
            "status": "skipped",
            "reason": "IBM Cloud network analysis not yet implemented",
            "findings": [],
            "topology_snapshots": [],
            "report_metrics": _EMPTY_METRICS,
            "scan_duration_ms": 0,
        }
