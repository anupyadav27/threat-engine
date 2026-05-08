"""
Base provider interface for network-security engine.

Every CSP-specific provider must implement BaseNetworkProvider.analyze()
and return a normalized result dict that run_scan.py can persist without
knowing anything about the underlying cloud.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseNetworkProvider(ABC):
    """Abstract base for all CSP network-security providers."""

    @abstractmethod
    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        """Run CSP-specific network security analysis.

        Returns a dict with the following keys:

        - ``findings`` (List[dict]): Finding rows ready for
          :func:`save_network_findings`.
        - ``topology_snapshots`` (List[dict]): Rows for
          ``network_topology_snapshots`` table.  May be empty.
        - ``report_metrics`` (dict): Score / count fields that will be
          spread into the ``network_report`` row.  Required keys:

            posture_score, topology_score, reachability_score,
            nacl_score, firewall_score, lb_score, waf_score,
            monitoring_score, total_findings,
            critical_findings, high_findings, medium_findings, low_findings,
            findings_by_module, findings_by_status, findings_by_layer,
            severity_breakdown, exposure_summary

        - ``scan_duration_ms`` (int): Wall-clock elapsed time in ms.

        Returning ``{"status": "skipped", "reason": "<msg>"}`` signals that
        the provider has nothing to analyse (e.g. no discovery data found).
        run_scan.py will mark the report as *completed* with 0 findings.
        """
