"""
Attack Edge Validator Runner — orchestrates all Phase 1 validators.

Called from run_scan.py BEFORE pg_bfs so validated edges are in asset_relationships
when the graph is loaded.

Pipeline position:
  Stage 2a-pre2: run_all_validators()
    → validate_internet_reachability  (AWS-INET-001..005, SSM-001, CloudFront, ELB)
    → validate_service_chain          (AWS-SVC-001..006, ELB chain builder)
    → validate_network_topology       (VAL-NET-001..002, subnet/SG lateral movement)
    → validate_identity_usage         (AWS-ID-001..003)
    → validate_assume_role            (AWS-ID-004..005, filters service/account principals)
    → validate_data_access            (AWS-DATA-001..005, AWS-SEC-001..002, AWS-KMS-001..002)
    → validate_iam_policy             (AWS-IAM-001..003, CAN_READ/CAN_DECRYPT/CAN_INVOKE)
    → validate_eks_worker             (AWS-EKS-001, worker_node_of edges)
  Stage 2b: pg_bfs (reads is_attack_edge=TRUE rows)
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from .assume_role import validate_assume_role
from .data_access import validate_data_access
from .eks_worker import validate_eks_worker
from .iam_policy import validate_iam_policy
from .identity_usage import validate_identity_usage
from .internet_reachability import validate_internet_reachability
from .network_topology import validate_network_topology
from .service_chain import validate_service_chain

logger = logging.getLogger("attack-path.validators.runner")


def run_all_validators(
    di_conn: Any,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> Dict[str, int]:
    """Run all Phase 1 validators. Non-fatal — each validator is independent.

    Returns:
        Dict of validator_name → edges_written counts.
    """
    results: Dict[str, int] = {}

    _validators = [
        ("internet_reachability", validate_internet_reachability),
        ("service_chain",         validate_service_chain),
        # network_topology runs AFTER service_chain so it has all CAN_REACH entry points
        # to seed the subnet/SG co-location lateral movement derivation.
        ("network_topology",      validate_network_topology),
        ("identity_usage",        validate_identity_usage),
        ("assume_role",           validate_assume_role),
        ("data_access",           validate_data_access),
        # AP-VAL-03: replaces in-memory _build_iam_permission_edges() in run_scan.py.
        # Writes CAN_READ/CAN_DECRYPT/CAN_INVOKE edges to asset_relationships so the
        # pg BFS picks them up as first-class validated edges (not synthetic extra_edges).
        ("iam_policy",            validate_iam_policy),
        # AP-VAL-03: replaces in-memory _build_eks_worker_node_edges() in run_scan.py.
        # Writes worker_node_of edges so EC2 → EKS paths traverse the BFS graph.
        ("eks_worker",            validate_eks_worker),
    ]

    total = 0
    for name, fn in _validators:
        try:
            count = fn(di_conn, scan_run_id, tenant_id, account_id, provider)
            results[name] = count
            total += count
        except Exception as exc:
            logger.warning("validator %s failed (non-fatal): %s", name, exc, exc_info=True)
            results[name] = 0
            try:
                di_conn.rollback()
            except Exception:
                pass

    logger.info(
        "run_all_validators: total_attack_edges=%d scan=%s validators=%s",
        total, scan_run_id,
        {k: v for k, v in results.items() if v > 0},
    )
    return results
