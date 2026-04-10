"""
Internet exposure detection — CSP-scoped modules with a uniform interface.

Each module exposes exactly one public function:

    detect(session, tenant_id, pg_conn_fn, exposed_uids) -> int

Args:
    session      — active Neo4j driver session
    tenant_id    — tenant being built
    pg_conn_fn   — callable(db_name: str) -> psycopg2 connection
    exposed_uids — mutable set[str]; UIDs already EXPOSES'd; each detector
                   MUST skip UIDs already in the set and add new ones.

Returns:
    int — count of new Internet -[:EXPOSES]-> Resource edges created.

Module layout:
    _common.py   CSP-agnostic: check_findings patterns + config JSON inspection
    _aws.py      AWS-specific: EC2/RDS/ELB/EKS/API-GW/Lambda/Cognito/OpenSearch
    _azure.py    Azure-specific: VMs/SQL/Storage/AKS/App-Service
    _gcp.py      GCP-specific: GCE/CloudSQL/GKE/CloudRun/GCS
    _oci.py      OCI-specific: Compute/ObjectStorage/AutonomousDB

Usage (from graph_builder.py):
    from .exposure import detect_all
    count = detect_all(session, tenant_id, self._pg_conn)
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Set

logger = logging.getLogger(__name__)

# Ordered list: common runs first so subsequent CSP modules can skip known UIDs
_DETECTOR_MODULES = ["_common", "_aws", "_azure", "_gcp", "_oci"]


def detect_all(session: Any, tenant_id: str, pg_conn_fn: Callable) -> int:
    """Run all CSP exposure detectors; return total EXPOSES edges created."""
    exposed_uids: Set[str] = set()
    total = 0

    for mod_name in _DETECTOR_MODULES:
        try:
            import importlib
            mod = importlib.import_module(f".{mod_name}", package=__name__)
            n = mod.detect(session, tenant_id, pg_conn_fn, exposed_uids)
            if n:
                logger.debug(f"exposure.{mod_name}: {n} new EXPOSES edges")
            total += n
        except Exception as exc:
            logger.warning(f"exposure.{mod_name} detector failed: {exc}")

    logger.info(f"Inferred {total} internet exposure edges (all CSPs) for tenant={tenant_id}")
    return total
