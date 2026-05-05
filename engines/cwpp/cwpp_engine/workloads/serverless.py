"""
CWPP Serverless workload — Lambda, Azure Functions, GCF, OCI Functions.

Pulls from the container-security engine, filtering to Lambda/serverless-specific
findings. The container-security engine discovers Lambda functions as part of its
ECS/Fargate/Lambda service group and maps findings to security domains like
workload_security and runtime_audit.

Serverless security concerns covered:
  - Over-permissive execution roles (IAM)
  - Publicly accessible function URLs
  - Missing resource-based policies
  - Unencrypted environment variables (secrets in plaintext)
  - VPC isolation (Lambda not in VPC)
  - Deprecated runtimes (Python 2.7, Node 12, etc.)
  - Missing X-Ray tracing
  - Concurrency limits not set (DoS risk)

Source engine:
  container-security → GET /api/v1/container-security/ui-data
  (filter: container_service = 'lambda')

Service env var:
  CONTAINER_SEC_URL (default: http://engine-container-sec)
"""

from __future__ import annotations

import os
import logging
from collections import Counter
from typing import Any, Dict, List, Optional

from ..core.http_client import get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.serverless")

CONTAINER_SEC_URL = os.getenv("CONTAINER_SEC_URL", "http://engine-container-sec")

SERVERLESS_SERVICES = {"lambda", "azure_functions", "gcf", "cloud_functions", "oci_functions"}

DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "nodejs14.x", "dotnetcore2.1", "dotnetcore3.1", "ruby2.5", "java8",
}


async def fetch(scan_run_id: str, tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch serverless workload data from container-security engine."""
    data = await get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        # container-security engine uses scan_id (not scan_run_id)
        params={"tenant_id": tenant_id, "scan_id": scan_run_id},
        auth_header=auth_header,
    )

    if data is None:
        return _unavailable()

    all_findings = data.get("findings", [])
    inventory = data.get("inventory", [])

    # Filter to serverless-only resources
    serverless_findings = [
        f for f in all_findings
        if str(f.get("container_service") or "").lower() in SERVERLESS_SERVICES
        or "lambda" in str(f.get("resource_type") or "").lower()
        or "function" in str(f.get("resource_type") or "").lower()
    ]

    serverless_inventory = [
        i for i in inventory
        if str(i.get("container_service") or "").lower() in SERVERLESS_SERVICES
        or "lambda" in str(i.get("resource_type") or "").lower()
        or "function" in str(i.get("resource_type") or "").lower()
    ]

    if not serverless_findings and not serverless_inventory:
        # Engine is reachable but no serverless resources in this account
        return {
            "workload_type": "serverless",
            "status": "no_data",
            "posture_score": None,
            "summary": {
                "note": "No serverless resources (Lambda, Azure Functions, GCF) found in this scan.",
                "total_functions": 0,
                "total_findings": 0,
            },
            "data": {},
        }

    critical = sum(1 for f in serverless_findings if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in serverless_findings if f.get("severity", "").upper() == "HIGH")
    medium = sum(1 for f in serverless_findings if f.get("severity", "").upper() == "MEDIUM")
    total = len(serverless_findings)

    posture_score = severity_to_score_penalty(critical, high, medium, total)

    # Runtime breakdown (e.g. python2.7, nodejs12.x are deprecated)
    runtime_breakdown = _runtime_breakdown(serverless_inventory, serverless_findings)

    # Build per-function metadata from findings already in memory
    finding_count_by_uid: Counter = Counter(
        f.get("resource_uid") for f in serverless_findings
    )
    iam_finding_uids = {
        f["resource_uid"] for f in serverless_findings
        if any(
            kw in (f.get("rule_id", "") + f.get("title", "")).lower()
            for kw in ["iam", "role", "permission", "policy"]
        )
    }

    functions = []
    for item in serverless_inventory:
        fd = item.get("finding_data") or {}
        runtime = fd.get("Runtime") or fd.get("runtime") or "unknown"
        functions.append({
            "function_name":           item.get("resource_name"),
            "runtime":                 runtime,
            "region":                  item.get("region"),
            "account_id":              item.get("account_id"),
            "provider":                item.get("provider"),
            "resource_uid":            item.get("resource_uid"),
            "has_public_url":          bool(fd.get("FunctionUrlConfig")),
            "has_deprecated_runtime":  runtime in DEPRECATED_RUNTIMES,
            "has_overpermissive_role": item.get("resource_uid") in iam_finding_uids,
            "finding_count":           finding_count_by_uid.get(item.get("resource_uid"), 0),
        })

    return {
        "workload_type": "serverless",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "total_functions": len(serverless_inventory),
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": total - critical - high - medium,
            "deprecated_runtimes": runtime_breakdown.get("deprecated_count", 0),
            "public_functions": sum(
                1 for f in serverless_findings
                if "public" in str(f.get("title") or "").lower()
                or "publicly" in str(f.get("description") or "").lower()
            ),
        },
        "data": {
            "functions": functions,
            "findings": serverless_findings,
            "runtime_breakdown": runtime_breakdown,
        },
    }


def _runtime_breakdown(inventory: List[Dict], findings: List[Dict]) -> Dict:
    """Tally runtimes from inventory resource metadata."""
    runtimes: Dict[str, int] = {}
    deprecated_runtimes = {
        "python2.7", "nodejs4.3", "nodejs6.10", "nodejs8.10",
        "nodejs10.x", "nodejs12.x", "java8", "dotnetcore2.1",
        "ruby2.5", "go1.x",
    }
    deprecated_count = 0

    for item in inventory:
        fd = item.get("finding_data") or {}
        runtime = str(fd.get("Runtime") or fd.get("runtime") or "unknown").lower()
        runtimes[runtime] = runtimes.get(runtime, 0) + 1
        if runtime in deprecated_runtimes:
            deprecated_count += 1

    return {
        "by_runtime": runtimes,
        "deprecated_count": deprecated_count,
        "deprecated_runtimes": list(deprecated_runtimes),
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "workload_type": "serverless",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
