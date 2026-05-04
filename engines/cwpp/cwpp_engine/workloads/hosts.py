"""
CWPP Hosts workload — OS, VM, and middleware vulnerability management.

Covers:
  - Host OS CVEs           (Linux distro packages, Windows patches)
  - Middleware CVEs         (Apache Tomcat, Nginx, IIS, Kafka, JBoss, WebLogic, etc.)
  - Agent-reported scans   (scan results submitted by vul_engine agents on each host)
  - SBOM dependency data   (SCA/SBOM from SBOM engine — library-level CVEs)

Sources:
  vul_engine  → GET /api/v1/scans/           list of host agent scans
  vul_engine  → GET /api/v1/vulnerabilities/ CVE findings (OS + middleware)
  sbom_engine → GET /api/v1/sbom/            SBOM documents (dependency CVEs)

Service env vars:
  VUL_ENGINE_URL  (default: http://engine-vul)
  SBOM_ENGINE_URL (default: http://engine-sbom)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

from ..core.http_client import get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.hosts")

VUL_ENGINE_URL = os.getenv("VUL_ENGINE_URL", "http://engine-vul")
SBOM_ENGINE_URL = os.getenv("SBOM_ENGINE_URL", "http://engine-sbom")

# Middleware package names the vul_engine tracks
MIDDLEWARE_KEYWORDS = {
    "tomcat", "nginx", "iis", "kafka", "jboss", "wildfly", "weblogic",
    "glassfish", "jetty", "apache", "openssl", "log4j", "spring",
}


async def fetch(scan_run_id: str, tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch host/VM/middleware workload data from vul_engine + sbom_engine."""

    # 1. Recent host agent scans
    scans_data = await get(
        f"{VUL_ENGINE_URL}/api/v1/scans/",
        params={"limit": 50},
        auth_header=auth_header,
    )

    # 2. Vulnerability findings (OS + middleware CVEs)
    vulns_data = await get(
        f"{VUL_ENGINE_URL}/api/v1/vulnerabilities/",
        params={"limit": 200},
        auth_header=auth_header,
    )

    # 3. SBOM documents (dependency CVEs — library level)
    sbom_data = await get(
        f"{SBOM_ENGINE_URL}/api/v1/sbom/",
        params={"limit": 50},
        auth_header=auth_header,
    )

    if scans_data is None and vulns_data is None and sbom_data is None:
        return _unavailable()

    # Normalize: vul_engine may return a list or a paginated dict
    scans = _to_list(scans_data)
    vulns = _to_list(vulns_data)
    sbom_docs = _to_list(sbom_data)

    # Severity breakdown
    critical, high, medium, low = _severity_counts(vulns)
    total_vulns = len(vulns)

    # Middleware vs OS split
    middleware_vulns = [v for v in vulns if _is_middleware(v)]
    os_vulns = [v for v in vulns if not _is_middleware(v)]

    posture_score = severity_to_score_penalty(critical, high, medium, total_vulns)

    return {
        "workload_type": "hosts",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "total_host_scans": len(scans),
            "total_vulnerabilities": total_vulns,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "os_vulnerabilities": len(os_vulns),
            "middleware_vulnerabilities": len(middleware_vulns),
            "sbom_documents": len(sbom_docs),
        },
        "data": {
            "host_scans": scans[:20],   # cap for API response size
            "os_vulnerabilities": os_vulns[:50],
            "middleware_vulnerabilities": middleware_vulns[:50],
            "middleware_breakdown": _middleware_breakdown(middleware_vulns),
            "sbom_summary": _sbom_summary(sbom_docs),
        },
    }


def _to_list(data: Any) -> List[Dict]:
    """Normalise paginated dict or bare list to a list."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Common pagination keys from vul_engine
        for key in ("items", "results", "data", "vulnerabilities", "scans"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def _severity_counts(vulns: List[Dict]):
    critical = sum(1 for v in vulns if _sev(v) == "critical")
    high = sum(1 for v in vulns if _sev(v) == "high")
    medium = sum(1 for v in vulns if _sev(v) == "medium")
    low = sum(1 for v in vulns if _sev(v) == "low")
    return critical, high, medium, low


def _sev(v: Dict) -> str:
    return str(v.get("severity") or v.get("cvss_severity") or "low").lower()


def _is_middleware(v: Dict) -> bool:
    pkg = str(v.get("package_name") or v.get("package") or v.get("component") or "").lower()
    return any(kw in pkg for kw in MIDDLEWARE_KEYWORDS)


def _middleware_breakdown(vulns: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for v in vulns:
        pkg = str(v.get("package_name") or v.get("package") or "unknown").lower()
        matched = next((kw for kw in MIDDLEWARE_KEYWORDS if kw in pkg), "other")
        counts[matched] = counts.get(matched, 0) + 1
    return counts


def _sbom_summary(docs: List[Dict]) -> Dict:
    if not docs:
        return {"count": 0, "note": "No SBOM documents found — submit via POST /api/v1/secops/sca/scan-repo"}
    total_vulns = sum(d.get("vulnerability_count", 0) for d in docs)
    total_components = sum(d.get("component_count", 0) for d in docs)
    return {
        "count": len(docs),
        "total_components": total_components,
        "total_vulnerabilities": total_vulns,
        "docs": [
            {
                "sbom_id": d.get("sbom_id"),
                "name": d.get("name"),
                "version": d.get("version"),
                "vulnerability_count": d.get("vulnerability_count", 0),
            }
            for d in docs[:10]
        ],
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "workload_type": "hosts",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
