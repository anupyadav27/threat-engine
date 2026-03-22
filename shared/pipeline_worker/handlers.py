"""
Pipeline stage handlers — each function triggers one engine via HTTP
and polls DB-backed status endpoint until completion.

All engines receive ONLY scan_run_id. Each engine reads everything
it needs from scan_orchestration table via get_orchestration_metadata().

All engines use K8s Jobs on spot nodes. The API pod creates the Job
and returns a scan_id immediately. We poll GET .../status until done.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

# Default service URLs (overridden by env vars in K8s)
_DEFAULTS: Dict[str, str] = {
    "discoveries": "http://engine-discoveries.threat-engine-engines.svc.cluster.local",
    "inventory":   "http://engine-inventory.threat-engine-engines.svc.cluster.local",
    "check":       "http://engine-check.threat-engine-engines.svc.cluster.local",
    "threat":      "http://engine-threat.threat-engine-engines.svc.cluster.local",
    "compliance":  "http://engine-compliance.threat-engine-engines.svc.cluster.local",
    "iam":         "http://engine-iam.threat-engine-engines.svc.cluster.local",
    "datasec":     "http://engine-datasec.threat-engine-engines.svc.cluster.local",
}

# Polling config
ENGINE_POLL_INTERVAL: int = int(os.getenv("ENGINE_POLL_INTERVAL_S", "10"))
ENGINE_POLL_TIMEOUT: int = int(os.getenv("ENGINE_POLL_TIMEOUT_S", "3600"))
DISCOVERY_POLL_INTERVAL: int = int(os.getenv("DISCOVERY_POLL_INTERVAL_S", "15"))
DISCOVERY_TIMEOUT: int = int(os.getenv("DISCOVERY_TIMEOUT_S", "7200"))


def _url(engine: str) -> str:
    env_key = f"{engine.upper()}_ENGINE_URL"
    return os.getenv(env_key, _DEFAULTS[engine])


# ── Shared polling helper ────────────────────────────────────────────────────


async def _trigger_and_poll(
    engine: str,
    trigger_url: str,
    trigger_payload: dict,
    status_url_template: str,
    scan_id_key: str,
    poll_interval: int = ENGINE_POLL_INTERVAL,
    timeout: int = ENGINE_POLL_TIMEOUT,
) -> Dict[str, Any]:
    """Trigger an engine scan via POST, then poll GET status until done.

    Returns:
        Dict with scan_id_key and status='completed'

    Raises:
        RuntimeError: If scan fails
        TimeoutError: If scan doesn't complete within timeout
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(trigger_url, json=trigger_payload)
        resp.raise_for_status()
        dispatch_result = resp.json()

    scan_id = dispatch_result.get(scan_id_key)
    logger.info("%s triggered scan_id=%s", engine, scan_id)

    if not scan_id:
        return dispatch_result

    status_url = status_url_template.format(scan_id=scan_id)
    elapsed = 0

    while elapsed < timeout:
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(status_url)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                status_data = resp.json()
        except Exception as exc:
            logger.warning("%s status poll failed: %s", engine, exc)
            continue

        status = status_data.get("status", "running")

        if elapsed % 60 < poll_interval:
            logger.info("%s status=%s elapsed=%ds scan_id=%s", engine, status, elapsed, scan_id)

        if status == "completed":
            return {scan_id_key: scan_id, "status": "completed"}

        if status == "failed":
            error = status_data.get("error", "unknown")
            raise RuntimeError(f"{engine} scan failed: {scan_id} — {error}")

    raise TimeoutError(f"{engine} scan {scan_id} did not complete within {timeout}s")


# ── Per-engine triggers ──────────────────────────────────────────────────────
# Each engine receives ONLY scan_run_id.
# Engine reads upstream scan_ids from scan_orchestration table.


async def trigger_discovery(scan_run_id: str) -> Dict[str, Any]:
    base = _url("discoveries")
    return await _trigger_and_poll(
        engine="discovery",
        trigger_url=f"{base}/api/v1/discovery",
        trigger_payload={"scan_run_id": scan_run_id},
        status_url_template=f"{base}/api/v1/discovery/{{scan_id}}",
        scan_id_key="scan_run_id",
        poll_interval=DISCOVERY_POLL_INTERVAL,
        timeout=DISCOVERY_TIMEOUT,
    )


async def trigger_check(scan_run_id: str) -> Dict[str, Any]:
    base = _url("check")
    return await _trigger_and_poll(
        engine="check",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id},
        status_url_template=f"{base}/api/v1/check/{{scan_id}}/status",
        scan_id_key="scan_run_id",
    )


async def trigger_inventory(scan_run_id: str) -> Dict[str, Any]:
    base = _url("inventory")
    return await _trigger_and_poll(
        engine="inventory",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id},
        status_url_template=f"{base}/api/v1/inventory/scan/{{scan_id}}/status",
        scan_id_key="scan_run_id",
    )


async def trigger_threat(scan_run_id: str) -> Dict[str, Any]:
    base = _url("threat")
    return await _trigger_and_poll(
        engine="threat",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id},
        status_url_template=f"{base}/api/v1/threat/{{scan_id}}/status",
        scan_id_key="scan_run_id",
    )


async def trigger_compliance(scan_run_id: str) -> Dict[str, Any]:
    base = _url("compliance")
    return await _trigger_and_poll(
        engine="compliance",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id},
        status_url_template=f"{base}/api/v1/compliance/{{scan_id}}/status",
        scan_id_key="scan_run_id",
        timeout=1800,
    )


async def trigger_iam(scan_run_id: str, csp: str = "aws") -> Dict[str, Any]:
    base = _url("iam")
    return await _trigger_and_poll(
        engine="iam",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id, "csp": csp},
        status_url_template=f"{base}/api/v1/iam-security/{{scan_id}}/status",
        scan_id_key="scan_run_id",
        timeout=900,
    )


async def trigger_datasec(scan_run_id: str, csp: str = "aws") -> Dict[str, Any]:
    base = _url("datasec")
    return await _trigger_and_poll(
        engine="datasec",
        trigger_url=f"{base}/api/v1/scan",
        trigger_payload={"scan_run_id": scan_run_id, "csp": csp},
        status_url_template=f"{base}/api/v1/data-security/{{scan_id}}/status",
        scan_id_key="scan_run_id",
        timeout=900,
    )
