"""
Argo Workflows client for triggering CSPM scan pipelines.

Talks to the Argo Server REST API (port 2746) using httpx.
The Argo Server must be reachable from within the cluster at:
  http://argo-server.argo.svc.cluster.local:2746

Environment variables:
  ARGO_SERVER_URL   — default: http://argo-server.argo.svc.cluster.local:2746
  ARGO_NAMESPACE    — default: threat-engine-engines
  ARGO_TOKEN        — Bearer token (optional; required if auth is enabled)
  ARGO_WORKFLOW_TEMPLATE — default: cspm-scan-pipeline
"""

import os
import logging
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Config from environment ───────────────────────────────────────────────────

ARGO_SERVER_URL     = os.getenv("ARGO_SERVER_URL", "https://argo-server.argo.svc.cluster.local:2746")
ARGO_NAMESPACE      = os.getenv("ARGO_NAMESPACE",  "threat-engine-engines")
ARGO_TOKEN          = os.getenv("ARGO_TOKEN", "")
ARGO_WF_TEMPLATE    = os.getenv("ARGO_WORKFLOW_TEMPLATE", "cspm-scan-pipeline")

# Request timeout for Argo API calls (seconds)
ARGO_TIMEOUT = int(os.getenv("ARGO_TIMEOUT", "10"))


def _headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if ARGO_TOKEN:
        h["Authorization"] = f"Bearer {ARGO_TOKEN}"
    return h


class ArgoClient:
    """
    Thin wrapper around the Argo Server REST API.

    Only the operations needed by the scheduler and run-now endpoint:
      - submit_pipeline()  — fire a full CSPM scan
      - get_workflow()     — poll workflow status
    """

    # ── Submit a pipeline from a WorkflowTemplate ─────────────────────────────

    def submit_pipeline(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str = "aws",
        credential_type: str = "access_key",
        credential_ref: str = "",
        include_services: Optional[List[str]] = None,
        include_regions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a full CSPM scan pipeline from the WorkflowTemplate.

        Maps to:
          argo submit -n {ns} --from wftmpl/cspm-scan-pipeline \\
            --generate-name cspm-scan- \\
            -p scan-run-id=... \\
            --labels scan-run-id=...

        Returns the created Workflow dict from Argo (includes metadata.name).
        Raises RuntimeError on failure.
        """
        params = [
            {"name": "scan-run-id",      "value": scan_run_id},
            {"name": "tenant-id",        "value": tenant_id},
            {"name": "account-id",       "value": account_id},
            {"name": "provider",         "value": provider},
            {"name": "credential-type",  "value": credential_type},
            {"name": "credential-ref",   "value": credential_ref},
            {"name": "include-services", "value": ",".join(include_services) if include_services else ""},
            {"name": "include-regions",  "value": ",".join(include_regions)  if include_regions  else ""},
        ]

        body = {
            "namespace":        ARGO_NAMESPACE,
            "resourceKind":     "WorkflowTemplate",
            "resourceName":     ARGO_WF_TEMPLATE,
            "submitOptions": {
                "generateName": "cspm-scan-",
                "labels":       f"scan-run-id={scan_run_id}",
                "parameters":   [f"{p['name']}={p['value']}" for p in params],
            },
        }

        url = f"{ARGO_SERVER_URL}/api/v1/workflows/{ARGO_NAMESPACE}/submit"
        return self._post(url, body, context=f"submit scan_run_id={scan_run_id}")

    # ── Poll workflow status ───────────────────────────────────────────────────

    def get_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """
        Get current state of a workflow.
        Returns the Workflow dict; raises RuntimeError if not found.
        """
        url = f"{ARGO_SERVER_URL}/api/v1/workflows/{ARGO_NAMESPACE}/{workflow_name}"
        return self._get(url, context=f"get workflow {workflow_name}")

    def list_workflows_by_scan_run(self, scan_run_id: str) -> List[Dict[str, Any]]:
        """Return workflows labeled with scan-run-id=<id>."""
        url = (
            f"{ARGO_SERVER_URL}/api/v1/workflows/{ARGO_NAMESPACE}"
            f"?listOptions.labelSelector=scan-run-id%3D{scan_run_id}"
        )
        data = self._get(url, context=f"list workflows scan_run_id={scan_run_id}")
        return data.get("items") or []

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _post(self, url: str, body: Dict, context: str = "") -> Dict[str, Any]:
        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx not installed — cannot call Argo API")
        try:
            resp = httpx.post(url, json=body, headers=_headers(), timeout=ARGO_TIMEOUT, verify=False)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Argo API error [{context}]: {e.response.status_code} — {e.response.text}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Argo API call failed [{context}]: {e}") from e

    def _get(self, url: str, context: str = "") -> Dict[str, Any]:
        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx not installed — cannot call Argo API")
        try:
            resp = httpx.get(url, headers=_headers(), timeout=ARGO_TIMEOUT, verify=False)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Argo API error [{context}]: {e.response.status_code} — {e.response.text}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Argo API call failed [{context}]: {e}") from e


# ── Async wrapper (used by FastAPI endpoints) ─────────────────────────────────

async def trigger_scan(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str = "aws",
    credential_type: str = "",
    credential_ref: str = "",
    include_services: Optional[List[str]] = None,
    include_regions: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Async convenience wrapper. Fires the Argo pipeline.
    Returns workflow_name on success; None on failure (logs but does not raise,
    so callers can handle the scan_run_id even if Argo is temporarily down).
    """
    client = ArgoClient()
    try:
        result = client.submit_pipeline(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
            credential_type=credential_type,
            credential_ref=credential_ref,
            include_services=include_services,
            include_regions=include_regions,
        )
        workflow_name = result.get("metadata", {}).get("name")
        logger.info(f"Argo workflow started: {workflow_name} (scan_run_id={scan_run_id})")
        return workflow_name
    except RuntimeError as e:
        logger.error(f"Argo trigger failed for scan_run_id={scan_run_id}: {e}")
        return None


# ── Module-level singleton ────────────────────────────────────────────────────
_client: Optional[ArgoClient] = None


def get_argo_client() -> ArgoClient:
    global _client
    if _client is None:
        _client = ArgoClient()
    return _client
