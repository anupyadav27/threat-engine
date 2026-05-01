"""
findings_client.py — Pushes agent findings to the central tech-check server.

Uses HTTPS outbound only.  Auth: Bearer token from AGENT_TOKEN env var.
Retries once on 5xx responses.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30  # seconds
RETRY_DELAY = 2       # seconds between retry attempts


class FindingsClient:
    """Pushes a batch of findings to POST /api/v1/tech/findings.

    Args:
        central_url: Base URL of the tech-check engine.
        token: Bearer token for auth.  Falls back to AGENT_TOKEN env var.
    """

    def __init__(
        self,
        central_url: str,
        token: Optional[str] = None,
    ) -> None:
        self._central_url = central_url.rstrip("/")
        self._token = token or os.getenv("AGENT_TOKEN", "")

    # ── public API ────────────────────────────────────────────────────────────

    def push(
        self,
        scan_run_id: str,
        account_id: str,
        tenant_id: str,
        findings: List[Dict[str, Any]],
    ) -> int:
        """POST findings to the central server.

        Args:
            scan_run_id: Pipeline scan run UUID.
            account_id: Account/host identifier.
            tenant_id: Tenant UUID.
            findings: List of finding dicts from RuleEvaluator.

        Returns:
            Number of findings acknowledged by the server.

        Raises:
            RuntimeError: When both the initial request and the retry fail.
        """
        if not findings:
            logger.info("No findings to push")
            return 0

        payload = {
            "scan_run_id": scan_run_id,
            "account_id": account_id,
            "tenant_id": tenant_id,
            "findings": findings,
        }

        url = f"{self._central_url}/api/v1/tech/findings"
        headers = self._build_headers()

        result = self._post(url, headers, payload)
        if result is None:
            logger.info("Retrying after %ds…", RETRY_DELAY)
            time.sleep(RETRY_DELAY)
            result = self._post(url, headers, payload)

        if result is None:
            raise RuntimeError(f"Failed to push findings to {url} after 2 attempts")

        inserted: int = result.get("inserted", 0)
        logger.info("Pushed %d findings → server acknowledged %d", len(findings), inserted)
        return inserted

    # ── private helpers ───────────────────────────────────────────────────────

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _post(
        self,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Attempt one POST.  Returns parsed JSON on 2xx, None on 5xx.

        Args:
            url: Endpoint URL.
            headers: HTTP headers including auth.
            payload: Request body dict.

        Returns:
            Parsed JSON response dict on success, ``None`` on server error.

        Raises:
            requests.HTTPError: On 4xx responses (client errors — do not retry).
        """
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code >= 500:
                logger.warning("Server error %d from %s", resp.status_code, url)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as exc:
            # 4xx — log and re-raise (don't retry auth/validation errors)
            logger.error("Client error pushing findings: %s", exc)
            raise
        except requests.RequestException as exc:
            logger.warning("Network error pushing findings: %s", exc)
            return None
