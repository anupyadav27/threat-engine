"""
Platform Admin Engine — Argo Workflows REST API client.

Reads the in-cluster service account token to authenticate against the
Argo server. Falls back to unauthenticated requests when no token is
present (local development).

Argo server: http://argo-server.argo.svc.cluster.local:2746
Docs: https://argoproj.github.io/argo-workflows/rest-api/
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

ARGO_SERVER_URL: str = os.environ.get(
    "ARGO_SERVER_URL", "http://argo-server.argo.svc.cluster.local:2746"
)
ARGO_NAMESPACE: str = os.environ.get("ARGO_NAMESPACE", "threat-engine-engines")

_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def _load_sa_token() -> Optional[str]:
    """Read the pod's service account JWT from the standard mount path.

    Returns:
        Token string, or None if not running inside a cluster.
    """
    try:
        token = Path(_SA_TOKEN_PATH).read_text().strip()
        return token if token else None
    except (FileNotFoundError, PermissionError):
        logger.debug("SA token not found — running outside cluster, Argo auth skipped")
        return None


def get_argo_headers() -> dict[str, str]:
    """Build authorization headers for Argo REST API calls.

    Returns:
        Dict with Authorization header if a service account token is
        available, otherwise an empty dict.
    """
    token = _load_sa_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}
