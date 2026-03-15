"""
Credential Manager — Task 0.3.2 [Seq 26 | BD]

Securely retrieves and auto-refreshes authentication tokens from AWS Secrets
Manager. Provides a single get_credential(service_name) interface used by all
external adapters.

Credentials managed:
  - threat-engine/dockerhub-token
  - threat-engine/github-token
  - threat-engine/gitlab-token
  - threat-engine/nvd-api-key
  - threat-engine/threatintel-keys

Dependencies:
  - AWS IAM role with secretsmanager:GetSecretValue (IRSA)
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("external_collector.credential_manager")

# Refresh interval and staleness threshold
REFRESH_INTERVAL_SECONDS = 3600   # 1 hour
STALE_THRESHOLD_SECONDS = 3300    # 55 minutes (refresh before expiry)

# Default secret name mapping
DEFAULT_SECRET_MAP = {
    "dockerhub":    "threat-engine/dockerhub-token",
    "github":       "threat-engine/github-token",
    "gitlab":       "threat-engine/gitlab-token",
    "nvd":          "threat-engine/nvd-api-key",
    "threatintel":  "threat-engine/threatintel-keys",
}


class CredentialManager:
    """Manages external service credentials via AWS Secrets Manager.

    Caches credentials in memory with automatic refresh on staleness.

    Args:
        secret_map: Dict mapping service names to Secrets Manager secret IDs.
        region: AWS region for Secrets Manager.
        sm_client: Optional boto3 Secrets Manager client (for testing).
    """

    def __init__(
        self,
        secret_map: Optional[Dict[str, str]] = None,
        region: Optional[str] = None,
        sm_client: Optional[Any] = None,
    ) -> None:
        self._secret_map = secret_map or dict(DEFAULT_SECRET_MAP)
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._sm = sm_client or boto3.client("secretsmanager", region_name=self._region)

        # Cache: {service_name: {"value": str|dict, "fetched_at": float}}
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get_credential(self, service_name: str) -> Optional[str]:
        """Get a credential for a service, refreshing if stale.

        Args:
            service_name: One of 'dockerhub', 'github', 'gitlab', 'nvd', 'threatintel'.

        Returns:
            Credential string (token/key), or None if unavailable.
        """
        # Check cache freshness
        cached = self._cache.get(service_name)
        if cached and not self._is_stale(cached):
            return cached["value"]

        # Refresh from Secrets Manager
        secret_id = self._secret_map.get(service_name)
        if not secret_id:
            logger.warning("No secret mapping for service '%s'", service_name)
            return cached["value"] if cached else None

        try:
            value = self._fetch_secret(secret_id)
            self._cache[service_name] = {
                "value": value,
                "fetched_at": time.time(),
            }
            logger.info("Refreshed credential for '%s'", service_name)
            return value
        except Exception as exc:
            logger.error("Failed to refresh credential for '%s': %s", service_name, exc)
            # Fall back to cached value if available
            return cached["value"] if cached else None

    def get_credential_json(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get a credential that is stored as JSON (e.g., threatintel-keys).

        Args:
            service_name: Service name.

        Returns:
            Parsed JSON dict, or None if unavailable.
        """
        raw = self.get_credential(service_name)
        if raw is None:
            return None
        try:
            return json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            return None

    async def refresh_all(self) -> Dict[str, bool]:
        """Refresh all credentials. Returns {service: success_bool}.

        Called periodically (every 1 hour) to keep credentials fresh.
        """
        results: Dict[str, bool] = {}
        for service_name in self._secret_map:
            try:
                self.get_credential(service_name)
                results[service_name] = True
            except Exception:
                results[service_name] = False
        return results

    def load_all(self) -> None:
        """Load all credentials on startup. Non-fatal if some fail."""
        for service_name, secret_id in self._secret_map.items():
            try:
                value = self._fetch_secret(secret_id)
                self._cache[service_name] = {
                    "value": value,
                    "fetched_at": time.time(),
                }
                logger.info("Loaded credential for '%s'", service_name)
            except Exception as exc:
                logger.warning(
                    "Failed to load credential for '%s' (secret=%s): %s",
                    service_name, secret_id, exc,
                )

    def _fetch_secret(self, secret_id: str) -> str:
        """Fetch a secret value from Secrets Manager.

        Returns:
            The secret string.

        Raises:
            ClientError: If the secret cannot be retrieved.
        """
        response = self._sm.get_secret_value(SecretId=secret_id)
        return response.get("SecretString", "")

    def _is_stale(self, cached: Dict[str, Any]) -> bool:
        """Check if a cached credential is stale (older than threshold)."""
        age = time.time() - cached.get("fetched_at", 0)
        return age > STALE_THRESHOLD_SECONDS
