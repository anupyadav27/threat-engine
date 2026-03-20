"""
Discovery Scanner — K8s Job entry point.

Runs a full multi-threaded discovery scan for one account and exits.
Created by the Discovery API when ``POST /api/v1/discovery`` is called.

Usage::

    python -m run_scan \
        --orchestration-id 337a7425-5a53-4664-8569-04c1f0d6abf0 \
        --discovery-scan-id disc_abc123

Environment:
    Same as the Discovery API pod (DB config, AWS creds, PYTHONPATH=/app).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import traceback

# Ensure /app is on the path (same as Dockerfile PYTHONPATH)
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from common.database.database_manager import DatabaseManager
from common.orchestration.discovery_engine import DiscoveryEngine
from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

# CSP-specific scanners
from providers.aws.scanner.service_scanner import AWSDiscoveryScanner
from providers.azure.scanner.service_scanner import AzureDiscoveryScanner
from providers.gcp.scanner.service_scanner import GCPDiscoveryScanner
from providers.oci.scanner.service_scanner import OCIDiscoveryScanner
from providers.ibm.scanner.service_scanner import IBMDiscoveryScanner
from providers.kubernetes.scanner.service_scanner import K8sDiscoveryScanner

# Orchestration helpers
from consolidated_services.database.orchestration_client import (
    get_scan_context as get_orchestration_metadata,
    update_engine_scan_id,
)

# Credential retrieval
from engine_onboarding.storage.secrets_manager_storage import SecretsManagerStorage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("discovery_scanner")

PROVIDER_SCANNERS = {
    "aws": AWSDiscoveryScanner,
    "azure": AzureDiscoveryScanner,
    "gcp": GCPDiscoveryScanner,
    "oci": OCIDiscoveryScanner,
    "ibm": IBMDiscoveryScanner,
    "k8s": K8sDiscoveryScanner,
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _resolve_credentials(account_id: str, credential_ref: str, credential_type: str, provider: str):
    """Resolve credentials from Secrets Manager (same logic as api_server.py)."""
    cred_type = (credential_type or "").lower()

    # Role-based: no Secrets Manager fetch needed
    if cred_type in ("aws_iam_role", "iam_role", "role", "managed_identity"):
        return {
            "credential_type": cred_type,
            "role_arn": credential_ref,
        }

    # Key-based: fetch from Secrets Manager
    storage = SecretsManagerStorage()
    secret_data = storage.retrieve(account_id=account_id)

    if not isinstance(secret_data, dict) or not secret_data:
        raise ValueError(f"Empty/invalid credentials for account {account_id}")

    # Normalize credential_type
    raw_type = (secret_data.get("credential_type") or "").lower()
    if provider == "aws":
        if raw_type in ("aws_access_key", "access_key", "access_key_id"):
            secret_data["credential_type"] = "access_key"
        elif "role" in raw_type:
            secret_data["credential_type"] = "iam_role"

    return secret_data


def _get_scanner(provider: str, credentials: dict) -> DiscoveryScanner:
    """Instantiate CSP-specific scanner."""
    provider_lower = provider.lower()
    if provider_lower not in PROVIDER_SCANNERS:
        raise ValueError(f"Unsupported provider: {provider}")
    scanner_class = PROVIDER_SCANNERS[provider_lower]
    return scanner_class(credentials=credentials, provider=provider_lower)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Run a discovery scan (K8s Job entry point)")
    parser.add_argument("--orchestration-id", required=True, help="Orchestration UUID from scan_orchestration")
    parser.add_argument("--discovery-scan-id", required=True, help="Pre-assigned discovery_scan_id")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    discovery_scan_id = args.discovery_scan_id

    logger.info(
        "Discovery scanner starting orchestration_id=%s scan_id=%s",
        orchestration_id, discovery_scan_id,
    )

    db_manager = DatabaseManager()

    # SIGTERM handler — mark scan as failed on timeout/preemption
    def _handle_sigterm(signum, frame):
        logger.warning("SIGTERM received — marking scan as failed (timeout/preemption)")
        try:
            db_manager.update_scan_status(discovery_scan_id, "failed")
        except Exception:
            pass
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(orchestration_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {orchestration_id}")

        provider = metadata.get("provider", "aws")
        account_id = metadata.get("account_id")
        credential_ref = metadata.get("credential_ref")
        credential_type = (metadata.get("credential_type") or "").lower()

        if not account_id or not credential_ref:
            raise ValueError("Missing account_id or credential_ref in orchestration")

        # 2. Resolve credentials
        logger.info("Resolving credentials for account=%s provider=%s", account_id, provider)
        credentials = _resolve_credentials(account_id, credential_ref, credential_type, provider)

        # 3. Create scanner and authenticate
        scanner = _get_scanner(provider, credentials)
        scanner.authenticate()
        logger.info("Authentication successful")

        # 4. Build scan metadata (same shape as api_server.py passes to DiscoveryEngine)
        scan_metadata = {
            "discovery_scan_id": discovery_scan_id,
            "orchestration_id": orchestration_id,
            "provider": provider,
            "tenant_id": metadata.get("tenant_id", "default-tenant"),
            "customer_id": metadata.get("customer_id", "default"),
            "hierarchy_id": metadata.get("hierarchy_id") or account_id,
            "hierarchy_type": metadata.get("hierarchy_type", "account"),
            "include_services": metadata.get("include_services"),
            "include_regions": metadata.get("include_regions"),
            "exclude_regions": metadata.get("exclude_regions"),
            "use_database": True,
        }

        # 5. Run scan (multi-threaded, writes to DB)
        discovery_engine = DiscoveryEngine(scanner=scanner, db_manager=db_manager)
        logger.info("Starting discovery scan...")
        asyncio.run(discovery_engine.run_scan(metadata=scan_metadata))

        # 6. Update orchestration table
        try:
            update_engine_scan_id(
                orchestration_id=orchestration_id,
                engine="discovery",
                scan_id=discovery_scan_id,
            )
        except Exception as exc:
            logger.warning("Failed to update orchestration table: %s", exc)

        logger.info("Discovery scan COMPLETED scan_id=%s", discovery_scan_id)

    except (AuthenticationError, DiscoveryError, ValueError) as exc:
        logger.error("Discovery scan FAILED: %s", exc)
        try:
            db_manager.update_scan_status(discovery_scan_id, "failed")
        except Exception:
            pass
        sys.exit(1)

    except Exception as exc:
        logger.error("Discovery scan FAILED (unexpected): %s\n%s", exc, traceback.format_exc())
        try:
            db_manager.update_scan_status(discovery_scan_id, "failed")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
