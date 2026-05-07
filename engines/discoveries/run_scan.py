"""
Discovery Scanner — K8s Job entry point.

Runs a full multi-threaded discovery scan for one account and exits.
Created by the Discovery API when ``POST /api/v1/discovery`` is called.

Usage::

    python -m run_scan \
        --orchestration-id 337a7425-5a53-4664-8569-04c1f0d6abf0 \
        --scan-run-id disc_abc123

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
from providers.alicloud.scanner.service_scanner import AliCloudDiscoveryScanner
from providers.kubernetes.scanner.service_scanner import K8sDiscoveryScanner

# Orchestration helpers
from engine_common.orchestration import get_orchestration_metadata

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
    "alicloud": AliCloudDiscoveryScanner,
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

    # CLI / DefaultAzureCredential: no Secrets Manager fetch needed
    # account_id == subscription_id for Azure
    if cred_type == "cli":
        return {
            "credential_type": "cli",
            "subscription_id": account_id,
        }

    # K8s in-cluster: no Secrets Manager fetch needed — uses pod service account
    if cred_type in ("in_cluster", "k8s_in_cluster"):
        return {
            "credential_type": "in_cluster",
            "account_id": account_id,
            "cluster_name": account_id,
        }

    # Key-based: fetch from Secrets Manager
    storage = SecretsManagerStorage()
    secret_data = storage.retrieve(account_id=account_id)

    if not isinstance(secret_data, dict) or not secret_data:
        raise ValueError(f"Empty/invalid credentials for account {account_id}")

    # Normalize credential_type per provider
    raw_type = (secret_data.get("credential_type") or "").lower()

    if provider == "aws":
        if raw_type in ("aws_access_key", "access_key", "access_key_id"):
            secret_data["credential_type"] = "access_key"
        elif "role" in raw_type:
            secret_data["credential_type"] = "iam_role"

    elif provider == "gcp":
        # GCP service account key stored under "credentials" or "service_account_json"
        if raw_type in ("service_account", "service_account_key", "gcp_service_account"):
            secret_data["credential_type"] = "service_account"
        # Ensure the SA JSON is accessible under the key the GCP scanner expects
        if not secret_data.get("credentials") and not secret_data.get("service_account_json"):
            # Secret may have been stored with SA JSON at top level (type: service_account)
            if secret_data.get("type") == "service_account":
                secret_data["credentials"] = {k: v for k, v in secret_data.items()
                                               if k not in ("credential_type", "account_id",
                                                            "created_at", "expires_at")}

    elif provider == "azure":
        if raw_type in ("service_principal", "client_secret", "azure_service_principal"):
            secret_data["credential_type"] = "service_principal"

    elif provider == "oci":
        if raw_type in ("api_key", "oci_api_key"):
            secret_data["credential_type"] = "api_key"

    elif provider == "ibm":
        if raw_type in ("api_key", "ibm_api_key"):
            secret_data["credential_type"] = "api_key"

    elif provider in ("k8s", "kubernetes"):
        if raw_type in ("in_cluster", "kubeconfig"):
            secret_data["credential_type"] = raw_type or "in_cluster"

    elif provider == "alicloud":
        if raw_type in ("access_key", "alicloud_access_key"):
            secret_data["credential_type"] = "access_key"

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
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan_run_id from scan_orchestration")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(
        "Discovery scanner starting scan_run_id=%s",
        scan_run_id,
    )

    db_manager = DatabaseManager()

    # DCAT-01: ensure discovery_emit_failures table exists at scan startup
    # so failure-flush at scan-end can always insert without table-missing errors.
    try:
        from common.jinja_renderer import ensure_failure_table as _ensure_table
        from engine_common.db_connections import get_discoveries_conn
        _conn = get_discoveries_conn()
        try:
            _ensure_table(_conn)
            logger.info("[DCAT-EMIT] discovery_emit_failures table ensured")
        finally:
            try: _conn.close()
            except Exception: pass
    except Exception as _ddl_err:
        logger.warning("[DCAT-EMIT] could not ensure failure table: %s", _ddl_err)

    # SIGTERM handler — mark scan as failed on timeout/preemption
    def _handle_sigterm(signum, frame):
        logger.warning("SIGTERM received — marking scan as failed (timeout/preemption)")
        try:
            db_manager.update_scan_status(scan_run_id, "failed")
        except Exception:
            pass
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

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
            "scan_run_id": scan_run_id,
            "provider": provider,
            "tenant_id": metadata.get("tenant_id", "default-tenant"),
            "customer_id": metadata.get("customer_id", "default"),
            "account_id": metadata.get("account_id") or account_id,
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

        # 6. Orchestration table uses scan_run_id directly (no per-engine scan IDs)

        logger.info("Discovery scan COMPLETED scan_id=%s", scan_run_id)

        # DCAT-01/02: flush Jinja-render failures to discovery_emit_failures.
        # Each provider scanner maintains its own _emit_failure_sink.
        # We try to flush both AWS and K8s sinks (only the active provider
        # will have rows; the other will be a no-op).
        for _mod_path in (
            "providers.aws.scanner.service_scanner",
            "providers.kubernetes.scanner.service_scanner",
            "providers.azure.scanner.service_scanner",
        ):
            try:
                _mod = __import__(_mod_path, fromlist=["_emit_failure_sink"])
                _sink = getattr(_mod, "_emit_failure_sink", None)
                if not _sink:
                    continue
                from common.jinja_renderer import flush_failures
                from engine_common.db_connections import get_discoveries_conn
                _conn = get_discoveries_conn()
                try:
                    flush_failures(
                        _conn,
                        rows=list(_sink),
                        scan_run_id=str(scan_run_id),
                        tenant_id=str(metadata.get("tenant_id") or ""),
                        provider=str(metadata.get("provider") or ""),
                    )
                    _sink.clear()
                    logger.info("[DCAT-EMIT] flushed failures from %s", _mod_path)
                finally:
                    try: _conn.close()
                    except Exception: pass
            except Exception as _flush_err:
                logger.warning("[DCAT-EMIT] flush %s failed: %s", _mod_path, _flush_err)

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("discoveries", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

    except (AuthenticationError, DiscoveryError, ValueError) as exc:
        logger.error("Discovery scan FAILED: %s", exc)
        try:
            db_manager.update_scan_status(scan_run_id, "failed")
        except Exception:
            pass
        sys.exit(1)

    except Exception as exc:
        logger.error("Discovery scan FAILED (unexpected): %s\n%s", exc, traceback.format_exc())
        try:
            db_manager.update_scan_status(scan_run_id, "failed")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
