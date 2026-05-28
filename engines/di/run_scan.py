"""
engine-di Scan Entry Point (K8s Job)

Runs the 3-phase DI scan for one cloud account:
  Phase 0: Enumerate all resources → canonical UIDs
  Phase 1: Enrich enumerated resources with detail data
  Phase 2: Write to asset_inventory + asset_relationships

Usage:
    python run_scan.py --scan-run-id <uuid>

Environment:
    DI_DB_HOST / DI_DB_NAME / DI_DB_USER / DI_DB_PASSWORD
    INVENTORY_DB_HOST / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
    AWS_RETRY_MODE=adaptive
    AWS_MAX_ATTEMPTS=10
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

os.environ.setdefault("AWS_RETRY_MODE", "adaptive")
os.environ.setdefault("AWS_MAX_ATTEMPTS", "10")

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("di.run_scan")

from engine_common.orchestration import get_orchestration_metadata
from engine_onboarding.storage.secrets_manager_storage import SecretsManagerStorage

from di_engine.phase0.enumerator import run_phase0
from di_engine.phase2.writer import write_assets, write_errors, update_scan_status
# relationship_writer removed — per-engine writers (network, IAM, encryption) write
# directly to asset_relationships in DI DB via engine_common.relationship_writer.


def _resolve_credentials(account_id: str, credential_ref: str, credential_type: str, provider: str) -> dict:
    """Resolve credentials from Secrets Manager (same logic as discoveries run_scan.py)."""
    cred_type = (credential_type or "").lower()

    if cred_type in ("aws_iam_role", "iam_role", "role", "managed_identity"):
        return {"credential_type": cred_type, "role_arn": credential_ref}

    if cred_type == "cli":
        return {"credential_type": "cli", "subscription_id": account_id}

    if cred_type in ("in_cluster", "k8s_in_cluster"):
        return {"credential_type": "in_cluster", "account_id": account_id, "cluster_name": account_id}

    storage = SecretsManagerStorage()
    secret_data = storage.retrieve(account_id=account_id)

    if not isinstance(secret_data, dict) or not secret_data:
        raise ValueError(f"Empty/invalid credentials for account {account_id}")

    raw_type = (secret_data.get("credential_type") or "").lower()

    if provider == "aws":
        if raw_type in ("aws_access_key", "access_key", "access_key_id"):
            secret_data["credential_type"] = "access_key"
        elif "role" in raw_type:
            secret_data["credential_type"] = "iam_role"
    elif provider == "gcp":
        if raw_type in ("service_account", "service_account_key", "gcp_service_account"):
            secret_data["credential_type"] = "service_account"
        if not secret_data.get("credentials") and not secret_data.get("service_account_json"):
            if secret_data.get("type") == "service_account":
                secret_data["credentials"] = {
                    k: v for k, v in secret_data.items()
                    if k not in ("credential_type", "account_id", "created_at", "expires_at")
                }
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
        secret_data["credential_type"] = raw_type or "in_cluster"
    elif provider == "alicloud":
        if raw_type in ("access_key", "alicloud_access_key"):
            secret_data["credential_type"] = "access_key"

    return secret_data


async def run_scan(scan_run_id: str, services: list[str] | None = None) -> None:
    """Run the full 3-phase DI scan for all accounts in the scan orchestration."""
    logger.info("DI scan starting: scan_run_id=%s services=%s", scan_run_id, services or "all")

    # ── Load orchestration metadata ────────────────────────────────────────────
    meta = get_orchestration_metadata(scan_run_id)
    if not meta:
        raise RuntimeError(f"No orchestration metadata for scan_run_id={scan_run_id}")

    tenant_id = meta.get("tenant_id") or meta.get("engine_tenant_id", "")
    account_id = meta.get("account_id", "")
    provider = (meta.get("provider") or "aws").lower()
    credential_ref = meta.get("credential_ref", "")
    credential_type = meta.get("credential_type", "")
    include_regions  = meta.get("include_regions") or None   # None = scan all
    exclude_regions  = meta.get("exclude_regions") or None   # None = skip none
    exclude_services = meta.get("exclude_services") or None  # None = skip none

    # CLI --services takes priority; fall back to include_services from DB
    if services is None:
        meta_services = meta.get("include_services")
        if isinstance(meta_services, list) and meta_services:
            services = meta_services

    logger.info(
        "Scan metadata: tenant=%s account=%s provider=%s "
        "include_regions=%s exclude_regions=%s include_services=%s exclude_services=%s",
        tenant_id, account_id, provider,
        include_regions or "all", exclude_regions or "none",
        services or "all", exclude_services or "none",
    )

    update_scan_status(
        scan_run_id=scan_run_id,
        tenant_id=tenant_id,
        status="running",
        phase=0,
    )

    # ── Resolve credentials ────────────────────────────────────────────────────
    credentials = _resolve_credentials(account_id, credential_ref, credential_type, provider)

    # ── Phase 0: Enumerate ────────────────────────────────────────────────────
    logger.info("Starting Phase 0: enumerate")
    p0_result = await run_phase0(
        scan_run_id=scan_run_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        credentials=credentials,
        include_regions=include_regions,
        exclude_regions=exclude_regions,
        include_services=services,
        exclude_services=exclude_services,
    )

    # Enumeration + enrichment are now a single pass (scanner runs root_op + enrich_ops
    # together). p0_result.rows already contain fully enriched data at phase=1.
    enriched_rows = p0_result.rows
    all_errors = p0_result.errors

    update_scan_status(
        scan_run_id=scan_run_id,
        tenant_id=tenant_id,
        status="running",
        phase=2,
        resources_enumerated=len(enriched_rows),
        resources_enriched=len(enriched_rows),
        error_count=len(all_errors),
    )

    # ── Phase 2: Write ────────────────────────────────────────────────────────
    logger.info("Starting Phase 2: write (%d rows)", len(enriched_rows))
    written = write_assets(enriched_rows)

    # Relationship edges are written by per-engine writers (network, IAM, encryption)
    # directly to asset_relationships — DI no longer writes this table.
    rels_written = 0

    # Write all enumeration errors
    errors_written = write_errors(all_errors)

    update_scan_status(
        scan_run_id=scan_run_id,
        tenant_id=tenant_id,
        status="completed",
        phase=2,
        resources_enumerated=len(enriched_rows),
        resources_enriched=len(enriched_rows),
        resources_written=written,
        relationships_written=rels_written,
        error_count=errors_written,
    )

    logger.info(
        "DI scan COMPLETE: scan_run_id=%s written=%d relationships=%d errors=%d",
        scan_run_id, written, rels_written, errors_written,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="engine-di scan entry point")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan_run_id")
    parser.add_argument(
        "--services", default=None,
        help="Comma-separated service filter for quick validation (e.g. ec2,s3,iam). "
             "Omit for full scan.",
    )
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    services = [s.strip() for s in args.services.split(",")] if args.services else None

    def _handle_sigterm(signum, frame):
        logger.warning("SIGTERM received — marking scan as failed")
        try:
            from di_engine.phase2.writer import update_scan_status as _upd
            _upd(scan_run_id=scan_run_id, tenant_id="", status="failed", phase=-1)
        except Exception:
            pass
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        asyncio.run(run_scan(scan_run_id, services=services))
    except Exception as e:
        logger.error("DI scan FAILED: %s", e, exc_info=True)
        try:
            from di_engine.phase2.writer import update_scan_status as _upd
            _upd(scan_run_id=scan_run_id, tenant_id="", status="failed", phase=-1)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
