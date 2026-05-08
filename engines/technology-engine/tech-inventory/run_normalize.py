"""
tech-inventory — K8s Job entry point.

Reads tech_discovery_findings, normalizes them into tech_inventory_assets,
and enriches assets with version/OS metadata.

Usage::

    python run_normalize.py \\
        --scan-run-id 337a7425-... \\
        --account-id acct_abc123

Mirrors: engines/inventory/run_normalize.py
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from common.database.tech_db_manager import TechDBManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("tech_inventory")


def _asset_id(account_id: str, resource_uid: str) -> str:
    return hashlib.sha256(f"{account_id}|{resource_uid}".encode()).hexdigest()[:16]


def _normalize_finding(finding: dict, scan_run_id: str) -> dict:
    """Convert one discovery finding row into an inventory asset dict."""
    raw: dict = finding.get("raw_data") or {}

    version   = raw.get("version") or raw.get("server_version") or raw.get("product_version")
    os_ver    = raw.get("os_version") or raw.get("os") or raw.get("kernel_version")
    asset_name = (
        raw.get("hostname")
        or raw.get("display_name")
        or raw.get("instance_name")
        or finding.get("resource_uid")
    )

    return {
        "asset_id":        _asset_id(finding["account_id"], finding["resource_uid"]),
        "scan_run_id":     scan_run_id,
        "tenant_id":       finding["tenant_id"],
        "account_id":      finding["account_id"],
        "credential_ref":  finding.get("credential_ref"),
        "credential_type": finding.get("credential_type"),
        "provider":        finding["provider"],
        "tech_category":   finding["tech_category"],
        "region":          finding.get("region"),
        "resource_uid":    finding["resource_uid"],
        "resource_type":   finding.get("resource_type"),
        "asset_name":      asset_name,
        "version":         str(version) if version else None,
        "os_version":      str(os_ver) if os_ver else None,
        "metadata":        raw,
        "severity":        finding.get("severity", "info"),
        "status":          "active",
    }


def run(scan_run_id: str, account_id: str) -> None:
    db = TechDBManager()

    raw_findings = db.get_findings_for_inventory(scan_run_id)
    if not raw_findings:
        logger.warning("No discovery findings for scan_run_id=%s", scan_run_id)
        db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-inventory", count=0)
        return

    # Deduplicate by resource_uid — keep the richest raw_data
    seen: dict[str, dict] = {}
    for f in raw_findings:
        uid = f["resource_uid"]
        if uid not in seen or len(str(f.get("raw_data", {}))) > len(str(seen[uid].get("raw_data", {}))):
            seen[uid] = f

    assets = [_normalize_finding(f, scan_run_id) for f in seen.values()]
    inserted = db.upsert_assets(assets)
    db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-inventory", count=inserted)
    logger.info("Inventory normalized: %d assets from %d findings", inserted, len(raw_findings))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--account-id",  required=True)
    args = parser.parse_args()
    try:
        run(args.scan_run_id, args.account_id)
    except Exception as exc:
        logger.error("tech-inventory failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
