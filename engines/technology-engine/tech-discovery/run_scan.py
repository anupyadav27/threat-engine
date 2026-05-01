"""
tech-discovery — K8s Job entry point.

Runs a technology discovery scan for one account (one technology instance)
and stores raw JSONB results to tech_discovery_findings.

Usage::

    python run_scan.py \\
        --scan-run-id 337a7425-... \\
        --account-id acct_abc123

Mirrors: engines/discoveries/run_scan.py
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from common.database.tech_db_manager import TechDBManager
from executor.yaml_executor import TechYAMLExecutor
from common.models.connector_interface import TechScanner, AuthenticationError, DiscoveryError

# Category scanners
from providers.db.scanner           import DBScanner
from providers.linux.scanner        import LinuxScanner
from providers.network.scanner      import NetworkScanner
from providers.web_server.scanner   import WebServerScanner
from providers.virtualization.scanner import VirtualizationScanner
from providers.container.scanner    import ContainerScanner
from providers.devops.scanner       import DevOpsScanner
from providers.collaboration.scanner import CollaborationScanner
from providers.data_platform.scanner import DataPlatformScanner
from providers.middleware.scanner   import MiddlewareScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("tech_discovery")

# Maps tech_category → scanner class
CATEGORY_SCANNERS: dict[str, type[TechScanner]] = {
    "db":             DBScanner,
    "linux":          LinuxScanner,
    "network":        NetworkScanner,
    "web_server":     WebServerScanner,
    "virtualization": VirtualizationScanner,
    "container":      ContainerScanner,
    "devops":         DevOpsScanner,
    "collaboration":  CollaborationScanner,
    "data_platform":  DataPlatformScanner,
    "middleware":     MiddlewareScanner,
}


async def run(scan_run_id: str, account_id: str) -> None:
    db = TechDBManager()
    credential = db.get_credential(account_id=account_id)
    if not credential:
        raise ValueError(f"No credential found for account_id={account_id}")

    tech_type     = credential["tech_type"]
    tech_category = credential["tech_category"]

    scanner_cls = CATEGORY_SCANNERS.get(tech_category)
    if not scanner_cls:
        raise ValueError(f"No scanner for category: {tech_category}")

    scanner = scanner_cls(
        scan_run_id=scan_run_id,
        account_id=account_id,
        credential=credential,
        db_manager=db,
    )

    logger.info(f"scan_run_id={scan_run_id} tech_type={tech_type} host={credential.get('host')}")

    try:
        await scanner.connect()
        findings = await scanner.discover()
        db.upsert_findings(scan_run_id=scan_run_id, findings=findings)
        db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-discovery", count=len(findings))
        logger.info(f"Discovery complete: {len(findings)} findings")
    except AuthenticationError as e:
        logger.error(f"Auth failed: {e}")
        db.mark_engine_failed(scan_run_id=scan_run_id, engine="tech-discovery", error=str(e))
        sys.exit(1)
    except DiscoveryError as e:
        logger.error(f"Discovery error: {e}")
        db.mark_engine_failed(scan_run_id=scan_run_id, engine="tech-discovery", error=str(e))
        sys.exit(1)
    finally:
        await scanner.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id",  required=True)
    parser.add_argument("--account-id",   required=True)
    args = parser.parse_args()
    asyncio.run(run(args.scan_run_id, args.account_id))


if __name__ == "__main__":
    main()
