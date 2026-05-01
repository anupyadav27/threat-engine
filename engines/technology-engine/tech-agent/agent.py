"""
agent.py — Tech Scan Agent entry point.

Runs on the target host (database, Linux OS, web server, etc.) and:
1. Pulls discovery + check catalog from the central tech-check server
2. Executes discovery locally (SQL / subprocess / docker)
3. Evaluates check rules against discovery results
4. Pushes PASS/FAIL findings to the central server via HTTPS

Usage::

    python agent.py \\
      --scan-run-id 337a7425-... \\
      --account-id  acct_pg_prod_01 \\
      --tech-type   postgresql \\
      --central-url https://tech-check.threat-engine.internal \\
      --token       <jwt>

Exit codes:
    0 — scan completed successfully
    1 — fatal error (catalog unavailable, all transports failed, etc.)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, Optional

from catalog_client import CatalogClient
from findings_client import FindingsClient
from local_executor import LocalExecutor
from rule_evaluator import RuleEvaluator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("tech-agent")


def _load_credential(credential_file: Optional[str]) -> Dict[str, Any]:
    """Load optional credential dict from a JSON file or env vars.

    Args:
        credential_file: Path to a JSON file containing DB credentials.
            When ``None`` the agent relies on env vars (DB_USER, DB_PASSWORD,
            DB_HOST, DB_PORT, DB_NAME).

    Returns:
        Dict with credential keys; may be empty when using env vars.
    """
    if credential_file:
        try:
            with open(credential_file) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not load credential file %s: %s", credential_file, exc)
    return {}


def run(
    scan_run_id: str,
    account_id: str,
    tech_type: str,
    tenant_id: str,
    central_url: Optional[str],
    token: Optional[str],
    credential_file: Optional[str],
) -> int:
    """Execute a full agent scan cycle.

    Args:
        scan_run_id: Pipeline scan run UUID.
        account_id: Account/host identifier passed to the central server.
        tech_type: Technology type to scan, e.g. ``postgresql``.
        tenant_id: Tenant UUID for the central server.
        central_url: Base URL of the tech-check engine.
        token: Bearer token for the central server.
        credential_file: Optional path to JSON credential file.

    Returns:
        Number of findings pushed on success.

    Raises:
        RuntimeError: On unrecoverable failures.
    """
    logger.info(
        "Starting tech-scan-agent scan_run_id=%s account_id=%s tech_type=%s",
        scan_run_id, account_id, tech_type,
    )

    # 1. Pull catalog
    catalog_client = CatalogClient(central_url=central_url, token=token)
    catalog = catalog_client.get_catalog(tech_type)
    discovery_entries = catalog.get("discovery_entries", [])
    check_rules = catalog.get("check_rules", [])
    logger.info(
        "Catalog loaded: %d discovery entries, %d check rules",
        len(discovery_entries), len(check_rules),
    )

    # 2. Run local discovery
    credential = _load_credential(credential_file)
    executor = LocalExecutor(tech_type=tech_type, credential=credential)
    discovery_results = executor.run(discovery_entries)
    logger.info("Discovery complete: %d entries executed", len(discovery_results))

    # 3. Evaluate rules
    evaluator = RuleEvaluator(
        scan_run_id=scan_run_id,
        account_id=account_id,
        tech_type=tech_type,
    )
    findings = evaluator.evaluate(check_rules, discovery_results)
    logger.info("Rule evaluation complete: %d findings", len(findings))

    # 4. Push findings
    if not central_url:
        logger.info("No central URL configured — printing findings to stdout only")
        for f in findings:
            print(json.dumps(f))
        return len(findings)

    findings_client = FindingsClient(central_url=central_url, token=token)
    inserted = findings_client.push(
        scan_run_id=scan_run_id,
        account_id=account_id,
        tenant_id=tenant_id,
        findings=findings,
    )
    logger.info("Scan complete — %d findings inserted", inserted)
    return inserted


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Tech Scan Agent — runs CIS technology compliance scanning locally "
            "on the target host and pushes findings to the central tech-check engine."
        )
    )
    parser.add_argument(
        "--scan-run-id",
        required=True,
        help="Pipeline scan run UUID (from orchestration)",
    )
    parser.add_argument(
        "--account-id",
        required=True,
        help="Account / host identifier (unique per onboarded asset)",
    )
    parser.add_argument(
        "--tech-type",
        required=True,
        help="Technology type to scan (postgresql, ubuntu, docker, …)",
    )
    parser.add_argument(
        "--central-url",
        default=os.getenv("CENTRAL_URL"),
        help="Base URL of the tech-check engine (default: $CENTRAL_URL)",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("AGENT_TOKEN"),
        help="Bearer token for the central server (default: $AGENT_TOKEN)",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.getenv("TENANT_ID", "default"),
        help="Tenant UUID (default: $TENANT_ID or 'default')",
    )
    parser.add_argument(
        "--credential-file",
        default=None,
        help="Path to JSON file with DB credentials (optional, uses env vars otherwise)",
    )

    args = parser.parse_args()

    try:
        run(
            scan_run_id=args.scan_run_id,
            account_id=args.account_id,
            tech_type=args.tech_type,
            tenant_id=args.tenant_id,
            central_url=args.central_url,
            token=args.token,
            credential_file=args.credential_file,
        )
    except Exception as exc:
        logger.error("tech-agent fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
