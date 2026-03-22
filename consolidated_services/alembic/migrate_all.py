#!/usr/bin/env python3
"""Run Alembic migrations for all engines sequentially.

Used by the Kubernetes pre-deploy Job and local development.

Usage:
    # Run upgrade head for all engines:
    python alembic/migrate_all.py

    # Dry-run (show current state, no migrations):
    python alembic/migrate_all.py --status

    # Stamp all DBs as being at head (for existing production DBs):
    python alembic/migrate_all.py --stamp-head

    # Specific engines only:
    python alembic/migrate_all.py --engines check inventory

    # Run from repo root:
    cd /path/to/threat-engine/shared/database
    python alembic/migrate_all.py
"""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# All engines in dependency order (onboarding first — it holds scan_orchestration)
ALL_ENGINES = [
    "onboarding",
    "discoveries",
    "check",
    "inventory",
    "threat",
    "compliance",
    "iam",
    "datasec",
    "secops",
]


def run_alembic(engine: str, command: list[str]) -> bool:
    """Run an alembic command for the given engine.

    Returns True on success, False on failure.
    """
    here = Path(__file__).parent.parent  # shared/database/
    cmd = [sys.executable, "-m", "alembic", "-x", f"engine={engine}", *command]
    env = {**os.environ, "ALEMBIC_ENGINE": engine}

    logger.info("[%s] Running: %s", engine, " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(here),
        env=env,
        capture_output=False,
    )
    if result.returncode != 0:
        logger.error("[%s] FAILED (exit %d)", engine, result.returncode)
        return False
    return True


def get_current(engine: str) -> None:
    """Show the current revision for an engine (informational)."""
    run_alembic(engine, ["current"])


def upgrade_head(engine: str) -> bool:
    return run_alembic(engine, ["upgrade", "head"])


def stamp_head(engine: str) -> bool:
    return run_alembic(engine, ["stamp", "head"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Alembic migrations for all engines.")
    parser.add_argument(
        "--engines",
        nargs="+",
        default=ALL_ENGINES,
        choices=ALL_ENGINES,
        metavar="ENGINE",
        help="Engines to migrate (default: all)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current revision for each engine (no migrations run)",
    )
    parser.add_argument(
        "--stamp-head",
        action="store_true",
        dest="stamp",
        help="Stamp all DBs as head WITHOUT running migrations (use on existing DBs)",
    )
    args = parser.parse_args()

    engines = args.engines
    logger.info("Engines: %s", engines)

    failed: list[str] = []

    for engine in engines:
        if args.status:
            get_current(engine)
        elif args.stamp:
            if not stamp_head(engine):
                failed.append(engine)
        else:
            if not upgrade_head(engine):
                failed.append(engine)

    if failed:
        logger.error("Migrations FAILED for: %s", failed)
        return 1

    logger.info("All migrations complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
