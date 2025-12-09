#!/usr/bin/env python3
"""
OCI Smart Corrector
Applies safe, low-risk corrections to OCI YAMLs (severity/logic defaults).
Creates backups before modifying files.
"""

import argparse
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import yaml

SERVICES_DIR = Path(__file__).parent / "services"
BACKUP_DIR = Path(__file__).parent / "services_backup" / f"auto_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"


def _load(path: Path) -> Dict[str, Any]:
    with open(path, "r") as fh:
        return yaml.safe_load(fh) or {}


def _save(path: Path, data: Dict[str, Any]) -> None:
    with open(path, "w") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)


def _correct_service(service_name: str, rules_path: Path) -> Dict[str, int]:
    data = _load(rules_path)
    svc = data.get(service_name) or {}
    checks = svc.get("checks") or []

    changes = 0
    for chk in checks:
        if not chk.get("severity"):
            chk["severity"] = "medium"
            changes += 1
        if not chk.get("logic"):
            chk["logic"] = "AND"
            changes += 1
    if changes:
        data[service_name]["checks"] = checks
        _save(rules_path, data)
    return {"changes": changes}


def run_corrections(dry_run: bool) -> Dict[str, int]:
    summary = {"services_updated": 0, "changes": 0}
    if not dry_run:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    for svc_dir in SERVICES_DIR.iterdir():
        if not svc_dir.is_dir() or svc_dir.name == "__pycache__":
            continue
        rules_path = svc_dir / "rules" / f"{svc_dir.name}.yaml"
        if not rules_path.exists():
            continue

        if not dry_run:
            svc_backup_dir = BACKUP_DIR / svc_dir.name / "rules"
            svc_backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(rules_path, svc_backup_dir / rules_path.name)

        result = _correct_service(svc_dir.name, rules_path)
        if result["changes"]:
            summary["services_updated"] += 1
            summary["changes"] += result["changes"]

    return summary


def main():
    ap = argparse.ArgumentParser(description="Apply safe default corrections to OCI YAMLs")
    ap.add_argument("--dry-run", action="store_true", help="Do not write changes, just report")
    args = ap.parse_args()

    summary = run_corrections(dry_run=args.dry_run)
    summary["dry_run"] = args.dry_run
    if not args.dry_run and summary["services_updated"] == 0:
        summary["note"] = "No changes applied; YAMLs already had defaults."
    print(summary)


if __name__ == "__main__":
    main()
