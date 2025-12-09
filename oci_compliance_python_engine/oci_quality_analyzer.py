#!/usr/bin/env python3
"""
OCI Quality Analyzer
Scans service YAMLs for common quality issues and produces a report.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import yaml

SERVICES_DIR = Path(__file__).parent / "services"
OUTPUT_DIR = Path(__file__).parent / "output"


def _load_yaml(path: Path) -> Dict[str, Any]:
    with open(path, "r") as fh:
        return yaml.safe_load(fh) or {}


def _analyze_service(service_name: str, rules_path: Path) -> Dict[str, Any]:
    data = _load_yaml(rules_path)
    svc = data.get(service_name) or {}
    discovery = svc.get("discovery") or []
    checks = svc.get("checks") or []

    issues: List[Dict[str, Any]] = []

    if not discovery:
        issues.append({"type": "missing_discovery", "message": "No discovery definitions"})
    if not checks:
        issues.append({"type": "missing_checks", "message": "No checks defined"})

    for idx, chk in enumerate(checks):
        check_id = chk.get("check_id") or f"{service_name}.check_{idx}"
        if not chk.get("severity"):
            issues.append({"type": "missing_severity", "check_id": check_id})
        if not chk.get("logic"):
            issues.append({"type": "missing_logic", "check_id": check_id})
        for field in chk.get("calls", [{}])[0].get("fields", []):
            path = field.get("path")
            if path in {"name", "id", "namespace"}:
                issues.append({"type": "suspicious_field_path", "check_id": check_id, "path": path})
        if "TODO" in json.dumps(chk):
            issues.append({"type": "placeholder_values", "check_id": check_id})

    return {
        "service": service_name,
        "rule_file": str(rules_path),
        "checks": len(checks),
        "discovery_defs": len(discovery),
        "issues": issues,
        "issue_count": len(issues),
    }


def run_analysis() -> Dict[str, Any]:
    reports: List[Dict[str, Any]] = []

    for svc_dir in SERVICES_DIR.iterdir():
        if not svc_dir.is_dir() or svc_dir.name == "__pycache__":
            continue
        rules_file = svc_dir / "rules" / f"{svc_dir.name}.yaml"
        if not rules_file.exists():
            continue
        reports.append(_analyze_service(svc_dir.name, rules_file))

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "services_analyzed": len(reports),
        "total_issues": sum(r["issue_count"] for r in reports),
        "reports": reports,
    }

    OUTPUT_DIR.mkdir(exist_ok=True)
    out_file = OUTPUT_DIR / f"oci_quality_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps({"summary_file": str(out_file), "services": summary["services_analyzed"], "issues": summary["total_issues"]}, indent=2))
    return summary


def main():
    run_analysis()


if __name__ == "__main__":
    main()
