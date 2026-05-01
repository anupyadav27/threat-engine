#!/usr/bin/env python3
"""
Build per-service identifier JSON from CSP inventory CSVs.
Output schema: resource_independent_methods, resource_dependent_methods, identifier_type, etc.
"""

import argparse
import csv
import json
import os
from pathlib import Path


# CSP key used as output directory name under workspace_root
CSP_CONFIG = {
    "aws": {
        "csv_path": "aws_services_data_fieldandinventories/services_resources_arn.csv",
        "pattern_column": "arn_pattern",
        "identifiers_column": "arn_identifiers",  # AWS uses arn_identifiers
        "identifier_type": "arn",
        "output_filename": "arn_identifier.json",
    },
    "alicloud": {
        "csv_path": "alibaba_services_data_fieldandinventories/services_resources_arn.csv",
        "pattern_column": "arn_pattern",
        "identifiers_column": "resource_identifiers",
        "identifier_type": "arn",
        "output_filename": "arn_identifier.json",
    },
    "azure": {
        "csv_path": "azure_services_data_fieldandinventories/services_resources_ids.csv",
        "pattern_column": "resource_id_pattern",
        "identifiers_column": "resource_identifiers",
        "identifier_type": "id",
        "output_filename": "id_identifier.json",
    },
    "gcp": {
        "csv_path": "gcp_services_data_fieldandinventories/services_resources_names.csv",
        "pattern_column": "resource_name_pattern",
        "identifiers_column": "resource_identifiers",
        "identifier_type": "name",
        "output_filename": "name_identifier.json",
    },
    "ibm": {
        "csv_path": "ibm_services_data_fieldandinventories/services_resources_crn.csv",
        "pattern_column": "crn_pattern",
        "identifiers_column": "resource_identifiers",
        "identifier_type": "crn",
        "output_filename": "crn_identifier.json",
    },
    "oci": {
        "csv_path": "oci_services_data_fieldandinventories/services_resources_ocids.csv",
        "pattern_column": "ocid_pattern",
        "identifiers_column": "resource_identifiers",
        "identifier_type": "ocid",
        "output_filename": "ocid_identifier.json",
    },
}


def parse_method_list(cell: str) -> list[str]:
    """Split semicolon-separated methods, strip, drop empty."""
    if not cell or not str(cell).strip():
        return []
    return [m.strip() for m in str(cell).split(";") if m.strip()]


def normalize_service_dir(service: str) -> str:
    """Use CSV service value as folder name; lowercase, spaces to hyphens."""
    return service.strip().lower().replace(" ", "-")


def build_json_row(
    row: dict,
    pattern_column: str,
    identifiers_column: str,
    identifier_type: str,
) -> dict:
    """Build one JSON object from a CSV row."""
    indep = parse_method_list(row.get("independent_methods", "") or "")
    dep = parse_method_list(row.get("dependent_methods", "") or "")
    # Calculate totals from method lists
    total_independent = len(indep)
    total_dependent = len(dep)
    
    pattern = (row.get(pattern_column) or "").strip()
    identifiers_from_csv = (row.get(identifiers_column) or "").strip()
    # Use CSV value as-is, no extraction logic

    return {
        "service": (row.get("service") or "").strip(),
        "resource": (row.get("resource") or "").strip(),
        "identifier_type": identifier_type,
        "pattern": pattern,
        "resource_identifiers": identifiers_from_csv,
        "resource_independent_methods": indep,
        "resource_dependent_methods": dep,
        "total_independent": total_independent,
        "total_dependent": total_dependent,
    }


def process_csp(
    csp_key: str,
    csv_base_path: Path,
    workspace_root: Path,
    dry_run: bool = False,
) -> int:
    """Read CSV for one CSP, write one JSON per service. Returns count of files written."""
    if csp_key not in CSP_CONFIG:
        raise ValueError(f"Unknown CSP: {csp_key}. Valid: {list(CSP_CONFIG)}")

    cfg = CSP_CONFIG[csp_key]
    csv_path = csv_base_path / cfg["csv_path"]
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    out_dir = workspace_root / csp_key
    pattern_col = cfg["pattern_column"]
    identifiers_col = cfg["identifiers_column"]
    identifier_type = cfg["identifier_type"]
    out_filename = cfg["output_filename"]

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        return 0

    count = 0
    for row in rows:
        service = (row.get("service") or "").strip()
        if not service:
            continue
        service_dir_name = normalize_service_dir(service)
        service_dir = out_dir / service_dir_name
        if not dry_run:
            service_dir.mkdir(parents=True, exist_ok=True)
        obj = build_json_row(row, pattern_col, identifiers_col, identifier_type)
        out_path = service_dir / out_filename
        if not dry_run:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(obj, f, indent=2, ensure_ascii=False)
        count += 1

    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build per-service identifier JSON from CSP inventory CSVs."
    )
    parser.add_argument(
        "csp",
        nargs="?",
        default="all",
        choices=["all"] + list(CSP_CONFIG),
        help="CSP to process (default: all)",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Workspace root (default: repo root)",
    )
    parser.add_argument(
        "--cspm-root",
        type=Path,
        default=Path("/Users/apple/Desktop/cspm"),
        help="Base path for CSP inventory CSVs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write files",
    )
    args = parser.parse_args()

    csps = list(CSP_CONFIG) if args.csp == "all" else [args.csp]
    total = 0
    for csp in csps:
        n = process_csp(csp, args.cspm_root, args.workspace_root, dry_run=args.dry_run)
        total += n
        print(f"{csp}: wrote {n} JSONs")
    print(f"Total: {total} files")


if __name__ == "__main__":
    main()
