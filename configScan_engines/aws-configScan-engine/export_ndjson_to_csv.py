#!/usr/bin/env python3
"""
Export a scan folder's NDJSON outputs into CSV for review.

This is intentionally lightweight and does NOT require pandas.

Defaults:
- reads:  <scan_folder>/results.ndjson and <scan_folder>/inventory.ndjson
- writes: <scan_folder>/csv_exports/findings.csv and <scan_folder>/csv_exports/inventory.csv

Option A compatibility:
- results.ndjson may be "minimal finding" lines (schema_version=cspm_finding.v1)
- or legacy "task" lines containing checks[]; we will flatten them
"""

import argparse
import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator, List, Optional


def _iter_ndjson(path: str) -> Iterator[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def _service_category_fallback(service: str) -> str:
    category_map = {
        "ec2": "Compute",
        "lambda": "Compute",
        "s3": "Storage",
        "rds": "Database",
        "dynamodb": "Database",
        "iam": "Security",
        "kms": "Security",
        "secretsmanager": "Security",
        "vpc": "Network",
        "elb": "Network",
        "cloudfront": "Network",
        "route53": "Network",
        "sns": "Application",
        "sqs": "Application",
        "cloudwatch": "Monitoring",
        "account": "Account",
    }
    return category_map.get((service or "").lower(), "General")


def _flatten_result_obj_to_findings(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Minimal finding already
    if obj.get("schema_version") == "cspm_finding.v1" and obj.get("rule_id"):
        return [obj]

    # Task wrapper with checks[]
    if isinstance(obj.get("checks"), list):
        out: List[Dict[str, Any]] = []
        for c in obj.get("checks") or []:
            if not isinstance(c, dict):
                continue
            status = c.get("status") or c.get("result") or "UNKNOWN"
            created_at = c.get("created_at") or datetime.utcnow().isoformat() + "Z"
            out.append(
                {
                    "schema_version": "cspm_finding.v1",
                    "tenant_id": obj.get("tenant_id") or "",
                    "scan_run_id": obj.get("scan_run_id") or obj.get("scan_id") or "",
                    "provider": obj.get("provider") or "aws",
                    "account_id": obj.get("account_id") or obj.get("account") or "",
                    "region": obj.get("region") or "global",
                    "scope": obj.get("scope") or "",
                    "service": obj.get("service") or "",
                    "rule_id": c.get("rule_id") or "",
                    "status": status,
                    "result": status,
                    "created_at": created_at,
                    "resource_uid": c.get("resource_uid") or "",
                    "resource_arn": c.get("resource_arn") or "",
                    "resource_id": c.get("resource_id") or "",
                    "resource_type": c.get("resource_type") or "",
                    "resource_name": c.get("resource_name") or c.get("name") or c.get("Name") or "",
                }
            )
        return out

    return []


def export_findings(results_path: str, out_csv_path: str) -> None:
    # Import here so running exporter doesn't force engine imports in all contexts.
    try:
        from utils.metadata_loader import get_metadata_loader
    except Exception:
        get_metadata_loader = None  # type: ignore

    loader = get_metadata_loader() if get_metadata_loader else None

    fieldnames = [
        "scan_run_id",
        "provider",
        "account_id",
        "region",
        "scope",
        "service",
        "rule_id",
        "status",
        "created_at",
        "resource_uid",
        "resource_arn",
        "resource_id",
        "resource_type",
        "resource_name",
        # Enriched (derived via rule_id; not duplicated in NDJSON Option A)
        "title",
        "severity",
        "check_category",
        "finding_message",
        "compliance_frameworks",
    ]

    os.makedirs(os.path.dirname(out_csv_path), exist_ok=True)
    with open(out_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for obj in _iter_ndjson(results_path):
            for finding in _flatten_result_obj_to_findings(obj):
                service = finding.get("service") or ""
                rule_id = finding.get("rule_id") or ""

                meta = {}
                if loader and service and rule_id:
                    try:
                        meta = loader.get_check_metadata(service, rule_id) or {}
                    except Exception:
                        meta = {}

                title = meta.get("title") or rule_id
                severity = meta.get("severity") or ""
                check_category = meta.get("category") or _service_category_fallback(service)
                frameworks = meta.get("frameworks") or []
                if not isinstance(frameworks, list):
                    frameworks = [str(frameworks)]

                finding_message = meta.get("description") or ""
                if not finding_message:
                    status = finding.get("status") or finding.get("result") or "UNKNOWN"
                    finding_message = f"{status}: {rule_id}"

                row = {k: (finding.get(k, "") if finding.get(k, "") is not None else "") for k in fieldnames}
                row.update(
                    {
                        "title": title,
                        "severity": severity,
                        "check_category": check_category,
                        "finding_message": finding_message,
                        "compliance_frameworks": json.dumps(frameworks, ensure_ascii=False),
                    }
                )
                writer.writerow(row)


def export_inventory(inventory_path: str, out_csv_path: str) -> None:
    fieldnames = [
        "scan_run_id",
        "provider",
        "account_id",
        "region",
        "scope",
        "service",
        "resource_type",
        "resource_id",
        "resource_arn",
        "resource_uid",
        "name",
        "environment",
        "category",
        "lifecycle_state",
        "health_status",
        "created_at",
        "updated_at",
        "tags",
        "discovery_operation",
        "raw_refs",
        "hash_sha256",
    ]

    os.makedirs(os.path.dirname(out_csv_path), exist_ok=True)
    with open(out_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for asset in _iter_ndjson(inventory_path):
            if not isinstance(asset, dict):
                continue
            meta = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
            tags = asset.get("tags") if isinstance(asset.get("tags"), dict) else {}
            row = {
                "scan_run_id": asset.get("scan_run_id") or "",
                "provider": asset.get("provider") or "",
                "account_id": asset.get("account_id") or "",
                "region": asset.get("region") or "",
                "scope": asset.get("scope") or "",
                "service": asset.get("service") or "",
                "resource_type": asset.get("resource_type") or "",
                "resource_id": asset.get("resource_id") or "",
                "resource_arn": asset.get("resource_arn") or "",
                "resource_uid": asset.get("resource_uid") or "",
                "name": asset.get("name") or "",
                "environment": asset.get("environment") or "",
                "category": asset.get("category") or "",
                "lifecycle_state": asset.get("lifecycle_state") or "",
                "health_status": asset.get("health_status") or "",
                "created_at": asset.get("created_at") or meta.get("created_at") or "",
                "updated_at": asset.get("updated_at") or meta.get("updated_at") or "",
                "tags": json.dumps(tags, ensure_ascii=False),
                "discovery_operation": meta.get("discovery_operation") or "",
                "raw_refs": json.dumps(meta.get("raw_refs") or [], ensure_ascii=False),
                "hash_sha256": asset.get("hash_sha256") or "",
            }
            writer.writerow(row)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scan-folder",
        required=True,
        help="Path to scan output folder (contains results.ndjson, inventory.ndjson, summary.json).",
    )
    args = parser.parse_args(argv)

    scan_folder = os.path.abspath(args.scan_folder)
    results_path = os.path.join(scan_folder, "results.ndjson")
    inventory_path = os.path.join(scan_folder, "inventory.ndjson")

    csv_dir = os.path.join(scan_folder, "csv_exports")
    findings_csv = os.path.join(csv_dir, "findings.csv")
    inventory_csv = os.path.join(csv_dir, "inventory.csv")

    export_findings(results_path, findings_csv)
    export_inventory(inventory_path, inventory_csv)

    print(f"Wrote: {findings_csv}")
    print(f"Wrote: {inventory_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


