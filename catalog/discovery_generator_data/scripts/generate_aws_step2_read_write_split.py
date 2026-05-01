#!/usr/bin/env python3
"""
Generate step2_read_operation_registry.json and step2_write_operation_registry.json
for all AWS services by splitting step1_api_driven_registry.json operations.

Alignment with GCP model:
  step2_read_operation_registry.json  → Describe* / List* / Get*  (feeds step3)
  step2_write_operation_registry.json → Create* / Delete* / Update* / all non-read ops

Schema mirrors the GCP step2 layout adapted for AWS.
"""

import glob
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Classification ────────────────────────────────────────────────────────────
READ_PREFIXES = ("Describe", "List", "Get", "Search", "Scan", "Query", "Fetch")

# Map prefix → kind label (read side)
def read_kind(name: str) -> str:
    if name.startswith("Describe"):
        return "read_describe"
    if name.startswith("List"):
        return "read_list"
    if name.startswith("Get"):
        return "read_get"
    if name.startswith(("Search", "Scan", "Query", "Fetch")):
        return "read_query"
    return "read_other"

# Map prefix → kind label (write side)
def write_kind(name: str) -> str:
    if name.startswith("Create") or name.startswith("Put") or name.startswith("Add"):
        return "write_create"
    if name.startswith("Delete") or name.startswith("Remove") or name.startswith("Deregister"):
        return "write_delete"
    if name.startswith(("Update", "Modify", "Set", "Change", "Replace", "Reset")):
        return "write_update"
    return "write_other"

def is_read(name: str) -> bool:
    return name.startswith(READ_PREFIXES)

# ── Builder ───────────────────────────────────────────────────────────────────
def build_split(service_dir: Path) -> tuple[dict, dict]:
    """Return (read_registry, write_registry) for a service directory."""
    step1_path = service_dir / "step1_api_driven_registry.json"
    if not step1_path.exists():
        return None, None

    raw = json.loads(step1_path.read_text())
    svc_key = list(raw.keys())[0]
    svc_data = raw[svc_key]
    service_name = svc_data.get("service", svc_key)

    now_ts = datetime.now(timezone.utc).isoformat()

    read_ops: dict = {}
    write_ops: dict = {}

    for bucket in ("independent", "dependent"):
        ops_list = svc_data.get(bucket, [])
        for op in ops_list:
            name = op.get("operation", "")
            if not name:
                continue
            independent = (bucket == "independent")
            entry = {
                "operation":       name,
                "service":         service_name,
                "csp":             "aws",
                "independent":     independent,
                "python_method":   op.get("python_method", ""),
                "yaml_action":     op.get("yaml_action", ""),
                "required_params": op.get("required_params", []),
                "optional_params": op.get("optional_params", []),
                "output_fields":   op.get("output_fields", {}),
            }
            if is_read(name):
                entry["kind"] = read_kind(name)
                read_ops[name] = entry
            else:
                entry["kind"] = write_kind(name)
                write_ops[name] = entry

    read_registry = {
        "service":            service_name,
        "csp":                "aws",
        "generated_at":       now_ts,
        "total_operations":   len(read_ops),
        "independent_count":  sum(1 for v in read_ops.values() if v["independent"]),
        "dependent_count":    sum(1 for v in read_ops.values() if not v["independent"]),
        "operations":         read_ops,
    }

    write_registry = {
        "service":            service_name,
        "csp":                "aws",
        "generated_at":       now_ts,
        "total_operations":   len(write_ops),
        "independent_count":  sum(1 for v in write_ops.values() if v["independent"]),
        "dependent_count":    sum(1 for v in write_ops.values() if not v["independent"]),
        "operations":         write_ops,
    }

    return read_registry, write_registry


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    aws_root = Path(__file__).parent.parent / "aws"
    service_dirs = sorted(
        d for d in aws_root.iterdir()
        if d.is_dir() and (d / "step1_api_driven_registry.json").exists()
    )

    print(f"Found {len(service_dirs)} AWS services with step1 data")

    skipped = 0
    processed = 0
    total_read = 0
    total_write = 0

    for svc_dir in service_dirs:
        read_reg, write_reg = build_split(svc_dir)
        if read_reg is None:
            skipped += 1
            continue

        (svc_dir / "step2_read_operation_registry.json").write_text(
            json.dumps(read_reg, indent=2)
        )
        (svc_dir / "step2_write_operation_registry.json").write_text(
            json.dumps(write_reg, indent=2)
        )

        r = read_reg["total_operations"]
        w = write_reg["total_operations"]
        total_read += r
        total_write += w
        processed += 1
        print(f"  {svc_dir.name:<40}  read={r:>4}  write={w:>4}")

    print()
    print(f"Done: {processed} services processed, {skipped} skipped")
    print(f"Total read ops:  {total_read}")
    print(f"Total write ops: {total_write}")


if __name__ == "__main__":
    main()
