#!/usr/bin/env python3
"""
Generate step2_read_operation_registry.json and step2_write_operation_registry.json
for all Azure services from step1_api_driven_registry.json.

Azure uses REST-style op names (not Pascal-case like AWS):
  READ:  list, list_by_*, list_all, get, get_*, *_List, *_Get, check_*, get_entity_tag
  WRITE: begin_*, create*, update*, delete*, regenerate*, cancel*, start, stop,
         restart, invoke*, rotate*, swap*, trigger*, run*, failover*, promote*
"""

import glob
import json
import re
from datetime import datetime, timezone
from pathlib import Path

AZURE_ROOT = Path(__file__).parent.parent / "azure"
SKIP = {"temp_code", "__pycache__"}

# ── Classification ─────────────────────────────────────────────────────────────

READ_EXACT  = {"list", "get", "list_all", "check_name_availability", "get_entity_tag"}

READ_STARTS = (
    "list_", "get_", "list_all",
)

READ_ENDS   = ("_list", "_get", "_list_all")

# PascalCase mixed names like 'Operations_List', 'Clusters_Get'
READ_PASCAL_ENDS = ("_list", "_get", "_listbyresourcegroup", "_listbysubscription",
                    "_listall", "_listkeys")

WRITE_STARTS = (
    "begin_", "create", "update", "delete", "put_",
    "regenerate", "cancel", "failover", "promote",
    "rotate", "swap", "trigger", "invoke", "run_",
    "start", "stop", "restart", "reboot", "reset",
    "enable_", "disable_", "activate", "deactivate",
    "add_", "remove_", "set_", "move_", "migrate",
    "import_", "export_", "sync_", "flush", "purge",
    "backup_", "restore_", "patch", "post_",
    "validate_", "execute_", "apply_", "refresh_",
)


def _is_read(name: str) -> bool:
    low = name.lower()

    if low in READ_EXACT:
        return True
    if any(low.startswith(p) for p in READ_STARTS):
        return True
    if any(low.endswith(s) for s in READ_ENDS):
        return True
    # PascalCase / Mixed like "Clusters_Get", "Operations_List"
    if "_" in name:
        low_last = name.split("_")[-1].lower()
        if low_last in ("get", "list", "listall", "listbyresourcegroup",
                        "listbysubscription", "listall", "listbyworkspace",
                        "listbyserver", "listbyservice", "listbyaccount"):
            return True

    return False


def _read_kind(name: str) -> str:
    low = name.lower()
    if "list" in low:
        return "read_list"
    if "get" in low or "check" in low:
        return "read_get"
    return "read_other"


def _write_kind(name: str) -> str:
    low = name.lower()
    if any(x in low for x in ("create", "begin_create", "put")):
        return "write_create"
    if any(x in low for x in ("delete", "begin_delete")):
        return "write_delete"
    if any(x in low for x in ("update", "begin_update", "patch", "set_",
                               "update_tags", "regenerate")):
        return "write_update"
    return "write_other"


# ── Builder ────────────────────────────────────────────────────────────────────

def build_split(svc_dir: Path) -> tuple[dict, dict] | tuple[None, None]:
    step1_path = svc_dir / "step1_api_driven_registry.json"
    if not step1_path.exists():
        return None, None

    raw = json.loads(step1_path.read_text())
    svc_key = list(raw.keys())[0]
    svc     = raw[svc_key]
    service = svc.get("service", svc_key)
    csp     = svc.get("csp", "azure")
    now     = datetime.now(timezone.utc).isoformat()

    read_ops:  dict = {}
    write_ops: dict = {}

    for bucket in ("independent", "dependent"):
        ops_list = svc.get(bucket, [])
        for op in ops_list:
            name       = op.get("operation", "")
            independent = (bucket == "independent")

            entry = {
                "operation":       name,
                "service":         service,
                "csp":             csp,
                "independent":     independent,
                "python_method":   op.get("python_method", name),
                "yaml_action":     op.get("yaml_action", name),
                "required_params": op.get("required_params", []),
                "optional_params": op.get("optional_params", []),
                "output_fields":   op.get("output_fields", []),
                "main_output_field": op.get("main_output_field"),
                "item_fields":     op.get("item_fields", {}),
            }

            if _is_read(name):
                entry["kind"] = _read_kind(name)
                read_ops[name] = entry
            else:
                entry["kind"] = _write_kind(name)
                write_ops[name] = entry

    def _reg(ops: dict, label: str) -> dict:
        return {
            "service":           service,
            "csp":               csp,
            "generated_at":      now,
            "total_operations":  len(ops),
            "independent_count": sum(1 for v in ops.values() if v["independent"]),
            "dependent_count":   sum(1 for v in ops.values() if not v["independent"]),
            "operations":        ops,
        }

    return _reg(read_ops, "read"), _reg(write_ops, "write")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(
        d for d in AZURE_ROOT.iterdir()
        if d.is_dir()
        and d.name not in SKIP
        and (d / "step1_api_driven_registry.json").exists()
    )
    print(f"Azure: {len(svc_dirs)} services with step1")

    ok = skipped = 0
    total_read = total_write = 0

    for svc_dir in svc_dirs:
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
        total_read  += r
        total_write += w
        ok += 1
        print(f"  {svc_dir.name:<40}  read={r:>4}  write={w:>4}")

    print()
    print(f"Done: {ok} written, {skipped} skipped")
    print(f"Total read ops:  {total_read}")
    print(f"Total write ops: {total_write}")


if __name__ == "__main__":
    main()
