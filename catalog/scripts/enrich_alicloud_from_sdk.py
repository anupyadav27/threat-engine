#!/usr/bin/env python3
"""
AliCloud SDK Enrichment Script — generates operation_registry.json + step2 + step6
for AliCloud services using installed aliyun-python-sdk-* packages.

For each service with an SDK package installed:
  1. Introspect all *Request classes → real API operation names
  2. Classify as read/write by name prefix
  3. For read ops: assign standard AliCloud CSPM produces fields
  4. Generate operation_registry.json → step2_read/write → step6 YAML

Standard CSPM produces fields (same as all 26 existing enriched services):
  InstanceId, InstanceName, Status, CreationTime, RegionId, ZoneId, Tags
  + service-specific security fields where known

Usage:
    python3 data_pythonsdk/scripts/enrich_alicloud_from_sdk.py
    python3 data_pythonsdk/scripts/enrich_alicloud_from_sdk.py --dry-run
    python3 data_pythonsdk/scripts/enrich_alicloud_from_sdk.py --service ecs
"""

import argparse
import importlib
import json
import pkgutil
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path

ALICLOUD_ROOT = Path(__file__).parent.parent / "alicloud"
SKIP = {"tools", "__pycache__", "temp_code"}

# ── Operation classification ──────────────────────────────────────────────────

READ_PREFIXES = (
    "Describe", "List", "Get", "Query", "Check",
    "Search", "Fetch", "Show", "View",
)
WRITE_PREFIXES = (
    "Create", "Delete", "Update", "Add", "Remove", "Set",
    "Enable", "Disable", "Attach", "Detach", "Modify", "Apply",
    "Cancel", "Stop", "Start", "Reboot", "Authorize", "Revoke",
    "Allocate", "Release", "Associate", "Unassociate",
    "Import", "Export", "Accept", "Reject", "Activate", "Deactivate",
    "Put", "Post", "Patch", "Replace", "Reset", "Refresh",
)

SKIP_FIELDS = {
    "next_token", "next_page", "page_number", "page_size",
    "total_count", "total", "count", "request_id",
    "next", "limit", "offset",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_read(op: str) -> bool:
    return any(op.startswith(p) for p in READ_PREFIXES)


def _read_kind(op: str) -> str:
    low = op.lower()
    if low.startswith("list") or low.startswith("describe"):
        return "read_list"
    return "read_get"


def _write_kind(op: str) -> str:
    low = op.lower()
    if any(low.startswith(p.lower()) for p in ("Create", "Add", "Import")):
        return "write_create"
    if any(low.startswith(p.lower()) for p in ("Delete", "Remove", "Release")):
        return "write_delete"
    return "write_update"


def _to_snake(name: str) -> str:
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    return s.lower()


# ── AliCloud base resource fields (fallback for services with no SDK on PyPI) ──
# Every AliCloud resource inherits these from the Resource Manager / common model.
# Mirrors the Azure ARM base field approach used for Azure 100% field coverage.
ALICLOUD_BASE_FIELDS: list[str] = [
    # Inventory / Identity
    "InstanceId",       # Primary resource identifier
    "Name",             # Resource name
    "Description",      # Resource description
    # State
    "Status",           # Resource state / health
    # Region / Zone
    "RegionId",         # AliCloud region
    "ZoneId",           # Availability zone
    # Billing / Ownership
    "ResourceGroupId",  # Resource group (billing, access control)
    "OwnerId",          # Account owner
    # Lifecycle
    "CreateTime",       # Creation timestamp
    "ExpireTime",       # Expiry / TTL
    # Tags
    "Tags",             # Resource tags (tagging, cost allocation)
]

# ── Standard AliCloud CSPM produces fields ────────────────────────────────────
# All 26 existing enriched services use exactly these 7 fields for every read op.
# They cover: inventory identity, lifecycle state, region, tags — the CSPM baseline.

STANDARD_PRODUCES = [
    {"entity": "{svc}.instance_id",   "source": "item", "path": "InstanceId"},
    {"entity": "{svc}.instance_name", "source": "item", "path": "InstanceName"},
    {"entity": "{svc}.status",        "source": "item", "path": "Status"},
    {"entity": "{svc}.creation_time", "source": "item", "path": "CreationTime"},
    {"entity": "{svc}.region_id",     "source": "item", "path": "RegionId"},
    {"entity": "{svc}.zone_id",       "source": "item", "path": "ZoneId"},
    {"entity": "{svc}.tags",          "source": "item", "path": "Tags"},
]

# Additional security-relevant produces fields per service (CSPM-critical)
SERVICE_EXTRA_PRODUCES: dict[str, list[dict]] = {
    "ecs": [
        {"entity": "ecs.encrypted",           "source": "item", "path": "Encrypted"},
        {"entity": "ecs.internet_max_bandwidth_out", "source": "item", "path": "InternetMaxBandwidthOut"},
        {"entity": "ecs.security_group_ids",  "source": "item", "path": "SecurityGroupIds"},
        {"entity": "ecs.vpc_id",              "source": "item", "path": "VpcId"},
        {"entity": "ecs.instance_type",       "source": "item", "path": "InstanceType"},
        {"entity": "ecs.public_ip_address",   "source": "item", "path": "PublicIpAddress"},
        {"entity": "ecs.eip_address",         "source": "item", "path": "EipAddress"},
        {"entity": "ecs.deletion_protection", "source": "item", "path": "DeletionProtection"},
    ],
    "rds": [
        {"entity": "rds.engine",                       "source": "item", "path": "Engine"},
        {"entity": "rds.engine_version",               "source": "item", "path": "EngineVersion"},
        {"entity": "rds.db_instance_net_type",         "source": "item", "path": "DBInstanceNetType"},
        {"entity": "rds.pay_type",                     "source": "item", "path": "PayType"},
        {"entity": "rds.vpc_id",                       "source": "item", "path": "VpcId"},
        {"entity": "rds.encryption_type",              "source": "item", "path": "EncryptionType"},
    ],
    "vpc": [
        {"entity": "vpc.cidr_block",          "source": "item", "path": "CidrBlock"},
        {"entity": "vpc.is_default",          "source": "item", "path": "IsDefault"},
        {"entity": "vpc.vpc_name",            "source": "item", "path": "VpcName"},
        {"entity": "vpc.user_cidrs",          "source": "item", "path": "UserCidrs"},
    ],
    "slb": [
        {"entity": "slb.address",             "source": "item", "path": "Address"},
        {"entity": "slb.address_type",        "source": "item", "path": "AddressType"},
        {"entity": "slb.address_ip_version",  "source": "item", "path": "AddressIPVersion"},
    ],
    "kms": [
        {"entity": "kms.key_state",           "source": "item", "path": "KeyState"},
        {"entity": "kms.key_usage",           "source": "item", "path": "KeyUsage"},
        {"entity": "kms.origin",              "source": "item", "path": "Origin"},
        {"entity": "kms.protection_level",    "source": "item", "path": "ProtectionLevel"},
        {"entity": "kms.automatic_rotation",  "source": "item", "path": "AutomaticRotation"},
        {"entity": "kms.deletion_protection", "source": "item", "path": "EnableAutomaticRotation"},
    ],
    "ram": [
        {"entity": "ram.user_name",           "source": "item", "path": "UserName"},
        {"entity": "ram.display_name",        "source": "item", "path": "DisplayName"},
        {"entity": "ram.mfabind_required",    "source": "item", "path": "MFABindRequired"},
        {"entity": "ram.policy_name",         "source": "item", "path": "PolicyName"},
        {"entity": "ram.policy_type",         "source": "item", "path": "PolicyType"},
        {"entity": "ram.policy_document",     "source": "item", "path": "PolicyDocument"},
    ],
    "cdn": [
        {"entity": "cdn.domain_name",         "source": "item", "path": "DomainName"},
        {"entity": "cdn.cname",               "source": "item", "path": "Cname"},
        {"entity": "cdn.ssl_protocol",        "source": "item", "path": "SslProtocol"},
    ],
    "cms": [
        {"entity": "cms.alert_name",          "source": "item", "path": "AlertName"},
        {"entity": "cms.namespace",           "source": "item", "path": "Namespace"},
        {"entity": "cms.enable_state",        "source": "item", "path": "EnableState"},
    ],
}


def _produces(svc: str) -> list[dict]:
    """Build produces list: standard 7 fields + service-specific extras."""
    result = [
        {k: v.replace("{svc}", svc) for k, v in p.items()}
        for p in STANDARD_PRODUCES
    ]
    result.extend(SERVICE_EXTRA_PRODUCES.get(svc, []))
    return result


# ── SDK introspection ─────────────────────────────────────────────────────────

def _get_sdk_module(svc: str):
    """
    Try to import the aliyunsdk{svc} request module.
    Returns (module, version_str) or None if not installed.
    """
    # Common AliCloud SDK package → module naming conventions
    candidates = [
        f"aliyunsdk{svc}",
        f"aliyunsdk{svc.replace('-', '')}",
        f"aliyunsdk{svc.replace('_', '')}",
    ]
    for pkg in candidates:
        # Find version subdirectory (e.g. v20140526)
        try:
            parent = importlib.import_module(pkg)
            req_path = Path(parent.__file__).parent / "request"
            if not req_path.exists():
                continue
            # Find version directories
            for version_dir in sorted(req_path.iterdir(), reverse=True):
                if version_dir.is_dir() and version_dir.name.startswith("v"):
                    mod_path = f"{pkg}.request.{version_dir.name}"
                    try:
                        mod = importlib.import_module(mod_path)
                        return mod, version_dir.name
                    except ImportError:
                        continue
        except ImportError:
            continue
    return None, None


def _list_sdk_ops(mod) -> tuple[list[str], list[str]]:
    """Return (read_ops, write_ops) from a service request module."""
    read_ops, write_ops = [], []
    for importer, modname, ispkg in pkgutil.iter_modules(mod.__path__):
        if not modname.endswith("Request"):
            continue
        op = modname[:-7]  # strip "Request"
        if _is_read(op):
            read_ops.append(op)
        else:
            write_ops.append(op)
    return sorted(read_ops), sorted(write_ops)


# ── Registry builders ─────────────────────────────────────────────────────────

def build_operation_registry(svc: str, read_ops: list, write_ops: list,
                              version: str) -> dict:
    """Build operation_registry.json structure."""
    operations = {}
    for op in read_ops:
        kind = _read_kind(op)
        operations[op] = {
            "kind": kind,
            "side_effect": False,
            "sdk": {"client": svc, "method": op},
            "consumes": [],
            "produces": _produces(svc),
            "notes": "",
        }
    for op in write_ops:
        kind = _write_kind(op)
        operations[op] = {
            "kind": kind,
            "side_effect": True,
            "sdk": {"client": svc, "method": op},
            "consumes": [],
            "produces": [],
            "notes": "",
        }
    return {
        "service": svc,
        "version": version,
        "kind_rules": {},
        "entity_aliases": {},
        "overrides": {},
        "operations": operations,
    }


def build_step2(svc: str, op_registry: dict) -> tuple[dict, dict]:
    """Build step2 read + write operation registries from operation_registry."""
    now = _now()
    ops = op_registry.get("operations", {})
    read_ops, write_ops = {}, {}

    for op_name, op in ops.items():
        kind = op.get("kind", "")
        produces = op.get("produces", [])
        output_fields = {}
        for p in produces:
            field_name = p["entity"].split(".", 1)[-1]  # "ecs.instance_id" → "instance_id"
            if field_name in SKIP_FIELDS:
                continue
            output_fields[field_name] = {
                "type": "string",
                "path": p["path"],
                "entity": p["entity"],
            }

        consumes = op.get("consumes", [])
        required_params = [c["param"] for c in consumes if c.get("required")]
        optional_params = [c["param"] for c in consumes if not c.get("required")]

        entry = {
            "operation": op_name,
            "service": svc,
            "csp": "alicloud",
            "kind": kind,
            "independent": len(required_params) == 0,
            "python_method": op_name,
            "yaml_action": op_name,
            "required_params": required_params,
            "optional_params": optional_params,
            "output_fields": output_fields,
        }

        if kind.startswith("read"):
            read_ops[op_name] = entry
        else:
            write_ops[op_name] = entry

    def _reg(ops_dict):
        return {
            "service": svc,
            "csp": "alicloud",
            "generated_at": now,
            "total_operations": len(ops_dict),
            "independent_count": sum(1 for v in ops_dict.values() if v["independent"]),
            "dependent_count": sum(1 for v in ops_dict.values() if not v["independent"]),
            "operations": ops_dict,
        }

    return _reg(read_ops), _reg(write_ops)


def build_step6_yaml(svc: str, read_reg: dict) -> str:
    """Build step6 discovery YAML from read operation registry."""
    ops = read_reg.get("operations", {})
    ind_ops = {k: v for k, v in ops.items() if v["independent"]}
    dep_ops = {k: v for k, v in ops.items() if not v["independent"]}

    now = _now()
    header = textwrap.dedent(f"""\
        # Discovery YAML — {svc} (AliCloud)
        # Generated: {now}
        # Enriched from aliyun-python-sdk-{svc} request class introspection
        version: '1.0'
        provider: alicloud
        service: {svc}
        services:
          client: {svc}
          module: alibabacloud_python_sdk.{svc}
        discovery:
        """)

    def _block(op_name: str, op: dict, dep: bool = False) -> str:
        action = op.get("yaml_action", op_name)
        disc_id = f"alicloud.{svc}.{op_name}"
        kind = op.get("kind", "read_get")
        label = " [dependent]" if dep else ""
        out_fields = op.get("output_fields", {})
        field_names = sorted(f for f in out_fields if f not in SKIP_FIELDS)

        lines = [
            f"  # ── {op_name}{label} ──",
            f"  - discovery_id: {disc_id}",
            f"    calls:",
            f"      - action: {action}",
            f"        save_as: response",
            f"        on_error: continue",
            f"    emit:",
            f"      as: item",
        ]
        if kind == "read_list":
            lines.append("      items_for: '{{ response.data }}'")
            if field_names:
                lines.append("      item:")
                for f in field_names:
                    lines.append(f"        {f}: '{{{{ item.{f} }}}}'")
        else:
            if field_names:
                lines.append("      item:")
                for f in field_names:
                    lines.append(f"        {f}: '{{{{ response.{f} }}}}'")
        if op.get("required_params"):
            lines.append(f"    # required_params: {op['required_params']}")
        return "\n".join(lines)

    blocks = [_block(k, v) for k, v in sorted(ind_ops.items())]
    if dep_ops:
        blocks += ["  # ── Dependent ops ──"]
        blocks += [_block(k, v, True) for k, v in sorted(dep_ops.items())]

    return header + "\n".join(blocks) + "\n"


# ── Main ──────────────────────────────────────────────────────────────────────

# Map AliCloud data directory names → SDK module names (when they differ)
SVC_TO_SDK: dict[str, str] = {
    "alidns":  "alidns",      # aliyunsdk + alidns
    "dds":     "dds",         # MongoDB
    "kvstore": "r_kvstore",   # ApsaraDB for Redis/Memcache
    "waf":     "waf_openapi", # WAF ships as aliyun-python-sdk-waf-openapi
}

def _sdk_name(svc: str) -> str:
    return SVC_TO_SDK.get(svc, svc)


def _build_fallback_step2(svc: str) -> tuple[dict, dict]:
    """
    Build step2 read registry for a service with no SDK package on PyPI.
    Generates two synthetic read ops:
      - List{Svc}s  (read_list) — enumerate all instances
      - Describe{Svc} (read_get) — get a single instance
    Both use ALICLOUD_BASE_FIELDS — the universal AliCloud resource fields
    inherited by every Resource Manager resource.
    """
    now = _now()
    svc_cap = svc.capitalize()

    read_ops_dict = {
        f"Describe{svc_cap}s": {
            "operation": f"Describe{svc_cap}s",
            "service": svc,
            "csp": "alicloud",
            "kind": "read_list",
            "independent": True,
            "python_method": f"Describe{svc_cap}s",
            "yaml_action": f"Describe{svc_cap}s",
            "required_params": [],
            "optional_params": [],
            "output_fields": {
                f: {"type": "string", "path": f, "entity": f"{svc}.{f.lower()}"}
                for f in ALICLOUD_BASE_FIELDS
            },
        },
        f"Describe{svc_cap}": {
            "operation": f"Describe{svc_cap}",
            "service": svc,
            "csp": "alicloud",
            "kind": "read_get",
            "independent": False,
            "python_method": f"Describe{svc_cap}",
            "yaml_action": f"Describe{svc_cap}",
            "required_params": ["InstanceId"],
            "optional_params": [],
            "output_fields": {
                f: {"type": "string", "path": f, "entity": f"{svc}.{f.lower()}"}
                for f in ALICLOUD_BASE_FIELDS
            },
        },
    }

    def _reg(ops_dict):
        return {
            "service": svc,
            "csp": "alicloud",
            "generated_at": now,
            "total_operations": len(ops_dict),
            "independent_count": sum(1 for v in ops_dict.values() if v["independent"]),
            "dependent_count": sum(1 for v in ops_dict.values() if not v["independent"]),
            "operations": ops_dict,
            "_fallback": True,
        }

    return _reg(read_ops_dict), _reg({})


def main():
    parser = argparse.ArgumentParser(
        description="Enrich AliCloud services from installed aliyun-python-sdk packages"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Report without writing files")
    parser.add_argument("--service", default=None,
                        help="Only process one service directory")
    parser.add_argument("--skip-existing", action="store_true", default=True,
                        help="Skip services that already have step2 (default: True)")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing step2/step6 files")
    parser.add_argument("--fallback", action="store_true",
                        help="For services with no SDK, generate step2/step6 using "
                             "ALICLOUD_BASE_FIELDS (universal AliCloud resource fields). "
                             "Achieves 100%% service coverage like Azure ARM base fields.")
    args = parser.parse_args()

    if args.service:
        svc_dirs = [ALICLOUD_ROOT / args.service]
    else:
        svc_dirs = sorted(d for d in ALICLOUD_ROOT.iterdir()
                          if d.is_dir() and d.name not in SKIP)

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"AliCloud SDK enrichment ({mode}): {len(svc_dirs)} service directories")
    if args.fallback:
        print("Fallback mode ON — services without SDK will get ALICLOUD_BASE_FIELDS")
    print()

    enriched = fallback_written = skipped_no_sdk = skipped_exists = 0

    for svc_dir in svc_dirs:
        svc = svc_dir.name
        step2_path = svc_dir / "step2_read_operation_registry.json"

        # Skip already-enriched unless --overwrite
        if step2_path.exists() and not args.overwrite:
            skipped_exists += 1
            continue

        # Try to load SDK module
        sdk_name = _sdk_name(svc)
        mod, version = _get_sdk_module(sdk_name)

        if mod is None:
            if args.fallback:
                # Apply base field fallback for services without any SDK on PyPI
                read_reg, write_reg = _build_fallback_step2(svc)
                step6_yaml = build_step6_yaml(svc, read_reg)
                n_read = read_reg["total_operations"]
                if args.dry_run:
                    print(f"  {svc:<35} Would write (fallback): {n_read} read ops "
                          f"[ALICLOUD_BASE_FIELDS]")
                else:
                    step2_path.write_text(json.dumps(read_reg, indent=2))
                    (svc_dir / "step2_write_operation_registry.json").write_text(
                        json.dumps(write_reg, indent=2))
                    (svc_dir / f"step6_{svc}.discovery.yaml").write_text(step6_yaml)
                    print(f"  {svc:<35} Written (fallback):    {n_read} read ops "
                          f"[ALICLOUD_BASE_FIELDS]")
                    fallback_written += 1
            else:
                print(f"  {svc:<35} SKIPPED — no SDK package (aliyunsdk{sdk_name})")
                skipped_no_sdk += 1
            continue

        read_ops, write_ops = _list_sdk_ops(mod)
        if not read_ops and not write_ops:
            print(f"  {svc:<35} SKIPPED — SDK found but no operations")
            skipped_no_sdk += 1
            continue

        op_registry = build_operation_registry(svc, read_ops, write_ops, version)
        read_reg, write_reg = build_step2(svc, op_registry)
        step6_yaml = build_step6_yaml(svc, read_reg)

        n_read = read_reg["total_operations"]
        n_write = write_reg["total_operations"]
        n_ind = read_reg["independent_count"]
        n_dep = read_reg["dependent_count"]

        if args.dry_run:
            print(f"  {svc:<35} Would write: {n_read} read "
                  f"({n_ind} ind/{n_dep} dep), {n_write} write  [{version}]")
        else:
            (svc_dir / "operation_registry.json").write_text(
                json.dumps(op_registry, indent=2))
            step2_path.write_text(json.dumps(read_reg, indent=2))
            (svc_dir / "step2_write_operation_registry.json").write_text(
                json.dumps(write_reg, indent=2))
            (svc_dir / f"step6_{svc}.discovery.yaml").write_text(step6_yaml)
            print(f"  {svc:<35} Written:     {n_read} read "
                  f"({n_ind} ind/{n_dep} dep), {n_write} write  [{version}]")
            enriched += 1

    print()
    print(f"Done: {enriched} SDK-enriched, {fallback_written} fallback-written, "
          f"{skipped_no_sdk} skipped (no SDK), "
          f"{skipped_exists} skipped (already have step2)")
    total_covered = enriched + fallback_written
    total_dirs = len(svc_dirs) - skipped_exists
    if total_dirs:
        pct = f"{total_covered / total_dirs * 100:.1f}%"
        print(f"Coverage: {total_covered}/{total_dirs} new services ({pct})")


if __name__ == "__main__":
    main()
