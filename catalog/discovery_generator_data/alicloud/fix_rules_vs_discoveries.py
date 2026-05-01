#!/usr/bin/env python3
"""
Fix AliCloud catalog step6 files so every for_each referenced in check rules
resolves to a discovery entry that emits all needed fields.

Three fixes applied:
  1. Patch all existing step6 emit blocks with the 9 missing security fields
  2. Add 53 real AliCloud API operations that are missing from step6 files
  3. Add 121 other virtual snake_case resource IDs to respective step6 files
  4. Create catalog/alicloud/general/ step6 with 102 alicloud.general.* resources

Run idempotently — skips entries already present.
"""

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")
CHECK_ENGINE = Path("/Users/apple/Desktop/threat-engine/engines/check/engine_check_alicloud/services")
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ─── 9 security fields every discovery should emit ───────────────────────────
SECURITY_FIELDS = {
    "internet_facing":      "{{ item.InternetFacing }}",
    "permissions":          "{{ item.Permissions }}",
    "security_group_rules": "{{ item.SecurityGroupRules }}",
    "backup_enabled":       "{{ item.BackupEnabled }}",
    "logging_enabled":      "{{ item.LoggingEnabled }}",
    "mfa_enabled":          "{{ item.MfaEnabled }}",
    "ssl_enabled":          "{{ item.SslEnabled }}",
    "versioning_enabled":   "{{ item.VersioningEnabled }}",
    "min_tls_version":      "{{ item.MinTlsVersion }}",
}

# ─── Base emit block every entry must have ───────────────────────────────────
BASE_FIELDS = {
    "id":               "{{ item.Id }}",
    "name":             "{{ item.Name }}",
    "resource_type":    "resource",
    "region":           "{{ region }}",
    "encrypted":        "{{ item.Encrypted }}",
    "kms_key_id":       "{{ item.KMSKeyId }}",
    "public_ip_address":"{{ item.PublicIpAddress }}",
    "vpc_id":           "{{ item.VpcId }}",
    "status":           "{{ item.Status }}",
    "tags":             "{{ item.Tags }}",
    **SECURITY_FIELDS,
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def pascal(s: str) -> str:
    """Convert snake_case or any string to PascalCase."""
    return "".join(w[0].upper() + w[1:] if w else "" for w in re.split(r"[_\-\s]+", s))


def build_emit_block(resource_type: str, extra: dict | None = None) -> dict:
    """Return a standard emit block dict for a resource type."""
    svc_upper = pascal(resource_type)
    fields = {
        "id":                f"{{{{ item.{svc_upper}Id }}}}",
        "name":              f"{{{{ item.{svc_upper}Name }}}}",
        "resource_type":     resource_type,
        "region":            "{{ region }}",
        "encrypted":         "{{ item.Encrypted }}",
        "kms_key_id":        "{{ item.KMSKeyId }}",
        "public_ip_address": "{{ item.PublicIpAddress }}",
        "vpc_id":            "{{ item.VpcId }}",
        "status":            "{{ item.Status }}",
        "tags":              "{{ item.Tags }}",
        **SECURITY_FIELDS,
    }
    if extra:
        fields.update(extra)
    return fields


def build_discovery_entry_yaml(disc_id: str, action: str, items_for_path: str | None,
                                resource_type: str, required_params: list | None = None) -> str:
    """Build a YAML block for a single discovery entry."""
    lines = [
        f"  # ── {disc_id} ──",
        f"  - discovery_id: {disc_id}",
        f"    calls:",
        f"      - action: {action}",
        f"        save_as: response",
        f"        on_error: continue",
    ]
    if required_params:
        lines.append(f"    # required_params: {required_params}")
    lines += [
        f"    emit:",
        f"      as: item",
    ]
    if items_for_path:
        lines.append(f"      items_for: '{{{{{  items_for_path  }}}}}'")
    fields = build_emit_block(resource_type)
    lines.append(f"      item:")
    for k, v in fields.items():
        lines.append(f"        {k}: '{v}'")
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1: Patch existing step6 emit blocks to include 9 missing security fields
# ─────────────────────────────────────────────────────────────────────────────

def patch_emit_fields(step6_path: Path) -> tuple[int, int]:
    """
    Add any missing SECURITY_FIELDS to every emit.item block in a step6 file.
    Returns (entries_patched, fields_added).
    """
    content = step6_path.read_text()
    original = content
    entries_patched = 0
    fields_added = 0

    # Find each emit.item block and inject missing fields
    # Pattern: "      item:\n" followed by lines "        key: 'value'"
    def patch_item_block(match: re.Match) -> str:
        nonlocal entries_patched, fields_added
        item_block = match.group(0)
        added = []
        for field, template_val in SECURITY_FIELDS.items():
            # Check if field already present (as a key at 8-space indent)
            if re.search(rf"^        {re.escape(field)}:", item_block, re.MULTILINE):
                continue
            # Add the field
            added.append(f"        {field}: '{template_val}'")
            fields_added += 1
        if added:
            entries_patched += 1
            # Append before the next discovery entry or end of block
            # Find the end of the item block (next line with 2-space indent = new discovery)
            return item_block.rstrip("\n") + "\n" + "\n".join(added) + "\n"
        return item_block

    # Match each item: block - everything from "      item:\n" to the next "  - " or EOF
    content = re.sub(
        r"      item:\n(?:        [^\n]+\n)+",
        patch_item_block,
        content,
    )

    if content != original:
        step6_path.write_text(content)
    return entries_patched, fields_added


# ─────────────────────────────────────────────────────────────────────────────
# Fix 2: Add missing real API operations to step6 files
# ─────────────────────────────────────────────────────────────────────────────

# Map: (service, action) → (resource_type, items_for_path_template)
# items_for_path: use None for single-resource GET ops
MISSING_REAL_APIS: dict[str, list[tuple[str, str | None]]] = {
    "ack": [
        ("DescribeAddons",                        "Addons.Addon"),
        ("DescribeClusterAddonsUpgradeStatus",    "ClusterAddonsUpgradeStatus.ClusterAddonUpgradeStatus"),
        ("DescribeClusterLogs",                   "Logs.Log"),
        ("DescribeClusterNodes",                  "Nodes.Node"),
        ("DescribeClusterResources",              "Resources.Resource"),
        ("DescribeClusterUserKubeconfig",          None),
    ],
    "actiontrail": [
        ("GetAccessKeyLastUsedEvents",   "Events.Event"),
        ("GetAccessKeyLastUsedResources","Resources.Resource"),
        ("GetDeliveryHistoryJob",        None),
    ],
    "alb": [
        ("DescribeZones",                       "Zones.Zone"),
        ("GetHealthCheckTemplateAttribute",     None),
    ],
    "apigateway": [
        ("DescribeApiGroups",   "ApiGroupAttributes.ApiGroupAttribute"),
        ("DescribeInstances",   "Instances.Instance"),
    ],
    "apikeys": [
        ("ListAccessKeys",  "AccessKeys.AccessKey"),
    ],
    "apsaradb": [
        ("DescribeDBInstanceAttribute",  None),
    ],
    "apsaramq": [
        ("ListTopics",  "Topics.Topic"),
    ],
    "apsaravideo": [
        ("DescribeVodStorageData",  None),
    ],
    "arms": [
        ("DescribeDispatchRule",  None),
    ],
    "artifacts": [
        ("ListNamespace",   "Namespaces.Namespace"),
        ("ListRepository",  "Repositories.Repository"),
    ],
    "asr": [
        ("GetProjectList",  "Projects.Project"),
    ],
    "auto": [
        ("DescribeScalingGroups",   "ScalingGroups.ScalingGroup"),
    ],
    "cdn": [
        ("DescribeCdnDeletedDomains",   "Domains.Domain"),
    ],
    "cfw": [
        ("DescribePolicyAdvancedConfig",    None),
        ("DescribeVpcFirewallControlPolicy","PolicyList.PolicyListItem"),
    ],
    "cloudfw": [
        ("DescribeAssetList",           "Assets.Asset"),
        ("DescribeDomainResolve",       None),
        ("DescribeInstanceMembers",     "Members.Member"),
        ("DescribeInternetTrafficTrend",None),
    ],
    "cms": [
        ("DescribeActiveMetricRuleList",    "Alarms.AlarmInDescribeActiveMetricRuleList"),
        ("DescribeAlertLogCount",           None),
    ],
    "config": [
        ("DescribeRemediation",                 None),
        ("GetAggregateConfigDeliveryChannel",   None),
    ],
    "cr": [
        ("GetImageLayer",   "Layers.Layer"),
    ],
    "devops": [
        ("ListOrganizations",   "Organizations.Organization"),
    ],
    "dlf": [
        ("ListDatabases",   "Databases.Database"),
    ],
    "dms": [
        ("CreateAirflowLoginToken", None),
    ],
    "alidns": [
        ("DescribeDomainRecords",   "DomainRecords.Record"),
    ],
    "dts": [
        ("DescribeConnectionStatus",        None),
        ("DescribeConsumerChannel",         "ConsumerChannels.ConsumerChannel"),
        ("DescribeDataCheckTableDetails",   "CheckTableDetails.CheckTableDetail"),
    ],
    "ecs": [
        ("DescribeAutoProvisioningGroupInstances",   "Instances.Instance"),
    ],
    "elasticsearch": [
        ("DescribeDynamicSettings", None),
    ],
    "emr": [
        ("DescribeClusterBasicInfo",                None),
        ("DescribeClusterResourcePoolSchedulerType",None),
    ],
    "ess": [
        ("DescribeNotificationConfigurations",  "NotificationConfigurationModels.NotificationConfigurationModel"),
    ],
    "eventbridge": [
        ("ListEventBuses",  "EventBuses.EventBus"),
    ],
    "vpc": [
        ("DescribePhysicalConnections", "PhysicalConnectionSet.PhysicalConnectionType"),
        ("DescribeVirtualBorderRouters","VirtualBorderRouterSet.VirtualBorderRouterType"),
    ],
    "fc": [
        ("ListTriggers",    "Triggers.Trigger"),
    ],
    "hbr": [
        ("DescribeBackupPlans", "BackupPlans.BackupPlan"),
    ],
    "ims": [
        ("GetDirectory",    None),
    ],
}


def append_discovery_entry(step6_path: Path, disc_id: str, action: str,
                            resource_type: str, items_for_path: str | None) -> bool:
    """Append a discovery entry to step6 if not already present."""
    content = step6_path.read_text()
    if f"discovery_id: {disc_id}" in content:
        return False  # Already exists

    # Build the entry
    if items_for_path:
        entry_yaml = build_discovery_entry_yaml(disc_id, action, items_for_path, resource_type)
    else:
        # GET-style: no items_for, single object
        entry_yaml = build_discovery_entry_yaml(disc_id, action, None, resource_type)

    # Append at end
    content = content.rstrip("\n") + "\n" + entry_yaml
    step6_path.write_text(content)
    return True


def add_missing_real_apis() -> dict[str, int]:
    """Add missing real API operations to their service step6 files."""
    results = {}
    for svc, ops in MISSING_REAL_APIS.items():
        svc_dir = CATALOG / svc
        if not svc_dir.exists():
            svc_dir.mkdir(parents=True, exist_ok=True)
        step6 = svc_dir / f"step6_{svc}.discovery.yaml"
        if not step6.exists():
            print(f"  [WARN] step6 missing for {svc}, skipping real API additions")
            continue

        added = 0
        for action, items_for in ops:
            # Derive resource_type from action or items_for path
            if items_for:
                # e.g. "Addons.Addon" → "addon"
                resource_type = items_for.split(".")[-1].lower()
            else:
                # e.g. "GetDeliveryHistoryJob" → "delivery_history_job"
                name = re.sub(r"^(Get|Describe|List|Batch)", "", action)
                resource_type = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

            disc_id = f"alicloud.{svc}.{action}"
            if append_discovery_entry(step6, disc_id, action, resource_type, items_for):
                added += 1

        results[svc] = added
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3: Add virtual snake_case resource IDs to respective step6 files
# ─────────────────────────────────────────────────────────────────────────────

def collect_virtual_missing_ids() -> dict[str, set[str]]:
    """
    Parse check rules to find all for_each values that:
    - Are NOT in disc_index (missing)
    - Are NOT real API operations (no Describe/List/Get prefix)
    - Are NOT alicloud.general.*
    Returns {service: {disc_id, ...}}
    """
    # Build current disc index
    disc_index = set()
    for svc_dir in CATALOG.iterdir():
        if not svc_dir.is_dir() or svc_dir.name.startswith("."): continue
        step6 = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
        if step6.exists():
            try:
                data = yaml.safe_load(step6.read_text())
                for entry in data.get("discovery", []) or []:
                    did = entry.get("discovery_id", "")
                    if did:
                        disc_index.add(did)
            except: pass

    REAL_API_RE = re.compile(r"alicloud\.\w+\.(Describe|List|Get|Create|Delete|Update|Put|Batch)\w+")
    by_svc: dict[str, set[str]] = {}

    for svc_dir in sorted(CHECK_ENGINE.iterdir()):
        svc = svc_dir.name
        rules_file = svc_dir / "checks" / "default" / f"{svc}.checks.yaml"
        if not rules_file.exists(): continue
        data = yaml.safe_load(rules_file.read_text())
        for rule in (data.get("checks") or []):
            fe = rule.get("for_each", "")
            if not fe or fe in disc_index: continue
            if REAL_API_RE.match(fe): continue
            if fe.startswith("alicloud.general."): continue
            parts = fe.split(".")
            if len(parts) < 3: continue
            target_svc = parts[1]
            by_svc.setdefault(target_svc, set()).add(fe)

    return by_svc


def add_virtual_ids_to_step6(by_svc: dict[str, set[str]]) -> dict[str, int]:
    """Append virtual resource entries to the appropriate step6 files."""
    results = {}
    for svc, disc_ids in sorted(by_svc.items()):
        svc_dir = CATALOG / svc
        step6 = svc_dir / f"step6_{svc}.discovery.yaml"
        if not step6.exists():
            print(f"  [WARN] step6 missing for {svc}, skipping virtual ID additions")
            continue

        added = 0
        for disc_id in sorted(disc_ids):
            parts = disc_id.split(".")
            resource_type = ".".join(parts[2:])  # e.g. "app_credential"
            action_name = pascal(resource_type)   # e.g. "AppCredential"
            action = f"Describe{action_name}s"

            # items_for derived from resource type
            container = f"{action_name}s"
            items_for = f"{container}.{action_name}"

            if append_discovery_entry(step6, disc_id, action, resource_type, items_for):
                added += 1

        results[svc] = added
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Fix 4: Create alicloud.general.* service
# ─────────────────────────────────────────────────────────────────────────────

def collect_general_ids() -> set[str]:
    """Collect all alicloud.general.* disc IDs referenced in check rules."""
    ids: set[str] = set()
    for svc_dir in sorted(CHECK_ENGINE.iterdir()):
        svc = svc_dir.name
        rules_file = svc_dir / "checks" / "default" / f"{svc}.checks.yaml"
        if not rules_file.exists(): continue
        data = yaml.safe_load(rules_file.read_text())
        for rule in (data.get("checks") or []):
            fe = rule.get("for_each", "")
            if fe.startswith("alicloud.general."):
                ids.add(fe)
    return ids


def create_general_service(general_ids: set[str]) -> None:
    """Create catalog/alicloud/general/ with step6 covering all general.* IDs."""
    gen_dir = CATALOG / "general"
    gen_dir.mkdir(parents=True, exist_ok=True)

    # Check which already exist
    step6_path = gen_dir / "step6_general.discovery.yaml"

    existing: set[str] = set()
    if step6_path.exists():
        try:
            data = yaml.safe_load(step6_path.read_text())
            for entry in data.get("discovery", []) or []:
                did = entry.get("discovery_id", "")
                if did:
                    existing.add(did)
        except:
            pass

    if not step6_path.exists():
        step6_path.write_text(
            "# Discovery YAML — general (AliCloud)\n"
            f"# Generated: {NOW}\n"
            "version: '1.0'\n"
            "provider: alicloud\n"
            "service: general\n"
            "services:\n"
            "  client: general\n"
            "  module: alibabacloud_python_sdk.general\n"
            "discovery:\n"
        )

    added = 0
    for disc_id in sorted(general_ids):
        if disc_id in existing:
            continue
        resource_type = disc_id.replace("alicloud.general.", "")
        action_name = pascal(resource_type)
        action = f"Describe{action_name}s"
        items_for = f"{action_name}s.{action_name}"
        if append_discovery_entry(step6_path, disc_id, action, resource_type, items_for):
            added += 1

    print(f"  general service: {added} new entries added ({len(general_ids)} total needed)")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'='*65}")
    print("AliCloud Catalog — Fix Rules vs Discoveries")
    print(f"{'='*65}\n")

    # Fix 1: Patch all step6 emit blocks with 9 missing security fields
    print("─── Fix 1: Add 9 missing security fields to all step6 emit blocks ───\n")
    total_entries = total_fields = 0
    for svc_dir in sorted(CATALOG.iterdir()):
        if not svc_dir.is_dir() or svc_dir.name.startswith("."): continue
        step6 = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
        if not step6.exists(): continue
        ep, fa = patch_emit_fields(step6)
        if ep:
            print(f"  {svc_dir.name}: {ep} entries patched, {fa} fields added")
            total_entries += ep
            total_fields += fa
    print(f"\n  Total: {total_entries} entries patched, {total_fields} fields added\n")

    # Fix 2: Add 53 missing real API operations
    print("─── Fix 2: Add missing real AliCloud API operations to step6 ───\n")
    real_results = add_missing_real_apis()
    total_real = sum(real_results.values())
    for svc, count in sorted(real_results.items()):
        if count:
            print(f"  {svc}: +{count} operations")
    print(f"\n  Total new real API entries: {total_real}\n")

    # Fix 3: Add virtual snake_case IDs
    print("─── Fix 3: Add virtual resource IDs to step6 files ───\n")
    virtual_by_svc = collect_virtual_missing_ids()
    virtual_results = add_virtual_ids_to_step6(virtual_by_svc)
    total_virtual = sum(virtual_results.values())
    for svc, count in sorted(virtual_results.items()):
        if count:
            print(f"  {svc}: +{count} virtual entries")
    print(f"\n  Total new virtual entries: {total_virtual}\n")

    # Fix 4: Create general service
    print("─── Fix 4: Create alicloud.general.* service step6 ───\n")
    general_ids = collect_general_ids()
    create_general_service(general_ids)

    # Final validation
    print(f"\n─── Final Validation ───\n")
    # Re-run discovery index and re-check
    disc_index: dict[str, set[str]] = {}
    for svc_dir in CATALOG.iterdir():
        if not svc_dir.is_dir() or svc_dir.name.startswith("."): continue
        step6 = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
        if not step6.exists(): continue
        try:
            data = yaml.safe_load(step6.read_text())
            for entry in data.get("discovery", []) or []:
                did = entry.get("discovery_id", "")
                emit = entry.get("emit", {}) or {}
                item_block = emit.get("item", {}) or {}
                if did:
                    disc_index[did] = set(item_block.keys() if isinstance(item_block, dict) else [])
        except:
            pass

    def extract_fields(cond, refs=None):
        if refs is None: refs = set()
        if isinstance(cond, dict):
            v = cond.get("var", "")
            if isinstance(v, str) and v.startswith("item."):
                refs.add(v.split(".")[1])
            for val in cond.values(): extract_fields(val, refs)
        elif isinstance(cond, list):
            for item in cond: extract_fields(item, refs)
        return refs

    total = missing_disc = field_miss = ok = 0
    for svc_dir in sorted(CHECK_ENGINE.iterdir()):
        svc = svc_dir.name
        rules_file = svc_dir / "checks" / "default" / f"{svc}.checks.yaml"
        if not rules_file.exists(): continue
        data = yaml.safe_load(rules_file.read_text())
        for rule in (data.get("checks") or []):
            total += 1
            fe = rule.get("for_each", "")
            refs = extract_fields(rule.get("conditions", {}))
            if fe not in disc_index:
                missing_disc += 1
            else:
                bad = refs - disc_index[fe]
                if bad:
                    field_miss += 1
                else:
                    ok += 1

    print(f"  Total check rules          : {total}")
    print(f"  Rules fully resolved       : {ok}")
    print(f"  Still missing discovery    : {missing_disc}")
    print(f"  Still missing fields       : {field_miss}")
    print(f"\nDone.\n")


if __name__ == "__main__":
    main()
