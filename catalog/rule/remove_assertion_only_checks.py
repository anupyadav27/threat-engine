#!/usr/bin/env python3
"""
Remove assertion_only checks from categories 2, 3, 4:
  - Category 3: Deprecated services (data_lake_analytics)
  - Category 4: Cross-cutting/generic rules (azure, general, resilience)
  - Also remove scattered assertion_only checks in other service files
    EXCEPT: active_directory, kubernetes, purview (category 1 - will get step1→step4 support)

Additionally removes other non-discoverable service assertion_only checks:
  - tags, policy, billing, cost_management, power_bi, managementgroups,
    subscription, resource_groups, changetrackingandinventory, maps,
    managed_application, devopsinfrastructure, azure_edge_hardware_center,
    azure_stack_edge, api_for_fhir, elasticsan, security_center_-_granular_pricing
"""
import os
import yaml
import shutil

BASE_DIR = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rule_check"

# Category 3 & 4: Delete entire directories (all checks are assertion_only or cross-cutting)
DELETE_DIRS = [
    "data_lake_analytics",  # Category 3: deprecated
]

# Category 1: KEEP these - will add step1→step4 support
KEEP_SERVICES = {
    "active_directory",
    "kubernetes",
    "purview",
}

# Services where we should remove assertion_only entries but keep executable ones
# (these are legitimate services that have some unresolvable checks)
CLEAN_ALL_SERVICES = True  # Clean assertion_only from ALL services except KEEP_SERVICES


def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def save_yaml(path, data):
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=200)


def main():
    stats = {
        'dirs_deleted': [],
        'files_cleaned': [],
        'checks_removed': 0,
        'checks_kept': 0,
        'files_deleted': [],
        'skipped_services': [],
    }

    # Phase 1: Delete entire directories for deprecated services
    for dirname in DELETE_DIRS:
        dirpath = os.path.join(BASE_DIR, dirname)
        if os.path.exists(dirpath):
            # Count checks before deletion
            yaml_file = os.path.join(dirpath, f"{dirname}.checks.yaml")
            if os.path.exists(yaml_file):
                data = load_yaml(yaml_file)
                count = len(data.get('checks', []))
                stats['checks_removed'] += count
                print(f"DELETING directory: {dirname}/ ({count} checks)")
            shutil.rmtree(dirpath)
            stats['dirs_deleted'].append(dirname)

    # Phase 2: Clean assertion_only entries from service files
    for service_dir in sorted(os.listdir(BASE_DIR)):
        dirpath = os.path.join(BASE_DIR, service_dir)
        if not os.path.isdir(dirpath):
            continue
        if service_dir in DELETE_DIRS:
            continue  # Already handled
        if service_dir in KEEP_SERVICES:
            stats['skipped_services'].append(service_dir)
            continue  # Category 1 - keep for step1→step4 enhancement

        yaml_file = os.path.join(dirpath, f"{service_dir}.checks.yaml")
        if not os.path.exists(yaml_file):
            continue

        data = load_yaml(yaml_file)
        if not data or 'checks' not in data:
            continue

        original_count = len(data['checks'])
        # Separate executable and assertion_only checks
        executable = []
        removed = []
        for check in data['checks']:
            if check.get('status') == 'assertion_only':
                removed.append(check.get('rule_id', 'unknown'))
            else:
                executable.append(check)

        if not removed:
            continue  # No assertion_only checks to remove

        stats['checks_removed'] += len(removed)
        stats['checks_kept'] += len(executable)

        if not executable:
            # All checks were assertion_only - delete the entire directory
            print(f"DELETING directory: {service_dir}/ (all {original_count} checks were assertion_only)")
            shutil.rmtree(dirpath)
            stats['dirs_deleted'].append(service_dir)
            stats['files_deleted'].append(yaml_file)
        else:
            # Keep executable checks, remove assertion_only
            data['checks'] = executable
            save_yaml(yaml_file, data)
            print(f"CLEANED: {service_dir}/ - removed {len(removed)} assertion_only, kept {len(executable)} executable")
            stats['files_cleaned'].append(service_dir)

    # Summary
    print("\n" + "=" * 60)
    print("REMOVAL SUMMARY")
    print("=" * 60)
    print(f"Directories deleted: {len(stats['dirs_deleted'])}")
    for d in stats['dirs_deleted']:
        print(f"  - {d}/")
    print(f"Files cleaned (assertion_only removed): {len(stats['files_cleaned'])}")
    for f in stats['files_cleaned']:
        print(f"  - {f}/")
    print(f"Total checks removed: {stats['checks_removed']}")
    print(f"Total executable checks kept: {stats['checks_kept']}")
    print(f"Category 1 services SKIPPED (for step1→step4 enhancement):")
    for s in stats['skipped_services']:
        print(f"  - {s}/")


if __name__ == '__main__':
    main()
