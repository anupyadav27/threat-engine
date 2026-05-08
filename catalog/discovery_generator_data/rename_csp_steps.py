#!/usr/bin/env python3
"""
rename_csp_steps.py
--------------------
Renames AWS and Azure per-service pipeline files to the GCP step1–step6
naming convention.  Also moves root-level scripts and result JSONs to
temp_code/ in each CSP folder.

Run once from the terminal:
    python3 /Users/apple/Desktop/data_pythonsdk/rename_csp_steps.py
"""

import os
import re
import shutil
from collections import defaultdict

BASE = '/Users/apple/Desktop/data_pythonsdk'
AWS_BASE  = os.path.join(BASE, 'aws')
AZURE_BASE = os.path.join(BASE, 'azure')

# ─────────────────────────────────────────────────────────────────────────────
# Rename maps
# ─────────────────────────────────────────────────────────────────────────────

AWS_PER_SERVICE_RENAMES = {
    'boto3_dependencies_with_python_names_fully_enriched.json':
        'step1_api_driven_registry.json',
    'resource_operations_prioritized.json':
        'step2_resource_operations_registry.json',
    'dependency_index.json':
        'step3_read_operation_dependency_chain.json',
    'direct_vars.json':
        'step4_fields_produced_index.json',
    'arn_identifier.json':
        'step5_resource_catalog_inventory_enrich.json',
    'minimal_operations_list.json':
        'step5b_minimal_operations_catalog.json',
    # discovery YAML handled separately (service-specific prefix)
}

AZURE_PER_SERVICE_RENAMES = {
    'azure_dependencies_with_python_names_fully_enriched.json':
        'step1_api_driven_registry.json',
    'operation_registry.json':
        'step1b_operation_registry.json',
    'adjacency.json':
        'step2_operation_adjacency_registry.json',
    'resource_operations_prioritized.json':
        'step2b_resource_operations_registry.json',
    'dependency_index.json':
        'step3_read_operation_dependency_chain.json',
    'direct_vars.json':
        'step4_fields_produced_index.json',
    'id_identifier.json':
        'step5_resource_catalog_inventory_enrich.json',
    'minimal_operations_list.json':
        'step5b_minimal_operations_catalog.json',
    # discovery YAML handled separately
}

# Root-level JSON renames for AWS
AWS_ROOT_JSON_RENAMES = {
    'boto3_dependencies_with_python_names_fully_enriched.json':
        'aws_step1_all_services_registry_enriched.json',
    'boto3_dependencies_with_python_names.json':
        'aws_step1_all_services_registry.json',
    'boto3_dependencies_with_python_names_normalized.json':
        'aws_step1_all_services_registry_normalized.json',
    'direct_vars_all_services.json':
        'aws_step4_all_services_fields_index.json',
}

# Result JSON files to move to temp_code (AWS root)
AWS_ROOT_RESULT_JSONS = {
    'dependency_index_build_results.json',
    'dependency_index_report.json',
    'dependency_index_validation_report.json',
    'comprehensive_validation_report.json',
    'derived_candidates_report.json',
    'direct_vars_operation_types_report.json',
    'direct_vars_traceability_report.json',
    'entity_naming_mismatch_report.json',
    'fields_without_operations_analysis.json',
    'global_summary.json',
    'manual_review_global_summary.json',
    'read_operations_validation_report.json',
}

# Result JSON files to move to temp_code (Azure root)
AZURE_ROOT_RESULT_JSONS = {
    'dependency_index_build_results.json',
    'dependency_index_report.json',
    'manual_review_global_summary.json',
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

stats = defaultdict(int)

def safe_rename(src, dst):
    """Rename src→dst, skipping if src missing or dst already exists."""
    if not os.path.exists(src):
        stats['skipped_missing'] += 1
        return
    if os.path.exists(dst):
        stats['skipped_exists'] += 1
        return
    try:
        os.rename(src, dst)
        stats['renamed'] += 1
    except Exception as e:
        print(f'  ERROR renaming {src} → {dst}: {e}')
        stats['errors'] += 1


def safe_move(src, dst_dir):
    """Move file src into dst_dir/, skipping if src missing."""
    if not os.path.exists(src):
        stats['skipped_missing'] += 1
        return
    dst = os.path.join(dst_dir, os.path.basename(src))
    if os.path.exists(dst):
        stats['skipped_exists'] += 1
        return
    try:
        shutil.move(src, dst)
        stats['moved'] += 1
    except Exception as e:
        print(f'  ERROR moving {src} → {dst}: {e}')
        stats['errors'] += 1


def rename_discovery_yaml(svc_dir, svc_name, csp):
    """
    Rename  {svc}_discovery.yaml  →  step6_{svc}.discovery.yaml
    Also rename the .backup version.
    """
    old_yaml   = os.path.join(svc_dir, f'{svc_name}_discovery.yaml')
    new_yaml   = os.path.join(svc_dir, f'step6_{svc_name}.discovery.yaml')
    old_backup = old_yaml + '.backup'
    new_backup = new_yaml + '.backup'

    if os.path.exists(old_yaml):
        safe_rename(old_yaml, new_yaml)
    if os.path.exists(old_backup):
        safe_rename(old_backup, new_backup)


def apply_renames(svc_dir, rename_map):
    """Apply a flat rename_map {old_name: new_name} inside svc_dir."""
    for old_name, new_name in rename_map.items():
        src = os.path.join(svc_dir, old_name)
        dst = os.path.join(svc_dir, new_name)
        safe_rename(src, dst)


# ─────────────────────────────────────────────────────────────────────────────
# AWS
# ─────────────────────────────────────────────────────────────────────────────

def process_aws():
    print('\n' + '='*60)
    print('AWS — per-service renames')
    print('='*60)

    svc_count = 0
    for entry in sorted(os.scandir(AWS_BASE), key=lambda e: e.name):
        if not entry.is_dir():
            continue
        svc_name = entry.name
        svc_dir  = entry.path

        # Skip temp_code itself (will be created below)
        if svc_name == 'temp_code':
            continue

        apply_renames(svc_dir, AWS_PER_SERVICE_RENAMES)
        rename_discovery_yaml(svc_dir, svc_name, 'aws')
        svc_count += 1

    print(f'  Processed {svc_count} service folders')

    # ── Root-level JSON renames ──
    print('\nAWS — root-level JSON renames')
    for old, new in AWS_ROOT_JSON_RENAMES.items():
        src = os.path.join(AWS_BASE, old)
        dst = os.path.join(AWS_BASE, new)
        safe_rename(src, dst)
        if os.path.exists(dst):
            print(f'  ✓ {old}  →  {new}')

    # ── Create temp_code and move scripts + result JSONs ──
    print('\nAWS — moving scripts and result JSONs to temp_code/')
    tc = os.path.join(AWS_BASE, 'temp_code')
    os.makedirs(tc, exist_ok=True)

    # Move .py scripts
    for entry in os.scandir(AWS_BASE):
        if entry.is_file() and entry.name.endswith('.py'):
            safe_move(entry.path, tc)

    # Move result JSONs
    for fname in AWS_ROOT_RESULT_JSONS:
        safe_move(os.path.join(AWS_BASE, fname), tc)

    print(f'  temp_code/ created at {tc}')


# ─────────────────────────────────────────────────────────────────────────────
# Azure
# ─────────────────────────────────────────────────────────────────────────────

def process_azure():
    print('\n' + '='*60)
    print('Azure — per-service renames')
    print('='*60)

    svc_count = 0
    for entry in sorted(os.scandir(AZURE_BASE), key=lambda e: e.name):
        if not entry.is_dir():
            continue
        svc_name = entry.name

        if svc_name == 'temp_code':
            continue

        svc_dir = entry.path
        apply_renames(svc_dir, AZURE_PER_SERVICE_RENAMES)
        rename_discovery_yaml(svc_dir, svc_name, 'azure')
        svc_count += 1

    print(f'  Processed {svc_count} service folders')

    # ── Create temp_code and move scripts + result JSONs ──
    print('\nAzure — moving scripts and result JSONs to temp_code/')
    tc = os.path.join(AZURE_BASE, 'temp_code')
    os.makedirs(tc, exist_ok=True)

    # Move .py scripts
    for entry in os.scandir(AZURE_BASE):
        if entry.is_file() and entry.name.endswith('.py'):
            safe_move(entry.path, tc)

    # Move result JSONs
    for fname in AZURE_ROOT_RESULT_JSONS:
        safe_move(os.path.join(AZURE_BASE, fname), tc)

    print(f'  temp_code/ created at {tc}')


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    process_aws()
    process_azure()

    print('\n' + '='*60)
    print('SUMMARY')
    print('='*60)
    print(f"  Renamed  : {stats['renamed']}")
    print(f"  Moved    : {stats['moved']}")
    print(f"  Skipped (file not found) : {stats['skipped_missing']}")
    print(f"  Skipped (dest exists)    : {stats['skipped_exists']}")
    print(f"  Errors   : {stats['errors']}")
    print()
