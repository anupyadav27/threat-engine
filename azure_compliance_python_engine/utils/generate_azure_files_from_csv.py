#!/usr/bin/env python3
import csv
import json
import re
import hashlib
from pathlib import Path

# Workspace root (threat-engine)
ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "compliance" / "consolidated_rules_phase4_2025-11-08_FINAL_WITH_ALL_IDS.csv"
SERVICES_ROOT = ROOT / "azure_compliance_python_engine" / "services"
LOGS_DIR = ROOT / "azure_compliance_python_engine" / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_PATH = LOGS_DIR / "generate_azure_files_from_csv_summary.json"

SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")

SERVICE_NORMALIZATION = {
    # map odd or truncated names from CSV to our folder names
    'active': 'ad',
    'aad': 'ad',
    'entra': 'ad',
    'security': 'securitycenter',
    'vm': 'virtualmachines',
    'vms': 'virtualmachines',
}

FILENAME_MAX = 180  # conservative for APFS/HFS filename length


def safe_name(name: str) -> str:
    return SAFE_CHARS_RE.sub('_', name)


def filename_for_rule(rule_id: str) -> str:
    base = safe_name(rule_id)
    if len(base) <= FILENAME_MAX:
        return base + ".yaml"
    digest = hashlib.sha1(rule_id.encode('utf-8')).hexdigest()[:10]
    trimmed = base[: (FILENAME_MAX - 1 - len(digest))]  # keep room for '_' + hash
    return f"{trimmed}_{digest}.yaml"

# Simple title from rule_id helper

def rule_id_to_title(rule_id: str) -> str:
    try:
        parts = rule_id.split('.')
        tail = parts[-3:]
        title = ' '.join(p.replace('_',' ').replace('-', ' ') for p in tail)
        return re.sub(r"\s+", " ", title).strip().title()
    except Exception:
        return rule_id

# Ensure folder exists

def ensure_dirs(service: str):
    d = SERVICES_ROOT / service
    (d / 'metadata').mkdir(parents=True, exist_ok=True)
    (d / 'rules').mkdir(parents=True, exist_ok=True)
    return d

# Write file only if not exists; else update headers if missing

def write_file(path: Path, content: str):
    if not path.exists():
        path.write_text(content, encoding='utf-8')
        return 'created'
    existing = path.read_text(encoding='utf-8')
    changed = False
    header = f"provider: azure\nservice: {path.parts[-3]}\n"
    head_lines = existing.splitlines()[0:3]
    if not any(l.startswith('provider:') for l in head_lines):
        existing = header + existing
        changed = True
    if changed:
        path.write_text(existing, encoding='utf-8')
        return 'updated'
    return 'skipped'

# Minimal metadata yaml

def gen_metadata_yaml(rule_id: str, service: str, category: str):
    title = rule_id_to_title(rule_id)
    return f"""
provider: azure
service: {service}
rule_id: {rule_id}
title: {title}
description: Auto-generated metadata stub for {rule_id}. Please complete fields as needed.
category_raw: {category}
severity: medium
scope: subscription
cspm_category: ""
cspm_subcategory: ""
security_domain: ""
compliance_frameworks: []
notes: "Prefilled from CSV. Complete remaining metadata per template."
""".lstrip()

# Minimal rule yaml

def gen_rule_yaml(rule_id: str, service: str, category: str):
    title = rule_id_to_title(rule_id)
    return f"""
provider: azure
service: {service}
# discovery: add appropriate discovery calls later
checks:
  - check_id: {rule_id}
    title: {title}
    severity: medium
    # TODO: add discovery and check logic based on service API
""".lstrip()


def normalize_service(svc: str) -> str:
    svc_l = (svc or '').strip().lower()
    return SERVICE_NORMALIZATION.get(svc_l, svc_l)


def collect_rule_ids_from_files(pattern: str, key_regex: re.Pattern) -> set[str]:
    ids: set[str] = set()
    for p in SERVICES_ROOT.rglob(pattern):
        try:
            txt = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        m = key_regex.search(txt)
        if m:
            ids.add(m.group(1).strip())
    return ids


def main():
    if not CSV_PATH.exists():
        err = {"error": f"CSV not found: {CSV_PATH}"}
        SUMMARY_PATH.write_text(json.dumps(err, indent=2), encoding='utf-8')
        print("SUMMARY:" + json.dumps(err))
        raise SystemExit(2)

    created_meta = created_rules = updated = skipped = 0
    total_rows = 0
    services_set = set()
    csv_rule_ids = set()

    with CSV_PATH.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cp = (row.get('cloud_provider') or '').strip().lower()
            if cp != 'azure':
                continue
            rule_id = (row.get('rule_id') or '').strip()
            service_raw = (row.get('service') or '').strip()
            category = (row.get('category') or '').strip()
            if not rule_id or not service_raw:
                continue
            service = normalize_service(service_raw)
            total_rows += 1
            services_set.add(service)
            csv_rule_ids.add(rule_id)

            ensure_dirs(service)
            filename = filename_for_rule(rule_id)
            meta_path = SERVICES_ROOT / service / 'metadata' / filename
            rule_path = SERVICES_ROOT / service / 'rules' / filename

            res1 = write_file(meta_path, gen_metadata_yaml(rule_id, service, category))
            res2 = write_file(rule_path, gen_rule_yaml(rule_id, service, category))
            created_meta += 1 if res1 == 'created' else 0
            created_rules += 1 if res2 == 'created' else 0
            updated += (1 if res1 == 'updated' else 0) + (1 if res2 == 'updated' else 0)
            skipped += (1 if res1 == 'skipped' else 0) + (1 if res2 == 'skipped' else 0)

    # Tally generated files by parsing rule_id/check_id within file contents
    meta_rule_ids = collect_rule_ids_from_files('metadata/*.yaml', re.compile(r'^rule_id:\s*(.+)$', re.MULTILINE))
    rule_rule_ids = collect_rule_ids_from_files('rules/*.yaml', re.compile(r'^\s*-?\s*check_id:\s*(.+)$', re.MULTILINE))

    missing_meta = sorted(csv_rule_ids - meta_rule_ids)
    missing_rules = sorted(csv_rule_ids - rule_rule_ids)

    summary = {
        'csv_rows_scanned': total_rows,
        'unique_services': len(services_set),
        'unique_rule_ids': len(csv_rule_ids),
        'files_created_metadata': created_meta,
        'files_created_rules': created_rules,
        'files_updated': updated,
        'files_skipped_existing': skipped,
        'generated_metadata_files': len(meta_rule_ids),
        'generated_rule_files': len(rule_rule_ids),
        'missing_metadata_count': len(missing_meta),
        'missing_rules_count': len(missing_rules),
        'sample_missing_metadata': missing_meta[:10],
        'sample_missing_rules': missing_rules[:10],
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print("SUMMARY:" + json.dumps(summary))

if __name__ == '__main__':
    main()
