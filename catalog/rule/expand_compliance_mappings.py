#!/usr/bin/env python3
"""
Expand Azure compliance framework mappings from 339 → 2000+ rules.

Strategy:
  1. Learn domain→framework patterns from the 339 existing mapped rules
  2. For each domain, identify "core" frameworks (appear in ≥25% of mapped rules)
  3. Apply core frameworks to unmapped rules in the same domain
  4. Write updated YAML with compliance fields added

This is conservative — only assigns frameworks that are already well-established
in the domain based on Azure Policy initiative data.
"""

import yaml
from collections import defaultdict
from pathlib import Path
from copy import deepcopy

BASE = Path("/Users/apple/Desktop/threat-engine")
RULES_PATH = BASE / "catalog/rule/azure_rules_by_category.yaml"
OUTPUT_PATH = BASE / "catalog/rule/azure_rules_by_category.yaml"

# ─── Step 1: Load rules ─────────────────────────────────────────────────────

with open(RULES_PATH) as f:
    rules = yaml.safe_load(f)

# ─── Step 2: Learn domain → framework patterns ──────────────────────────────

domain_framework_counts = defaultdict(lambda: defaultdict(int))
domain_total_mapped = defaultdict(int)

for svc, resources in rules.items():
    if not isinstance(resources, dict):
        continue
    for res, rule_list in resources.items():
        if not isinstance(rule_list, list):
            continue
        for r in rule_list:
            if r.get('compliance'):
                domain = r.get('domain', 'unknown')
                domain_total_mapped[domain] += 1
                for fw in r['compliance']:
                    domain_framework_counts[domain][fw] += 1

# ─── Step 3: Build domain → core frameworks map (≥25% threshold) ─────────────

THRESHOLD = 0.25  # Framework must appear in ≥25% of domain's mapped rules
MIN_COUNT = 2     # Must appear in at least 2 rules

domain_core_frameworks = {}

for domain, fw_counts in domain_framework_counts.items():
    total = domain_total_mapped[domain]
    if total < 2:  # Skip domains with too few samples
        continue
    core = []
    for fw, count in sorted(fw_counts.items(), key=lambda x: -x[1]):
        if count >= max(total * THRESHOLD, MIN_COUNT):
            core.append(fw)
    if core:
        domain_core_frameworks[domain] = sorted(core)

print("Domain → Core Frameworks (≥25% threshold):")
print("=" * 70)
for domain in sorted(domain_core_frameworks.keys()):
    fws = domain_core_frameworks[domain]
    print(f"  {domain}: {len(fws)} frameworks")
    for fw in fws[:5]:
        count = domain_framework_counts[domain][fw]
        total = domain_total_mapped[domain]
        print(f"    - {fw} ({count}/{total} = {count/total*100:.0f}%)")
    if len(fws) > 5:
        print(f"    ... and {len(fws)-5} more")
print()

# ─── Step 4: Apply frameworks to unmapped rules ─────────────────────────────

added_count = 0
already_mapped = 0
no_domain_match = 0
skipped_domains = set()

for svc, resources in rules.items():
    if not isinstance(resources, dict):
        continue
    for res, rule_list in resources.items():
        if not isinstance(rule_list, list):
            continue
        for r in rule_list:
            if r.get('compliance'):
                already_mapped += 1
                continue

            domain = r.get('domain', 'unknown')
            if domain in domain_core_frameworks:
                r['compliance'] = domain_core_frameworks[domain]
                r['compliance_source'] = 'domain_inference'
                added_count += 1
            else:
                skipped_domains.add(domain)
                no_domain_match += 1

# ─── Step 5: Report ─────────────────────────────────────────────────────────

total_rules = already_mapped + added_count + no_domain_match
print(f"Results:")
print(f"  Total rules: {total_rules}")
print(f"  Already mapped: {already_mapped}")
print(f"  Newly mapped (domain inference): {added_count}")
print(f"  No domain match: {no_domain_match}")
print(f"  Coverage: {already_mapped}/{total_rules} → {already_mapped + added_count}/{total_rules}")
print(f"  Coverage %: {already_mapped/total_rules*100:.1f}% → {(already_mapped + added_count)/total_rules*100:.1f}%")
print()

if skipped_domains:
    print(f"Skipped domains (too few samples to infer): {skipped_domains}")
    print()

# ─── Step 6: Write updated YAML ─────────────────────────────────────────────

# Custom representer to keep lists on single line when short
class CompactDumper(yaml.Dumper):
    pass

def str_representer(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

CompactDumper.add_representer(str, str_representer)

with open(OUTPUT_PATH, 'w') as f:
    # Write header
    f.write("# Azure Rules by Category — Unified Catalog\n")
    f.write(f"# Total rules: {total_rules}\n")
    f.write(f"# With compliance frameworks: {already_mapped + added_count}\n")
    f.write(f"#   - From Azure Policy initiatives: {already_mapped}\n")
    f.write(f"#   - From domain inference: {added_count}\n")
    f.write(f"# Compliance frameworks: 70\n")
    f.write("# Sources: engine checks (267), Azure Policy (1223), compliance DB (1155)\n")
    f.write("#\n")
    f.write("# compliance_source: domain_inference = frameworks inferred from security domain\n")
    f.write("# compliance_source: (absent) = frameworks from Azure Policy initiative mapping\n\n")
    yaml.dump(rules, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=200)

print(f"Written: {OUTPUT_PATH}")
