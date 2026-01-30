# scanner_file.py
# Per-file scanning logic (Mode A)
from .scanner_common import parse_terraform_file, load_rule_metadata, load_rules, visit_dict
import os
import json

def scan_file(tf_file, rules):
    ast_tree = parse_terraform_file(tf_file)
    all_findings = []
    for rule in rules:
        findings = []
        if hasattr(rule, 'visit') and callable(getattr(rule, 'visit')):
            visit_dict(ast_tree, rule.visit, findings, tf_file)
            all_findings.extend(findings)
        else:
            pass
            all_findings.extend(rule.check(ast_tree, tf_file))
    return all_findings

def per_file_scan(tf_files):
    metadata_map = load_rule_metadata()
    user_choice = input("Do you want to check against all rules or a specific rule? (Enter 'all' or 'specific'): ").strip().lower()
    selected_rule_id = None
    if user_choice == 'specific':
        rule_name_input = input("Enter rule name: ").strip().lower()
        for rule_id, meta in metadata_map.items():
            rule_name = meta.get("name") or meta.get("title") or ""
            if rule_name.lower() == rule_name_input:
                selected_rule_id = rule_id
                break
        if selected_rule_id:
            print(f"[rule_engine] Running only rule: {metadata_map[selected_rule_id].get('name', metadata_map[selected_rule_id].get('title', ''))} (id={selected_rule_id})")
            from .generic_rule import GenericRule
            rules = [GenericRule(metadata_map[selected_rule_id])]
        else:
            print(f"Rule '{rule_name_input}' not found. Running all rules instead.")
            rules = load_rules(metadata_map)
    else:
        rules = load_rules(metadata_map)
    all_results = []
    for tf_file in tf_files:
        results = scan_file(tf_file, rules)
        for finding in results:
            if isinstance(finding, dict) and 'file' in finding:
                del finding['file']
    # print(f"\nScan Summary for file: {tf_file}")
    # print(f"Vulnerabilities found: {len(results)}")
    # print(json.dumps(results, indent=2))
        all_results.extend(results)
        base_name = os.path.splitext(os.path.basename(tf_file))[0]
        report_file = os.path.join(os.path.dirname(tf_file), f"{base_name}_report.json")
        report_data = {
            "file_scanned": tf_file,
            "vulnerabilities_found": len(results),
            "findings": results
        }
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    # API entry point for plugin system
    def run_scan(file_path):
        """Scan a single Terraform file and return findings as a list of dicts."""
        metadata_map = load_rule_metadata()
        rules = load_rules(metadata_map)
        results = scan_file(file_path, rules)
        cleaned_results = []
        for finding in results:
            if isinstance(finding, dict):
                if 'file' in finding:
                    del finding['file']
            cleaned_results.append(finding)
        return cleaned_results
