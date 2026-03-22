import sys
import os
import hcl2
import json
import terraform_rule_classes  # Import the whole module
import inspect
import traceback

# Step 1: Input Handling (prompt user for file name)
tf_file = input("Enter the Terraform (.tf) file name to scan: ").strip()
# Look for the file in the same directory as the script if not found in cwd
if not os.path.isfile(tf_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    alt_path = os.path.join(script_dir, tf_file)
    if os.path.isfile(alt_path):
        tf_file = alt_path
    else:
        print(f"File '{tf_file}' not found.")
        sys.exit(1)

# Step 2: Parse Terraform file to AST-like structure
def parse_terraform_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return hcl2.load(f)

# Step 3: Load rule metadata from JSON files
def load_rule_metadata(folder="terraform_docs1"):
    # Look for metadata folder in the same directory as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        print(f"Metadata folder '{folder}' not found in {script_dir}.")
        sys.exit(1)
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            with open(os.path.join(folder_path, filename), encoding="utf-8") as f:
                data = json.load(f)
                rules_meta[data["rule_id"]] = data
    return rules_meta

# Step 4: Define base rule class
class BaseRule:
    def __init__(self, metadata):
        self.metadata = metadata
    def check(self, ast_tree, filename):
        raise NotImplementedError
    def visit(self, node, findings, filename):
        pass  # Optional: override in rules for visitor pattern

# Generic dict visitor utility
def visit_dict(node, visit_fn, findings, filename):
    if isinstance(node, dict):
        visit_fn(node, findings, filename)
        for value in node.values():
            visit_dict(value, visit_fn, findings, filename)
    elif isinstance(node, list):
        for item in node:
            visit_dict(item, visit_fn, findings, filename)

# Step 6: Rule loader (dynamic)
def load_rules(metadata_map):
    rules = []
    # print("[DEBUG] All classes discovered in terraform_rule_classes:")
    for name, cls in inspect.getmembers(terraform_rule_classes, inspect.isclass):
    # print(f"  {name}")
        # Only load classes that are not the base class and have matching metadata
        if name in ('TerraformRule', 'BaseRule'):
            continue
        rule_id = getattr(cls, 'rule_id', None)
        if rule_id is None:
            try:
                instance = cls()
                rule_id = getattr(instance, 'rule_id', None)
            except Exception as e:
                # print(f"[ERROR] Could not instantiate {name}: {e}")
                pass
            if rule_id is None:
                # print(f"[ERROR] Rule class '{name}' has no rule_id. Skipping.")
                continue
        if rule_id is None:
            # print(f"[ERROR] Rule class '{name}' has no rule_id. Skipping.")
            continue
        if rule_id not in metadata_map:
            # print(f"[ERROR] No metadata found for rule_id '{rule_id}' (class: {name}). Skipping.")
            continue
        meta = metadata_map[rule_id]
        try:
            rules.append(cls())
            # print(f"[DEBUG] Loaded rule: {name} (rule_id: {rule_id})")
        except Exception as e:
            # print(f"[ERROR] Could not instantiate {name} (rule_id: {rule_id}): {e}")
            # traceback.print_exc()
            pass
    return rules

# Step 7: Scanner engine
def scan_file(tf_file, rules):
    ast_tree = parse_terraform_file(tf_file)
    all_findings = []
    for rule in rules:
        findings = []
        # If the rule has a visit method, use the visitor pattern
        if hasattr(rule, 'visit') and callable(getattr(rule, 'visit')):
            visit_dict(ast_tree, rule.visit, findings, tf_file)
            all_findings.extend(findings)
        else:
            # Fallback to check method
            all_findings.extend(rule.check(ast_tree, tf_file))
    return all_findings

# Step 8: Reporting
if __name__ == "__main__":
    metadata_map = load_rule_metadata()
    rules = load_rules(metadata_map)
    results = scan_file(tf_file, rules)
    print(f"\nScan Summary for file: {tf_file}")
    print(f"Vulnerabilities found: {len(results)}")
    print(json.dumps(results, indent=2))
    # Save output to a detailed report file with summary
    base_name = os.path.splitext(os.path.basename(tf_file))[0]
    report_file = os.path.join(os.path.dirname(tf_file), f"{base_name}_report.json")
    report_data = {
        "file_scanned": tf_file,
        "vulnerabilities_found": len(results),
        "findings": results
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Detailed report saved to: {report_file}")
    print(f"Number of rules loaded: {len(rules)}")
