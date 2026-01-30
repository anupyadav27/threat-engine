# API entry point for folder scanning (for use by FastAPI)
def run_terraform_scan(tf_files: list) -> dict:
    asts = parse_all_files_with_metadata(tf_files)
    merged_ast = merge_asts(asts)
    variables, locals_, resources, outputs, modules = build_symbol_tables(merged_ast)
    resolve_references_in_dict(merged_ast, variables, locals_)
    metadata_map = load_rule_metadata()
    rules = load_rules(metadata_map)
    findings = scan_merged_ast(merged_ast, rules)
    return {
        "files": tf_files,
        "findings": findings
    }
# scanner_project.py
# Project-level (merged AST) scanning logic (Mode B)
from .scanner_common import parse_all_files_with_metadata, load_rule_metadata, load_rules, visit_dict
import os
import json


import re

# --- Reference resolution logic (move above merged_project_scan) ---
def resolve_reference_string(s, variables, locals_):
    # Add debug logging
    # original = s
    def replacer(match):
        ref = match.group(1)
        if ref.startswith("var."):
            var_name = ref[4:]
            value = variables.get(var_name, None)
            if value is not None:
                # print(f"[resolve_reference_string] Resolved ${{var.{var_name}}} -> {value}")
                return str(value)
            else:
                # print(f"[resolve_reference_string] Unresolved ${{var.{var_name}}}, keeping as-is")
                return f"${{{ref}}}"
        elif ref.startswith("local."):
            local_name = ref[6:]
            value = locals_.get(local_name, None)
            if value is not None:
                # print(f"[resolve_reference_string] Resolved ${{local.{local_name}}} -> {value}")
                return str(value)
            else:
                # print(f"[resolve_reference_string] Unresolved ${{local.{local_name}}}, keeping as-is")
                return f"${{{ref}}}"
    # print(f"[resolve_reference_string] Unknown reference ${{{ref}}}, keeping as-is")
        return f"${{{ref}}}"

    # If the string is exactly a reference, try to resolve it
    exact_var = re.fullmatch(r"\${var\.([A-Za-z0-9_]+)}", s)
    exact_local = re.fullmatch(r"\${local\.([A-Za-z0-9_]+)}", s)
    if exact_var:
        var_name = exact_var.group(1)
        value = variables.get(var_name, None)
        if value is not None:
            # print(f"[resolve_reference_string] Resolved exact ${{var.{var_name}}} -> {value}")
            return value
        else:
            # print(f"[resolve_reference_string] Unresolved exact ${{var.{var_name}}}, keeping as-is")
            return s
    if exact_local:
        local_name = exact_local.group(1)
        value = locals_.get(local_name, None)
        if value is not None:
            # print(f"[resolve_reference_string] Resolved exact ${{local.{local_name}}} -> {value}")
            return value
        else:
            # print(f"[resolve_reference_string] Unresolved exact ${{local.{local_name}}}, keeping as-is")
            return s

    # Otherwise, replace all ${...} patterns inside the string
    s_new = re.sub(r"\${([^}]+)}", replacer, s)
    # Also handle plain var.foo or local.bar
    var_match = re.fullmatch(r"var\.([A-Za-z0-9_]+)", s_new)
    local_match = re.fullmatch(r"local\.([A-Za-z0-9_]+)", s_new)
    if var_match:
        var_name = var_match.group(1)
        value = variables.get(var_name, None)
        if value is not None:
            # print(f"[resolve_reference_string] Resolved plain var.{var_name} -> {value}")
            return value
        else:
            # print(f"[resolve_reference_string] Unresolved plain var.{var_name}, keeping as-is")
            return s_new
    if local_match:
        local_name = local_match.group(1)
        value = locals_.get(local_name, None)
        if value is not None:
            # print(f"[resolve_reference_string] Resolved plain local.{local_name} -> {value}")
            return value
        else:
            # print(f"[resolve_reference_string] Unresolved plain local.{local_name}, keeping as-is")
            return s_new
    # if s != s_new:
    #     print(f"[resolve_reference_string] After replacements: '{original}' -> '{s_new}'")
    return s_new

def resolve_references_in_dict(d, variables, locals_):
    # Run multiple passes until no ${...} remain
    def has_unresolved_refs(obj):
        if isinstance(obj, str):
            return bool(re.search(r"\${[^}]+}", obj))
        elif isinstance(obj, dict):
            return any(has_unresolved_refs(v) for v in obj.values())
        elif isinstance(obj, list):
            return any(has_unresolved_refs(i) for i in obj)
        return False

    def resolve_pass(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, str):
                    d[k] = resolve_reference_string(v, variables, locals_)
                else:
                    resolve_pass(v)
        elif isinstance(d, list):
            for i, item in enumerate(d):
                if isinstance(item, str):
                    d[i] = resolve_reference_string(item, variables, locals_)
                else:
                    resolve_pass(item)

    max_passes = 5
    for pass_num in range(max_passes):
    # print(f"[resolve_references_in_dict] Pass {pass_num+1}")
        resolve_pass(d)
        if not has_unresolved_refs(d):
            # print(f"[resolve_references_in_dict] All references resolved after {pass_num+1} passes.")
            break
    else:
        pass
    # print(f"[resolve_references_in_dict] Some references could not be resolved after {max_passes} passes.")

def merge_asts(ast_list):
    merged = {'resource': [], 'variable': [], 'local': []}
    for ast in ast_list:
        if not isinstance(ast, dict):
            continue
        for key in ['resource', 'variable', 'local']:
            if key in ast and isinstance(ast[key], list):
                merged[key].extend(ast[key])
    return {k: v for k, v in merged.items() if v}

def build_symbol_tables(merged_ast):
    variables = {}
    locals_ = {}
    resources = {}
    outputs = {}
    modules = {}
    # Variables
    for block in merged_ast.get('variable', []):
        for var_name, var_body in block.items():
            variables[var_name] = var_body.get('default') if 'default' in var_body else None
            # print(f"[symbol_table] Added variable: {var_name} = {variables[var_name]}")
    # Locals
    for block in merged_ast.get('local', []):
        for local_name, local_body in block.items():
            locals_[local_name] = local_body
            # print(f"[symbol_table] Added local: {local_name} = {locals_[local_name]}")
    # Resources
    for block in merged_ast.get('resource', []):
        for resource_type, resources_dict in block.items():
            for resource_name, resource_body in resources_dict.items():
                key = f"{resource_type}.{resource_name}"
                resources[key] = resource_body
                # print(f"[symbol_table] Added resource: {key}")
    # Outputs
    for block in merged_ast.get('output', []):
        for output_name, output_body in block.items():
            outputs[output_name] = output_body
            # print(f"[symbol_table] Added output: {output_name}")
    # Modules
    for block in merged_ast.get('module', []):
        for module_name, module_body in block.items():
            modules[module_name] = module_body
            # print(f"[symbol_table] Added module: {module_name}")
    return variables, locals_, resources, outputs, modules

def scan_merged_ast(merged_ast, rules):
    all_findings = []
    for rule in rules:
        findings = []
    # print(f"[rule_engine] Applying rule: {getattr(rule, 'metadata', getattr(rule, '__class__', 'unknown'))}")
        if hasattr(rule, 'visit') and callable(getattr(rule, 'visit')):
            visit_dict(merged_ast, rule.visit, findings, 'merged')
            all_findings.extend(findings)
        else:
            all_findings.extend(rule.check(merged_ast, 'merged'))
    return all_findings

def merged_project_scan(tf_files):
    asts = parse_all_files_with_metadata(tf_files)
    # Save ASTs before merging
    with open("debug_asts_before.json", "w", encoding="utf-8") as f:
        json.dump([
            {"file": tf_files[i], "ast": asts[i]} for i in range(len(tf_files))
        ], f, indent=2)

    merged_ast = merge_asts(asts)
    # Save merged AST before resolving references
    with open("debug_merged_ast_before_resolving.json", "w", encoding="utf-8") as f:
        json.dump(merged_ast, f, indent=2)

    variables, locals_, resources, outputs, modules = build_symbol_tables(merged_ast)
    resolve_references_in_dict(merged_ast, variables, locals_)

    # Save merged AST after resolving references
    with open("debug_merged_ast_after_resolving.json", "w", encoding="utf-8") as f:
        json.dump(merged_ast, f, indent=2)

    metadata_map = load_rule_metadata()

    # --- Single rule selection logic (y/n prompt, strict match, only one rule if found) ---
    user_choice = input("Do you want to check against a specific rule? (y/n): ").strip().lower()
    selected_rule_id = None
    if user_choice == 'y':
        rule_name_input = input("Enter rule name: ").strip().lower()
        for rule_id, meta in metadata_map.items():
            rule_name = meta.get("name") or meta.get("title") or ""
            if rule_name.lower() == rule_name_input:
                selected_rule_id = rule_id
                break
        if selected_rule_id:
            print(f"[rule_engine] Running only rule: {metadata_map[selected_rule_id].get('name', metadata_map[selected_rule_id].get('title', ''))} (id={selected_rule_id})")
            from generic_rule import GenericRule
            rules = [GenericRule(metadata_map[selected_rule_id])]
        else:
            print(f"Rule '{rule_name_input}' not found. Running all rules instead.")
            rules = load_rules(metadata_map)
    else:
        rules = load_rules(metadata_map)
    results = scan_merged_ast(merged_ast, rules)
    # Reporting
    if len(tf_files) == 1:
        base_name = os.path.splitext(os.path.basename(tf_files[0]))[0]
        report_dir = os.path.dirname(tf_files[0])
        report_file = os.path.join(report_dir, f"{base_name}_report.json")
        report_label = base_name
    else:
        parent_dirs = set(os.path.dirname(f) for f in tf_files)
        if len(parent_dirs) == 1:
            folder_name = os.path.basename(list(parent_dirs)[0])
            report_dir = list(parent_dirs)[0]
            report_file = os.path.join(report_dir, f"{folder_name}_report.json")
            report_label = folder_name
        else:
            report_file = os.path.join(os.getcwd(), "merged_report.json")
            report_label = 'merged'
    print(f"\nScan Summary for {report_label} configuration")
    print(f"Vulnerabilities found: {len(results)}")
    print(json.dumps(results, indent=2))
    report_data = {
        "file_scanned": report_label,
        "vulnerabilities_found": len(results),
        "findings": results
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Detailed report saved to: {report_file}")
    print(f"Number of rules loaded: {len(rules)}")
