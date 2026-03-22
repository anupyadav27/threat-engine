
# scanner_common.py
# Main entry point and shared utilities for Terraform scanning

import os
import sys
import json
import hcl2
from .generic_rule import GenericRule

def parse_terraform_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return hcl2.load(f)

def add_tf_file_metadata(ast_tree, file_path):
    if not isinstance(ast_tree, dict):
        return ast_tree
    for block_type in ['resource', 'variable', 'local']:
        if block_type in ast_tree:
            for block in ast_tree[block_type]:
                if block_type == 'resource':
                    for resource_type, resources in block.items():
                        for resource_name, resource_body in resources.items():
                            if isinstance(resource_body, dict):
                                resource_body['_tf_file'] = file_path
                elif block_type == 'variable':
                    for var_name, var_body in block.items():
                        if isinstance(var_body, dict):
                            var_body['_tf_file'] = file_path
                elif block_type == 'local':
                    for local_name, local_body in block.items():
                        if isinstance(local_body, dict):
                            local_body['_tf_file'] = file_path
    return ast_tree

def parse_all_files_with_metadata(tf_files):
    asts = []
    for file_path in tf_files:
        ast = parse_terraform_file(file_path)
        ast_with_meta = add_tf_file_metadata(ast, file_path)
        asts.append(ast_with_meta)
    return asts

def load_rule_metadata(folder="terraform_docs1"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        raise RuntimeError(f"Metadata folder '{folder}' not found in {script_dir}")
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    rules_meta[data["rule_id"]] = data
            except Exception as e:
                # print(f"Error in file: {file_path}")
                raise
    return rules_meta

def load_rules(metadata_map):
    return [GenericRule(meta) for meta in metadata_map.values()]

def visit_dict(node, visit_fn, findings, filename):
    if isinstance(node, dict):
        visit_fn(node, findings, filename)
        for value in node.values():
            visit_dict(value, visit_fn, findings, filename)
    elif isinstance(node, list):
        for item in node:
            visit_dict(item, visit_fn, findings, filename)

def get_tf_files_from_path(path):
    if os.path.isfile(path):
        if path.endswith('.tf') or path.endswith('.tfvars'):
            return [os.path.abspath(path)]
        else:
            raise RuntimeError(f"File '{path}' is not a .tf or .tfvars file")
    elif os.path.isdir(path):
        tf_files = []
        for fname in os.listdir(path):
            if fname.endswith('.tf') or fname.endswith('.tfvars'):
                tf_files.append(os.path.join(path, fname))
        if not tf_files:
            raise RuntimeError(f"No .tf or .tfvars files found in folder '{path}'")
        return tf_files
    else:
        raise RuntimeError(f"Path '{path}' does not exist")


# API entry point for plugin system
def run_scan(file_path):
    """Scan a single Terraform file and return findings as a list of dicts."""
    try:
        from database.rule_cache import rule_cache
        metadata_map = rule_cache.get_rules("terraform")
    except Exception:
        metadata_map = load_rule_metadata()
    rules = load_rules(metadata_map)
    ast_tree = parse_terraform_file(file_path)
    all_findings = []
    for rule in rules:
        findings = []
        if hasattr(rule, 'visit') and callable(getattr(rule, 'visit')):
            visit_dict(ast_tree, rule.visit, findings, file_path)
            all_findings.extend(findings)
        else:
            all_findings.extend(rule.check(ast_tree, file_path))
    # Clean findings for API (remove 'file' key if present)
    cleaned_results = []
    for finding in all_findings:
        if isinstance(finding, dict) and 'file' in finding:
            del finding['file']
        cleaned_results.append(finding)
    return cleaned_results
