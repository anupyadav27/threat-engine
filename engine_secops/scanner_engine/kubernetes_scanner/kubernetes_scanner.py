"""
Kubernetes YAML Scanner - Enhanced Version

A scanner that applies security rules to Kubernetes manifests (YAML files).
Handles YAML parsing, multi-document support, and rule execution.
"""

import sys
import re
import os
import json
import yaml
from kubernetes_scanner import kubernetes_generic_rule
from kubernetes_scanner import kubernetes_ast_builder
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a single rule violation finding."""
    rule_id: str
    message: str
    file: str
    line: Optional[int]
    severity: str
    resource: str

    def __hash__(self) -> int:
        """Enable finding deduplication based on core attributes."""
        return hash((self.rule_id, self.file, self.line, self.message, self.resource))


def load_rule_metadata(folder="kubernetes_docs"):
    """Load all rule metadata JSON files from the specified folder."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".json") or filename.endswith("_metadata.json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "rule_id" in data:
                        rules_meta[data["rule_id"]] = data
            except Exception as e:
                print(f"Warning: Failed to load {filename}: {e}", file=sys.stderr)
                continue
    
    return rules_meta


def get_all_k8s_files(scan_path):
    """
    Recursively collect all Kubernetes YAML files.
    Supports .yaml, .yml extensions.
    """
    k8s_files = []
    
    if os.path.isfile(scan_path):
        if scan_path.endswith(".yaml") or scan_path.endswith(".yml"):
            k8s_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    k8s_files.append(os.path.join(root, file))
    
    return k8s_files


def parse_k8s_file(file_path):
    """
    Parse Kubernetes YAML file and convert to AST/Semantic Model.
    Uses SonarSource-inspired approach: Lexing → Parsing → Schema Binding → Semantic Model.
    Returns a list of AST dictionaries ready for rule analysis.
    """
    try:
        # Use the new AST builder
        ast_resources = kubernetes_ast_builder.parse_kubernetes_file_to_ast(file_path)
        return ast_resources
    
    except Exception as e:
        print(f"Error parsing Kubernetes file {file_path}: {str(e)}", file=sys.stderr)
        return []


def is_kubernetes_resource(resource):
    """
    Check if an AST resource is a valid Kubernetes resource.
    Valid resources must have 'apiVersion' and 'kind' fields.
    """
    if not isinstance(resource, dict):
        return False
    
    return 'apiVersion' in resource and 'kind' in resource


def parse_k8s_file_with_fallback(file_path):
    """
    Parse Kubernetes YAML with fallback handling.
    Returns AST resources ready for rule analysis.
    """
    ast_resources = parse_k8s_file(file_path)
    
    if not ast_resources:
        # Return empty list if no valid K8s resources found
        return []
    
    # AST resources are already in the correct format
    return ast_resources


def run_scanner(scan_path):
    """
    Main scanner function that applies all rules to all Kubernetes files.
    Returns a list of findings.
    """
    rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    k8s_files = get_all_k8s_files(scan_path)
    all_findings = []
    
    for k8s_file in k8s_files:
        # Parse to AST/Semantic Model
        ast_resources = parse_k8s_file_with_fallback(k8s_file)
        
        if not ast_resources:
            continue
        
        # Process each resource AST separately for better isolation
        for ast_resource in ast_resources:
            for rule in rules:
                findings = kubernetes_generic_rule.run_rule(rule, ast_resource, k8s_file)
                if findings:
                    for finding in findings:
                        finding['file'] = k8s_file
                        all_findings.append(finding)
    
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = (
            f.get('rule_id'),
            f.get('file'),
            f.get('line'),
            f.get('message'),
            f.get('resource', '')
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    return deduped


def run_scan(file_path):
    """
    Compatibility wrapper for the scanner plugin system.
    Scans a single file or directory path and returns findings.
    """
    return run_scanner(file_path)


def clean_for_json(obj, depth=0, max_depth=10):
    """
    Clean objects for JSON serialization.
    Removes circular references and non-serializable objects.
    """
    if depth > max_depth:
        return f"<Max depth {max_depth} reached>"
    
    if isinstance(obj, dict):
        # Remove internal line number markers from output
        obj = {k: v for k, v in obj.items() if k != '__line__'}
        return {key: clean_for_json(value, depth+1, max_depth) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [clean_for_json(item, depth+1, max_depth) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj


def load_rules(language: str = "kubernetes") -> Dict[str, Dict]:
    """Load all rule JSON files for Kubernetes."""
    rules_path = os.path.join("rules", language)
    rules = {}
    
    if not os.path.exists(rules_path):
        return rules
    
    for filename in os.listdir(rules_path):
        if filename.endswith('.json'):
            rule_id = filename.replace('.json', '')
            with open(os.path.join(rules_path, filename), 'r') as f:
                rules[rule_id] = json.load(f)
    
    return rules


def load_metadata(language: str = "kubernetes") -> Dict[str, Dict]:
    """Load all metadata JSON files for Kubernetes."""
    metadata_path = os.path.join("metadata", language)
    metadata = {}
    
    if not os.path.exists(metadata_path):
        return metadata
    
    for filename in os.listdir(metadata_path):
        if filename.endswith('_metadata.json'):
            rule_id = filename.replace('_metadata.json', '')
            with open(os.path.join(metadata_path, filename), 'r') as f:
                metadata[rule_id] = json.load(f)
    
    return metadata


def merge_rule_and_metadata(rule_json: Dict, metadata_json: Dict) -> Dict:
    """Combine rule and metadata into a unified rule object."""
    merged = {
        "rule_id": rule_json.get("rule_id", ""),
        "title": rule_json.get("title", ""),
        "description": rule_json.get("description", ""),
        "resource_types": rule_json.get("resource_types", []),
        "api_versions": rule_json.get("api_versions", []),
        "logic": metadata_json.get("logic", {}),
        "severity": rule_json.get("severity", "INFO"),
        "examples": metadata_json.get("examples", []),
        "recommendation": metadata_json.get("recommendation", ""),
        "impact": metadata_json.get("impact", "")
    }
    return merged


def get_kubernetes_extensions() -> List[str]:
    """Return list of Kubernetes manifest file extensions."""
    return [".yaml", ".yml"]


def get_all_files(path: str) -> List[str]:
    """Recursively collect all Kubernetes YAML files."""
    return get_all_k8s_files(path)


def parse_file_to_manifest(file_path: str) -> Dict:
    """
    Parse a Kubernetes YAML file to manifest structure.
    Returns a dictionary containing all resources.
    """
    return parse_k8s_file_with_fallback(file_path)


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))


def format_findings_report(findings: List[Dict], files_scanned: int) -> Dict:
    """
    Format findings into a structured report.
    Groups findings by severity and provides summary statistics.
    """
    # Group by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.get('severity', 'INFO')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Group by rule
    rule_counts = {}
    for finding in findings:
        rule_id = finding.get('rule_id', 'unknown')
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
    
    return {
        "summary": {
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_rule": rule_counts
        },
        "findings": findings
    }


def validate_kubernetes_manifest(file_path: str) -> tuple[bool, Optional[str]]:
    """
    Validate if a file contains valid Kubernetes manifests.
    Returns (is_valid, error_message).
    """
    try:
        resources = parse_k8s_file(file_path)
        if not resources:
            return False, "No valid YAML documents found"
        
        k8s_resources = [r for r in resources if is_kubernetes_resource(r)]
        if not k8s_resources:
            return False, "No Kubernetes resources found (missing apiVersion or kind)"
        
        return True, None
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: kubernetes_scanner.py <input_path>")
        print("  <input_path> - Path to Kubernetes YAML file or directory")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    if not os.path.exists(input_path):
        print(f"Error: Path '{input_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Run the scanner
        findings = run_scanner(input_path)
        
        # Count files scanned
        files_scanned = len(get_all_k8s_files(input_path))
        
        # Format report
        report = format_findings_report(findings, files_scanned)
        report["language"] = "kubernetes"
        
        # Output as JSON
        print(json.dumps(report, indent=2))
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
