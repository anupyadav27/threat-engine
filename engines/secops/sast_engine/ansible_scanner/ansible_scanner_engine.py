"""
Ansible Scanner Engine - Complete Pipeline
Input Code → YAML Parser → Ansible AST → Apply Rules from Metadata → Findings

This follows SonarSource's approach:
1. Read Ansible YAML files
2. Parse YAML into generic tree structure
3. Build Ansible Semantic Model (Play, Task, Module nodes)
4. Apply rules from metadata files
5. Return violations/findings
"""

import sys
import re
import os
import json
from ansible_scanner import ansible_generic_rule
from ansible_scanner import ansible_ast_builder
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

# Try to import advanced YAML parsers (fallback to basic yaml if not available)
try:
    from ruamel.yaml import YAML
    HAS_RUAMEL = True
except ImportError:
    import yaml
    HAS_RUAMEL = False
    print("Warning: ruamel.yaml not found. Install for better accuracy: pip install ruamel.yaml", file=sys.stderr)


@dataclass
class Finding:
    """Represents a single rule violation finding."""
    rule_id: str
    message: str
    file: str
    line: Optional[int]
    severity: str
    property_path: List[str]

    def __hash__(self) -> int:
        """Enable finding deduplication based on core attributes."""
        return hash((self.rule_id, self.file, self.line, self.message))


def load_rule_metadata(folder="ansible_docs"):
    """
    Load all rule metadata JSON files from the specified folder.
    Each file should contain rule_id and logic for checking.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        print(f"Warning: Metadata folder '{folder}' not found in {script_dir}.", file=sys.stderr)
        return {}
    
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
                print(f"Warning: Failed to load rule {filename}: {e}", file=sys.stderr)
                continue
    
    return rules_meta


def get_all_ansible_files(scan_path):
    """
    Collect all Ansible-related files including playbooks, roles, and task files.
    Looks for .yml and .yaml files in typical Ansible directory structures.
    """
    ansible_files = []
    ansible_extensions = ['.yml', '.yaml']
    
    # Common Ansible file patterns
    ansible_patterns = [
        'playbook', 'site.yml', 'site.yaml', 'main.yml', 'main.yaml',
        'tasks', 'handlers', 'vars', 'defaults', 'meta'
    ]
    
    if os.path.isfile(scan_path):
        if any(scan_path.endswith(ext) for ext in ansible_extensions):
            ansible_files.append(scan_path)
    else:
        for root, dirs, files in os.walk(scan_path):
            # Check if we're in an Ansible role directory structure
            is_ansible_dir = any(pattern in root.lower() for pattern in ansible_patterns)
            
            for file in files:
                if any(file.endswith(ext) for ext in ansible_extensions):
                    file_path = os.path.join(root, file)
                    # Include if it's in an Ansible directory or matches Ansible naming
                    if is_ansible_dir or any(pattern in file.lower() for pattern in ansible_patterns):
                        ansible_files.append(file_path)
                    # Also include if the file contains Ansible-specific content
                    elif _is_ansible_file(file_path):
                        ansible_files.append(file_path)
    
    return ansible_files


def _is_ansible_file(file_path):
    """
    Check if a YAML file is likely an Ansible file by inspecting its content.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(500)  # Read first 500 chars
            # Look for Ansible-specific keywords
            ansible_keywords = ['hosts:', 'tasks:', 'roles:', 'handlers:', 'vars:', 'become:', 'playbook']
            return any(keyword in content for keyword in ansible_keywords)
    except Exception:
        return False


def parse_ansible_file(file_path):
    """
    Parse Ansible YAML file using the proper AST builder.
    
    PIPELINE:
    1. Read YAML file
    2. Parse YAML → Generic YAML tree structure
    3. Build Ansible Semantic Model → Ansible-specific AST (Play, Task, Module nodes)
    4. Convert to generic format → Compatible with rule engine
    
    Returns a tuple: (ast_tree, parse_error)
    - ast_tree: structured AST tree with all nodes properly typed
    - parse_error: error message if parsing failed, None otherwise
    """
    try:
        # Use the dedicated Ansible AST builder (implements SonarSource approach)
        ast_tree = ansible_ast_builder.parse_ansible_to_generic_ast(file_path)
        return ast_tree, None
    except Exception as e:
        error_msg = str(e)
        print(f"Error parsing {file_path}: {error_msg}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        # Fallback to basic parsing with error marker
        fallback_ast = parse_ansible_file_fallback(file_path)
        # Mark the AST with parse error so the rule can detect it
        fallback_ast['parse_error'] = error_msg
        fallback_ast['parsing_failed'] = True
        return fallback_ast, error_msg


def parse_ansible_file_fallback(file_path):
    """
    Fallback regex-based parser for when YAML parsing fails.
    Extracts basic structure from Ansible files using pattern matching.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    lines = source_code.splitlines()
    nodes = []
    
    # Extract plays, tasks, and other constructs using regex
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip comments and empty lines
        if not line_strip or line_strip.startswith('#'):
            continue
        
        # Extract plays (lines with 'hosts:')
        if line_strip.startswith('- hosts:') or line_strip.startswith('hosts:'):
            nodes.append({
                'node_type': 'play',
                'type': 'play',
                'lineno': idx,
                '__line__': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract tasks (lines with '- name:' or module names)
        elif line_strip.startswith('- name:'):
            task_name = line_strip.replace('- name:', '').strip()
            nodes.append({
                'node_type': 'task',
                'type': 'task',
                'name': task_name,
                'lineno': idx,
                '__line__': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract become directives
        elif 'become:' in line_strip:
            nodes.append({
                'node_type': 'become',
                'type': 'become',
                'lineno': idx,
                '__line__': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract module calls (common modules)
        elif any(module in line_strip for module in ['docker_container:', 'shell:', 'command:', 'copy:', 'file:']):
            for module in ['docker_container', 'shell', 'command', 'copy', 'file']:
                if f'{module}:' in line_strip:
                    nodes.append({
                        'node_type': module,
                        'type': module,
                        'module': module,
                        'lineno': idx,
                        '__line__': idx,
                        'source': line_strip,
                        'parent_source': source_code
                    })
                    break
    
    return {
        'node_type': 'CompilationUnit',
        'filename': file_path,
        'source': source_code,
        'children': nodes
    }


def run_scanner(scan_path):
    """
    Main scanner function - complete pipeline:
    1. Load rules from metadata files
    2. Find all Ansible files in scan_path
    3. For each file:
       - Parse to AST
       - Apply all applicable rules
       - Collect findings
    4. Deduplicate and return findings
    """
    # Step 1: Load rules
    try:
        from database.rule_cache import rule_cache
        rules_meta = rule_cache.get_rules("ansible")
    except Exception:
        rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    print(f"Loaded {len(rules)} active rules", file=sys.stderr)
    
    # Step 2: Find all Ansible files
    ansible_files = get_all_ansible_files(scan_path)
    print(f"Found {len(ansible_files)} Ansible files to scan", file=sys.stderr)
    
    all_findings = []
    
    # Step 3: Scan each file
    for ansible_file in ansible_files:
        print(f"Scanning: {ansible_file}", file=sys.stderr)
        
        # Parse file to AST
        ast_tree, parse_error = parse_ansible_file(ansible_file)
        
        # If parsing failed, create a parsing failure violation
        if parse_error:
            all_findings.append({
                'rule_id': 'ansible_parsing_failure',
                'message': f'Ansible parsing failure: {parse_error}',
                'file': ansible_file,
                'line': 0,
                'severity': 'Major',
                'status': 'violation'
            })
        
        # Apply each rule to the AST
        for rule in rules:
            try:
                findings = ansible_generic_rule.run_rule(rule, ast_tree, ansible_file)
                if findings:
                    for finding in findings:
                        finding['file'] = ansible_file
                        all_findings.append(finding)
            except Exception as e:
                print(f"Error applying rule {rule.get('rule_id', 'unknown')} to {ansible_file}: {e}", file=sys.stderr)
                continue
    
    # Step 4: Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    print(f"Found {len(deduped)} violations", file=sys.stderr)
    return deduped


def run_scan(file_path):
    """
    Compatibility wrapper for the scanner plugin system.
    Scans a single file or directory path and returns findings.
    """
    return run_scanner(file_path)


def clean_for_json(obj, depth=0, max_depth=10):
    """Clean objects for JSON serialization."""
    if depth > max_depth:
        return f"<Max depth {max_depth} reached>"
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if k != '__parent__'}
        return {key: clean_for_json(value, depth+1, max_depth) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [clean_for_json(item, depth+1, max_depth) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))


if __name__ == "__main__":
    """
    Command-line entry point for the scanner.
    
    Usage:
        python ansible_scanner.py <path_to_ansible_files>
        
    Example:
        python ansible_scanner.py ./playbooks
        python ansible_scanner.py site.yml
    """
    if len(sys.argv) < 2:
        print("Usage: ansible_scanner.py <input_path>")
        print("\nExample:")
        print("  python ansible_scanner.py ./playbooks")
        print("  python ansible_scanner.py site.yml")
        sys.exit(1)
        
    input_path = sys.argv[1]
    
    if not os.path.exists(input_path):
        print(f"Error: Path '{input_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Run the scanner
        findings = run_scanner(input_path)
        
        # Count files scanned
        files_scanned = len(get_all_ansible_files(input_path))
            
        # Prepare output
        result = {
            "language": "ansible",
            "files_scanned": files_scanned,
            "violations_found": len(findings),
            "findings": findings
        }
        
        # Print JSON output
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
