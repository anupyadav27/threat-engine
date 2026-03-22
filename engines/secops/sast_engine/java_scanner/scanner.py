import sys
import re
import os
import json

# Add parent directory to path for relative imports when run from different locations
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generic_rule_engine

from typing import Dict, List, Optional, Set, Any  # Ensure typing imports are present
from dataclasses import dataclass

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

def load_rule_metadata(folder="java_docs"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "rule_id" in data:
                        rules_meta[data["rule_id"]] = data
            except Exception:
                continue
    return rules_meta

def get_all_java_files(scan_path):
    java_files = []
    if os.path.isfile(scan_path) and scan_path.endswith(".java"):
        java_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file.endswith(".java"):
                    java_files.append(os.path.join(root, file))
    return java_files

def parse_java_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    var_assignments = {}

    # Extract assignment statements from all lines (not just synchronized blocks)
    for idx, line in enumerate(lines):
        stmt_strip = line.strip()
        if stmt_strip and not stmt_strip.startswith('//') and stmt_strip not in ['{', '}']:
            # Extract normal assignments
            if '=' in stmt_strip and not stmt_strip.startswith('if') and not stmt_strip.startswith('for') and not stmt_strip.startswith('while'):
                stmt_type = 'Assignment'
                nodes.append({
                    'node_type': 'Statement',
                    'type': stmt_type,
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_method': None,
                    'parent_sync_lineno': None
                })
            # Extract assignments within sub-expressions (chained, parentheses, compound)
            # Chained assignment: int j, i = j = 0;
            if re.search(r'(\w+)\s*=\s*(\w+)\s*=\s*[^;]+;', stmt_strip):
                nodes.append({
                    'node_type': 'Statement',
                    'type': 'Assignment',
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_method': None,
                    'parent_sync_lineno': None
                })
            # Compound assignment in parentheses: int k = (j += 1);
            if re.search(r'\(\s*\w+\s*\+=\s*[^)]+\)', stmt_strip):
                nodes.append({
                    'node_type': 'Statement',
                    'type': 'Assignment',
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_method': None,
                    'parent_sync_lineno': None
                })
            # Assignment in parentheses: result = (bresult = ...);
            if re.search(r'(\w+)\s*=\s*\(\s*\w+\s*=\s*[^)]+\)', stmt_strip):
                nodes.append({
                    'node_type': 'Statement',
                    'type': 'Assignment',
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_method': None,
                    'parent_sync_lineno': None
                })
    # ...existing code...
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    var_assignments = {}

    # Synchronized block statement extraction FIRST
    for midx, line in enumerate(lines, 1):
        line_strip = line.strip()
        if 'synchronized' in line_strip and '{' in line_strip:
            block_lines = []
            brace_count = 0
            start_found = False
            block_start = midx - 1
            for i in range(block_start, len(lines)):
                current_line = lines[i]
                block_lines.append(current_line)
                for char in current_line:
                    if char == '{':
                        brace_count += 1
                        start_found = True
                    elif char == '}':
                        brace_count -= 1
                if start_found and brace_count == 0:
                    block_end = i
                    break
            # Find parent method declaration above synchronized block
            parent_method = None
            for j in range(block_start, 0, -1):
                method_line = lines[j].strip()
                if (method_line.startswith('public') or method_line.startswith('private') or method_line.startswith('protected')) and '(' in method_line and '{' in method_line:
                    parent_method = method_line
                    break
            # Extract statements within block, skipping braces and comments
            for sidx, stmt in enumerate(block_lines):
                stmt_strip = stmt.strip()
                if stmt_strip and not stmt_strip.startswith('//') and stmt_strip not in ['{', '}'] and not stmt_strip.startswith('synchronized'):
                    # Determine assignment type
                    if '=' in stmt_strip and not stmt_strip.startswith('if') and not stmt_strip.startswith('for') and not stmt_strip.startswith('while'):
                        stmt_type = 'Assignment'
                    else:
                        stmt_type = 'Statement'
                    nodes.append({
                        'node_type': 'Statement',
                        'type': stmt_type,
                        'lineno': block_start + sidx + 1,
                        'source': stmt_strip,
                        'position': sidx,
                        'parent_source': '\n'.join(block_lines),
                        'parent_method': parent_method,
                        'parent_sync_lineno': block_start + 1
                    })
    """
    Enhanced parser to extract annotations, for-loops, classes, methods, and method invocations from Java source.
    Returns a root node containing all extracted nodes and the source.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    var_assignments = {}

    # Extract for-loops (ForStatement nodes) and try-catch blocks (TryStatement nodes)
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Track variable assignments to Collections.emptyList()
        match = re.match(r'.*\b(\w+)\s*=\s*Collections\.emptyList\s*\(\s*\).*', line_strip)
        if match:
            var_assignments[match.group(1)] = 'emptyList'
        # ForStatement extraction
        if line_strip.startswith('for (') or line_strip.startswith('for('):
            loop_source = line_strip + '\n'
            brace_count = 0
            start_found = False
            for i in range(idx, len(lines)):
                current_line = lines[i]
                loop_source += current_line + '\n'
                for char in current_line:
                    if char == '{':
                        brace_count += 1
                        start_found = True
                    elif char == '}':
                        brace_count -= 1
                if start_found and brace_count == 0:
                    break
            nodes.append({
                'node_type': 'ForStatement',
                'lineno': idx,
                'source': loop_source
            })
        # TryStatement extraction
        if line_strip.startswith('try') and '{' in line_strip:
            try_source = line_strip + '\n'
            brace_count = 0
            start_found = False
            for i in range(idx, len(lines)):
                current_line = lines[i]
                try_source += current_line + '\n'
                for char in current_line:
                    if char == '{':
                        brace_count += 1
                        start_found = True
                    elif char == '}':
                        brace_count -= 1
                if start_found and brace_count == 0:
                    break
            nodes.append({
                'node_type': 'TryStatement',
                'lineno': idx,
                'source': try_source
            })

    # Extract annotations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        if line_strip.startswith('@'):
            parts = line_strip.split()
            annotation = parts[0][1:] if parts else None
            if annotation:
                nodes.append({
                    'node_type': 'Annotation',
                    'id': annotation,
                    'lineno': idx,
                    'source': line_strip
                })

    # Extract classes, methods, method invocations, expressions, and AssertJ assertion calls
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Extract AssertJ assertion calls
        call_match = re.match(r'.*Assertions\.assertThat\s*\(\s*(\w+)\s*\)\s*\.\s*(allMatch|doesNotContain).*', line_strip)
        if call_match:
            nodes.append({
                'node_type': 'AssertJAssertion',
                'lineno': idx,
                'var': call_match.group(1),
                'method': call_match.group(2),
                'source': line_strip,
                'parent_source': source_code
            })
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Extract class declarations (including inner classes)
        if 'class ' in line_strip and not line_strip.startswith('//'):
            parts = line_strip.split()
            class_idx = -1
            for i, part in enumerate(parts):
                if part == 'class':
                    class_idx = i
                    break
            if class_idx >= 0 and class_idx + 1 < len(parts):
                class_name = parts[class_idx + 1].split('{')[0].split('(')[0].strip()
                class_source = ""
                brace_count = 0
                start_found = False
                for i in range(idx - 1, len(lines)):
                    current_line = lines[i]
                    class_source += current_line + "\n"
                    for char in current_line:
                        if char == '{':
                            brace_count += 1
                            start_found = True
                        elif char == '}':
                            brace_count -= 1
                    if start_found and brace_count == 0:
                        break
                modifiers = parts[:class_idx]
                nodes.append({
                    'node_type': 'Class',
                    'name': class_name,
                    'lineno': idx,
                    'source': class_source,
                    'declaration': line_strip,
                    'modifiers': modifiers
                })
                # Extract inner classes from class_source
                inner_lines = class_source.split('\n')
                for j, inner_line in enumerate(inner_lines, 1):
                    inner_strip = inner_line.strip()
                    if 'class ' in inner_strip and not inner_strip.startswith('//'):
                        inner_parts = inner_strip.split()
                        inner_class_idx = -1
                        for k, part in enumerate(inner_parts):
                            if part == 'class':
                                inner_class_idx = k
                                break
                        if inner_class_idx >= 0 and inner_class_idx + 1 < len(inner_parts):
                            inner_class_name = inner_parts[inner_class_idx + 1].split('{')[0].split('(')[0].strip()
                            inner_class_source = ""
                            inner_brace_count = 0
                            inner_start_found = False
                            for m in range(j - 1, len(inner_lines)):
                                current_inner_line = inner_lines[m]
                                inner_class_source += current_inner_line + "\n"
                                for char in current_inner_line:
                                    if char == '{':
                                        inner_brace_count += 1
                                        inner_start_found = True
                                    elif char == '}':
                                        inner_brace_count -= 1
                                if inner_start_found and inner_brace_count == 0:
                                    break
                            inner_modifiers = inner_parts[:inner_class_idx]
                            nodes.append({
                                'node_type': 'Class',
                                'name': inner_class_name,
                                'lineno': j,
                                'source': inner_class_source,
                                'declaration': inner_strip,
                                'modifiers': inner_modifiers,
                                'is_inner': True
                            })
        # Extract interface declarations
        if 'interface ' in line_strip and not line_strip.startswith('//'):
            parts = line_strip.split()
            interface_idx = -1
            for i, part in enumerate(parts):
                if part == 'interface':
                    interface_idx = i
                    break
            if interface_idx >= 0 and interface_idx + 1 < len(parts):
                interface_name = parts[interface_idx + 1].split('{')[0].split('(')[0].strip()
                interface_source = ""
                brace_count = 0
                start_found = False
                for i in range(idx - 1, len(lines)):
                    current_line = lines[i]
                    interface_source += current_line + "\n"
                    for char in current_line:
                        if char == '{':
                            brace_count += 1
                            start_found = True
                        elif char == '}':
                            brace_count -= 1
                    if start_found and brace_count == 0:
                        break
                modifiers = parts[:interface_idx]
                nodes.append({
                    'node_type': 'Interface',
                    'name': interface_name,
                    'lineno': idx,
                    'source': interface_source,
                    'declaration': line_strip,
                    'modifiers': modifiers
                })
        # Extract method invocation (any method call, e.g., logMessages(...))
        elif '(' in line_strip and ')' in line_strip and not line_strip.startswith('//'):
            # Try to extract method name before '('
            invocation = line_strip
            method_name = None
            before_paren = invocation.split('(')[0].strip()
            # If it's like obj.method(...), get method
            if '.' in before_paren:
                method_name = before_paren.split('.')[-1]
            else:
                method_name = before_paren
            # Extract arguments inside (...)
            args_str = invocation.split('(',1)[-1].rsplit(')',1)[0]
            arguments = [a.strip() for a in args_str.split(',') if a.strip()]
            # Extract annotation info if present (simple heuristic: look for @ in line)
            annotation = []
            if '@' in line_strip:
                annotation = re.findall(r'@\w+', line_strip)
            nodes.append({
                'node_type': 'MethodInvocation',
                'name': method_name,
                'lineno': idx,
                'source': invocation,
                'parent_source': source_code,
                'arguments': arguments,
                'annotation': annotation
            })
            # If .equals( is present, also extract as Expression node
            if '.equals(' in line_strip:
                nodes.append({
                    'node_type': 'Expression',
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': source_code
                })
            # If AssertJ allMatch or doesNotContain is present, extract as Expression node
            if ('assertThat' in line_strip and ('allMatch' in line_strip or 'doesNotContain' in line_strip)):
                nodes.append({
                    'node_type': 'Expression',
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': source_code
                })
        # Extract Expression nodes for ==, != (not .equals(, already handled above)
        elif (('==' in line_strip or '!=' in line_strip) and not line_strip.startswith('//')):
            nodes.append({
                'node_type': 'Expression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        # Simple method extraction
        elif ('public ' in line_strip or 'private ' in line_strip or 'protected ' in line_strip) and '(' in line_strip and ('{' in line_strip or idx < len(lines)):
            method_part = line_strip.split('(')[0]
            parts = method_part.split()
            if len(parts) >= 2:
                method_name = parts[-1]
                method_source = ""
                brace_count = 0
                start_found = False
                for i in range(idx - 1, len(lines)):
                    current_line = lines[i]
                    method_source += current_line + "\n"
                    for char in current_line:
                        if char == '{':
                            brace_count += 1
                            start_found = True
                        elif char == '}':
                            brace_count -= 1
                    if start_found and brace_count == 0:
                        break
                # Check if method is static
                is_static = 'static' in method_part
                nodes.append({
                    'node_type': 'Method',
                    'name': method_name,
                    'lineno': idx,
                    'source': method_source,
                    'is_static': is_static,
                    'modifiers': parts[:-1],
                    'full_declaration': line_strip
                })

    # Return a root node containing all extracted nodes and the source
    return {
        'node_type': 'CompilationUnit',
        'filename': file_path,
        'source': source_code,
        'children': nodes
    }

def run_scanner(scan_path):
    try:
        from database.rule_cache import rule_cache
        rules_meta = rule_cache.get_rules("java")
    except Exception:
        rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    java_files = get_all_java_files(scan_path)
    all_findings = []
    for java_file in java_files:
        ast_tree = parse_java_file(java_file)
        # DEBUG: Print Statement and MethodInvocation nodes and their source
        debug_nodes = []
        def collect_debug_nodes(node):
            if isinstance(node, dict):
                if node.get('node_type') in ['Statement', 'MethodInvocation']:
                    debug_nodes.append((node.get('node_type'), node.get('lineno'), node.get('source')))
                for v in node.values():
                    collect_debug_nodes(v)
            elif isinstance(node, list):
                for item in node:
                    collect_debug_nodes(item)
        collect_debug_nodes(ast_tree)
        import sys
        print(f"DEBUG: Statement/MethodInvocation nodes in {java_file}:", file=sys.stderr)
        for ntype, lineno, src in debug_nodes:
            print(f"  [{ntype}] Line {lineno}: {src}", file=sys.stderr)
        for rule in rules:
            findings = generic_rule_engine.run_rule(rule, ast_tree, java_file)
            if findings:
                for finding in findings:
                    finding['file'] = java_file
                    all_findings.append(finding)
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped

def run_scan(file_path):
    """
    Wrapper function for plugin compatibility.
    Scans a single Java file or directory and returns findings.
    This function is called by the scanner_plugin system.
    """
    findings = run_scanner(file_path)
    # Clean findings for API (remove 'file' key if present for consistency)
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict):
            # Create a copy to avoid modifying original
            cleaned_finding = finding.copy()
            # Keep file path but ensure it's clean
            cleaned_results.append(cleaned_finding)
        else:
            cleaned_results.append(finding)
    return cleaned_results

def clean_for_json(obj, depth=0, max_depth=10):
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

def load_rules(language: str) -> Dict[str, Dict]:
    """Load all rule JSON files for a given language."""
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

def load_metadata(language: str) -> Dict[str, Dict]:
    """Load all metadata JSON files for a given language."""
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
        "node_types": rule_json.get("node_types", []),
        "logic": metadata_json.get("logic", {}),
        "severity": rule_json.get("severity", "INFO"),
        "examples": metadata_json.get("examples", []),
        "recommendation": metadata_json.get("recommendation", ""),
        "impact": metadata_json.get("impact", "")
    }
    return merged

def get_language_extensions(language: str) -> List[str]:
    """Map programming languages to their file extensions."""
    extensions = {
        "python": [".py"],
        "java": [".java"],
        "terraform": [".tf", ".hcl"],
        # Add more languages as needed
    }
    return extensions.get(language, [])

def get_all_files(path: str, language: str) -> List[str]:
    """Recursively collect all files of the target language."""
    target_files = []
    extensions = get_language_extensions(language)
    
    if os.path.isfile(path):
        if any(path.endswith(ext) for ext in extensions):
            target_files.append(path)
    else:
        for root, _, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    target_files.append(os.path.join(root, file))
                    
    return target_files

def parse_file_to_ast(file_path: str, language: str) -> Dict:
    """
    Parser placeholder - will be replaced with actual implementation.
    Returns a minimal AST structure.
    """
    return {"node_type": "Module", "body": []}

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: scanner.py <input_path> <language>")
        sys.exit(1)
        
    input_path = sys.argv[1]
    language = sys.argv[2].lower()
    
    try:
        # Use the original working function that loads from java_docs
        findings = run_scanner(input_path)
        result = {
            "language": language,
            "files_scanned": 1,
            "findings": findings
        }
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)