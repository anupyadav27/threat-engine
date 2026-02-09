"""
C Language Scanner - Enhanced Version

A comprehensive scanner for C language that parses C source files into AST-like structures
and applies rules using the generic rule engine. Handles functions, variables, structs,
loops, and other C language constructs.
"""

import sys
import re
import os
import json
from . import c_generic_rule_engine
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
    property_path: List[str]

    def __hash__(self) -> int:
        """Enable finding deduplication based on core attributes."""
        return hash((self.rule_id, self.file, self.line, self.message))

def load_rule_metadata(folder="c_docs"):
    """Load rule metadata from JSON files in the specified folder."""
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

def get_all_c_files(scan_path):
    """Recursively collect all C source and header files."""
    c_files = []
    c_extensions = [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"]
    
    if os.path.isfile(scan_path) and any(scan_path.endswith(ext) for ext in c_extensions):
        c_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if any(file.endswith(ext) for ext in c_extensions):
                    c_files.append(os.path.join(root, file))
    return c_files

def parse_c_file(file_path):
    """
    Parse C file using regex-based analysis to extract language constructs.
    Returns a structured AST-like tree with all nodes properly categorized.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        source_code = f.read()
    
    # Remove comments first to avoid false positives
    source_code_no_comments = remove_c_comments(source_code)
    lines = source_code.splitlines()
    lines_no_comments = source_code_no_comments.splitlines()
    nodes = []
    
    # Extract preprocessor directives
    nodes.extend(extract_preprocessor_directives(lines))
    
    # Extract function declarations and definitions
    nodes.extend(extract_functions(source_code, lines))
    
    # Extract variable declarations
    nodes.extend(extract_variables(lines))
    
    # Extract struct/union/enum declarations
    nodes.extend(extract_structures(source_code, lines))
    
    # Extract for/while/do-while loops
    nodes.extend(extract_loops(lines))
    
    # Extract if/switch statements
    nodes.extend(extract_conditionals(lines))
    
    # Extract function calls
    nodes.extend(extract_function_calls(lines))
    
    # Extract expressions and assignments
    nodes.extend(extract_expressions(lines))
    
    # Extract pointer operations
    nodes.extend(extract_pointer_operations(lines))
    
    # Extract array operations
    nodes.extend(extract_array_operations(lines))
    
    return {
        'node_type': 'TranslationUnit',
        'filename': file_path,
        'source': source_code,
        'source_no_comments': source_code_no_comments,
        'children': nodes,
        'line_count': len(lines)
    }

def remove_c_comments(source_code):
    """Remove C-style comments (/* */ and //) from source code."""
    # Remove /* */ comments
    source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
    # Remove // comments
    source_code = re.sub(r'//.*', '', source_code)
    return source_code

def extract_preprocessor_directives(lines):
    """Extract #include, #define, #ifdef, etc."""
    nodes = []
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        if line_strip.startswith('#'):
            directive_match = re.match(r'#(\w+)', line_strip)
            directive_name = directive_match.group(1) if directive_match else 'unknown'
            
            nodes.append({
                'node_type': 'PreprocessorDirective',
                'directive': directive_name,
                'lineno': idx,
                'source': line_strip,
                'full_line': line
            })
    return nodes

def extract_functions(source_code, lines):
    """Extract function declarations and definitions."""
    nodes = []
    
    # Pattern to match function declarations/definitions
    # Handles return types, function names, parameters
    # More restrictive pattern to avoid false positives
    func_pattern = r'^\s*(?:static\s+|extern\s+|inline\s+)*([a-zA-Z_][a-zA-Z0-9_]*\s*\*?\s*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*[{;]'
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives and comments
        if line_strip.startswith('#') or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
            
        match = re.match(func_pattern, line)
        if match:
            return_type = match.group(1).strip()
            function_name = match.group(2).strip()
            
            # Determine if it's a declaration or definition
            is_definition = '{' in line
            
            # Extract function body if it's a definition
            function_body = ""
            if is_definition:
                brace_count = 0
                start_idx = idx - 1
                for i in range(start_idx, len(lines)):
                    current_line = lines[i]
                    function_body += current_line + '\n'
                    for char in current_line:
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                    if brace_count == 1 and '{' in current_line:
                        continue
                    elif brace_count == 0 and '}' in current_line:
                        break
            
            nodes.append({
                'node_type': 'FunctionDefinition' if is_definition else 'FunctionDeclaration',
                'name': function_name,
                'return_type': return_type,
                'lineno': idx,
                'source': function_body if is_definition else line_strip,
                'declaration': line_strip,
                'is_definition': is_definition
            })
    
    return nodes

def extract_variables(lines):
    """Extract variable declarations."""
    nodes = []
    
    # Common C data types
    c_types = [
        'int', 'char', 'float', 'double', 'void', 'short', 'long',
        'unsigned', 'signed', 'const', 'volatile', 'static', 'extern',
        'struct', 'union', 'enum', 'typedef', 'size_t', 'FILE'
    ]
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives, comments, and function calls
        if (line_strip.startswith('#') or line_strip.startswith('//') or 
            line_strip.startswith('/*') or '(' in line_strip and ')' in line_strip):
            continue
        
        # Look for variable declarations
        for c_type in c_types:
            pattern = rf'\b{c_type}\b.*?([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;,\[]'
            matches = re.finditer(pattern, line_strip)
            for match in matches:
                var_name = match.group(1)
                # Skip if it looks like a function (has parentheses)
                if '(' not in line_strip or line_strip.find('(') > line_strip.find(var_name):
                    nodes.append({
                        'node_type': 'VariableDeclaration',
                        'name': var_name,
                        'type': c_type,
                        'lineno': idx,
                        'source': line_strip,
                        'declaration': line_strip
                    })
    
    return nodes

def extract_structures(source_code, lines):
    """Extract struct, union, and enum declarations."""
    nodes = []
    
    keywords = ['struct', 'union', 'enum']
    
    for keyword in keywords:
        pattern = rf'\b{keyword}\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for idx, line in enumerate(lines, 1):
            line_strip = line.strip()
            if keyword in line_strip:
                match = re.search(pattern, line_strip)
                if match:
                    struct_name = match.group(1)
                    
                    # Extract the full structure if it has a body
                    structure_body = ""
                    if '{' in line_strip:
                        brace_count = 0
                        start_idx = idx - 1
                        for i in range(start_idx, len(lines)):
                            current_line = lines[i]
                            structure_body += current_line + '\n'
                            for char in current_line:
                                if char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                            if brace_count == 0 and '}' in current_line:
                                break
                    
                    nodes.append({
                        'node_type': f'{keyword.capitalize()}Declaration',
                        'name': struct_name,
                        'lineno': idx,
                        'source': structure_body if structure_body else line_strip,
                        'declaration': line_strip,
                        'keyword': keyword
                    })
    
    return nodes

def extract_loops(lines):
    """Extract for, while, and do-while loops."""
    nodes = []
    
    loop_keywords = ['for', 'while', 'do']
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        for keyword in loop_keywords:
            if line_strip.startswith(f'{keyword} ') or line_strip.startswith(f'{keyword}('):
                # Extract loop body
                loop_body = ""
                if '{' in line_strip:
                    brace_count = 0
                    start_idx = idx - 1
                    for i in range(start_idx, len(lines)):
                        current_line = lines[i]
                        loop_body += current_line + '\n'
                        for char in current_line:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                        if brace_count == 0 and '}' in current_line:
                            break
                else:
                    # Single statement loop
                    loop_body = line_strip
                
                nodes.append({
                    'node_type': f'{keyword.capitalize()}Statement',
                    'keyword': keyword,
                    'lineno': idx,
                    'source': loop_body,
                    'declaration': line_strip
                })
                break
    
    return nodes

def extract_conditionals(lines):
    """Extract if, else if, else, and switch statements."""
    nodes = []
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # If statements
        if line_strip.startswith('if ') or line_strip.startswith('if('):
            nodes.append({
                'node_type': 'IfStatement',
                'lineno': idx,
                'source': line_strip,
                'declaration': line_strip
            })
        
        # Else if statements
        elif line_strip.startswith('else if ') or 'else if(' in line_strip:
            nodes.append({
                'node_type': 'ElseIfStatement',
                'lineno': idx,
                'source': line_strip,
                'declaration': line_strip
            })
        
        # Else statements
        elif line_strip.startswith('else') and 'if' not in line_strip:
            nodes.append({
                'node_type': 'ElseStatement',
                'lineno': idx,
                'source': line_strip,
                'declaration': line_strip
            })
        
        # Switch statements
        elif line_strip.startswith('switch ') or line_strip.startswith('switch('):
            nodes.append({
                'node_type': 'SwitchStatement',
                'lineno': idx,
                'source': line_strip,
                'declaration': line_strip
            })
        
        # Case statements
        elif line_strip.startswith('case ') and ':' in line_strip:
            nodes.append({
                'node_type': 'CaseStatement',
                'lineno': idx,
                'source': line_strip,
                'declaration': line_strip
            })
    
    return nodes

def extract_function_calls(lines):
    """Extract function calls."""
    nodes = []
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives, comments, and function declarations
        if (line_strip.startswith('#') or line_strip.startswith('//') or 
            line_strip.startswith('/*') or line_strip.startswith('int ') or
            line_strip.startswith('void ') or line_strip.startswith('char ') or
            line_strip.startswith('float ') or line_strip.startswith('double ')):
            continue
        
        # Look for function calls (identifier followed by parentheses)
        func_call_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.finditer(func_call_pattern, line_strip)
        
        for match in matches:
            function_name = match.group(1)
            
            # Skip common keywords and control structures
            skip_keywords = ['if', 'while', 'for', 'switch', 'sizeof', 'return']
            if function_name not in skip_keywords:
                nodes.append({
                    'node_type': 'CallExpression',
                    'name': function_name,
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': line_strip
                })
    
    return nodes

def extract_expressions(lines):
    """Extract expressions and assignments."""
    nodes = []
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives and comments
        if line_strip.startswith('#') or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
        
        # Assignment expressions
        if '=' in line_strip and not any(op in line_strip for op in ['==', '!=', '<=', '>=']):
            nodes.append({
                'node_type': 'AssignmentExpression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': line_strip
            })
        
        # Comparison expressions
        elif any(op in line_strip for op in ['==', '!=', '<', '>', '<=', '>=']):
            nodes.append({
                'node_type': 'BinaryExpression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': line_strip
            })
        
        # Arithmetic expressions (including those in assignments and returns)
        if any(op in line_strip for op in ['+', '-', '*', '/', '%']):
            nodes.append({
                'node_type': 'ArithmeticExpression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': line_strip
            })
    
    return nodes

def extract_pointer_operations(lines):
    """Extract pointer dereference and address-of operations."""
    nodes = []
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives and comments
        if line_strip.startswith('#') or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
        
        # Pointer dereference
        if '*' in line_strip and 'int *' not in line_strip and 'char *' not in line_strip:
            # Check if it's actually a dereference, not a declaration
            if re.search(r'\*\s*[a-zA-Z_][a-zA-Z0-9_]*', line_strip):
                nodes.append({
                    'node_type': 'PointerDereference',
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': line_strip
                })
        
        # Address-of operation
        if '&' in line_strip and '&&' not in line_strip:
            if re.search(r'&\s*[a-zA-Z_][a-zA-Z0-9_]*', line_strip):
                nodes.append({
                    'node_type': 'AddressOf',
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': line_strip
                })
    
    return nodes

def extract_array_operations(lines):
    """Extract array subscript operations."""
    nodes = []
    
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip preprocessor directives and comments
        if line_strip.startswith('#') or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
        
        # Array subscript operations
        if '[' in line_strip and ']' in line_strip:
            array_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\['
            matches = re.finditer(array_pattern, line_strip)
            
            for match in matches:
                array_name = match.group(1)
                nodes.append({
                    'node_type': 'ArraySubscript',
                    'name': array_name,
                    'lineno': idx,
                    'source': line_strip,
                    'parent_source': line_strip
                })
    
    return nodes

def run_scanner(scan_path):
    """Main scanner function that processes all C files and applies rules."""
    rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    c_files = get_all_c_files(scan_path)
    all_findings = []
    
    for c_file in c_files:
        try:
            ast_tree = parse_c_file(c_file)
            
            for rule in rules:
                findings = c_generic_rule_engine.run_rule(rule, ast_tree, c_file)
                if findings:
                    for finding in findings:
                        finding['file'] = c_file
                        all_findings.append(finding)
        except Exception as e:
            print(f"Error processing {c_file}: {str(e)}", file=sys.stderr)
            continue
    
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    return deduped

# API entry point for plugin system
def run_scan(file_path):
    """Scan a single C file and return findings as a list of dicts."""
    findings = run_scanner(file_path)
    # Clean findings for API
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict) and 'file' in finding:
            del finding['file']
        cleaned_results.append(finding)
    return cleaned_results

def clean_for_json(obj, depth=0, max_depth=10):
    """Clean object for JSON serialization."""
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
    if len(sys.argv) < 2:
        print("Usage: c_scanner.py <input_path>")
        sys.exit(1)
        
    input_path = sys.argv[1]
    
    try:
        findings = run_scanner(input_path)
        
        # Count actual files scanned
        files_scanned = len(get_all_c_files(input_path))
            
        result = {
            "language": "c",
            "files_scanned": files_scanned,
            "findings": findings
        }
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)