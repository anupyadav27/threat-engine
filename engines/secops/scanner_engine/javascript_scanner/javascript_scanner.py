import sys
import re
import os
import json
import esprima

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

def load_rule_metadata(folder="javascript_docs"):
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

def get_all_js_files(scan_path):
    js_files = []
    if os.path.isfile(scan_path) and (scan_path.endswith(".js") or scan_path.endswith(".mjs") or scan_path.endswith(".jsx")):
        js_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file.endswith(".js") or file.endswith(".mjs") or file.endswith(".jsx"):
                    js_files.append(os.path.join(root, file))
    return js_files

def parse_js_file(file_path):
    """
    Parse JavaScript file using esprima to generate proper AST.
    Returns a structured AST tree with all nodes properly typed.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    try:
        # Try parsing as module first (for import/export), then fall back to script
        try:
            ast = esprima.parseModule(source_code, {'loc': True, 'range': True, 'tokens': True, 'comment': True})
        except Exception:
            # Fall back to script parsing for non-module files
            ast = esprima.parseScript(source_code, {'loc': True, 'range': True, 'tokens': True, 'comment': True})
        
        # Convert esprima AST to our internal format
        nodes = []
        
        def extract_nodes(node, parent_source=source_code):
            """Recursively extract nodes from esprima AST."""
            if node is None:
                return
            
            # Skip non-object nodes (primitives, booleans, etc.)
            if not hasattr(node, 'type'):
                return
            
            # Convert esprima node to dict while preserving structure
            node_dict = node.toDict() if hasattr(node, 'toDict') else {}
            
            # Ensure both type and node_type are set for compatibility
            node_type = node.type if hasattr(node, 'type') else 'Unknown'
            node_dict['type'] = node_type
            node_dict['node_type'] = node_type
            
            # Add source information
            node_dict['parent_source'] = parent_source
            
            # Add line number if available
            if hasattr(node, 'loc') and node.loc:
                node_dict['lineno'] = node.loc.start.line
            
            # Add range and source if available
            if hasattr(node, 'range') and node.range:
                node_dict['range'] = node.range
                # Extract actual source code for this node
                node_dict['source'] = source_code[node.range[0]:node.range[1]]
            else:
                # Fallback to full source
                node_dict['source'] = source_code
            
            # Add simplified attributes for backward compatibility
            if node.type == 'CallExpression':
                # Extract function name for legacy compatibility
                if hasattr(node, 'callee'):
                    if hasattr(node.callee, 'type'):
                        if node.callee.type == 'Identifier' and hasattr(node.callee, 'name'):
                            node_dict['name'] = node.callee.name
                        elif node.callee.type == 'MemberExpression':
                            # Handle cases like console.log
                            obj_name = ''
                            if hasattr(node.callee, 'object') and hasattr(node.callee.object, 'name'):
                                obj_name = node.callee.object.name
                            prop_name = ''
                            if hasattr(node.callee, 'property') and hasattr(node.callee.property, 'name'):
                                prop_name = node.callee.property.name
                            node_dict['name'] = f"{obj_name}.{prop_name}" if obj_name and prop_name else prop_name or obj_name
            
            elif node.type == 'TryStatement':
                node_dict['node_type'] = 'TryStatement'
            
            elif node.type == 'BinaryExpression' or node.type == 'LogicalExpression':
                node_dict['node_type'] = 'Expression'
                node_dict['operator'] = node.operator if hasattr(node, 'operator') else None
            
            elif node.type == 'AssignmentExpression':
                node_dict['node_type'] = 'Statement'
                node_dict['assignment_type'] = 'Assignment'
                node_dict['operator'] = node.operator if hasattr(node, 'operator') else '='
            
            elif node.type == 'ExpressionStatement':
                # For test assertions like expect().toBe()
                if hasattr(node, 'expression') and hasattr(node.expression, 'type'):
                    if node.expression.type == 'CallExpression':
                        callee_name = ''
                        if hasattr(node.expression, 'callee'):
                            if hasattr(node.expression.callee, 'name'):
                                callee_name = node.expression.callee.name
                            elif hasattr(node.expression.callee, 'object') and hasattr(node.expression.callee.object, 'name'):
                                callee_name = node.expression.callee.object.name
                        
                        if callee_name in ['expect', 'assert', 'should']:
                            node_dict['node_type'] = 'TestAssertion'
            
            nodes.append(node_dict)
            
            # Recursively process child nodes
            if hasattr(node, 'body') and node.body is not None:
                if isinstance(node.body, list):
                    for child in node.body:
                        if child is not None:
                            extract_nodes(child, parent_source)
                else:
                    extract_nodes(node.body, parent_source)
            
            if hasattr(node, 'consequent') and node.consequent is not None:
                extract_nodes(node.consequent, parent_source)
            
            if hasattr(node, 'alternate') and node.alternate is not None:
                extract_nodes(node.alternate, parent_source)
            
            if hasattr(node, 'declarations') and node.declarations is not None:
                for decl in node.declarations:
                    if decl is not None and hasattr(decl, 'init') and decl.init is not None:
                        extract_nodes(decl.init, parent_source)
            
            if hasattr(node, 'expression') and node.expression is not None:
                extract_nodes(node.expression, parent_source)
            
            if hasattr(node, 'test') and node.test is not None:
                extract_nodes(node.test, parent_source)
            
            if hasattr(node, 'block') and node.block is not None:
                extract_nodes(node.block, parent_source)
            
            if hasattr(node, 'handler') and node.handler is not None:
                extract_nodes(node.handler, parent_source)
            
            if hasattr(node, 'finalizer') and node.finalizer is not None:
                extract_nodes(node.finalizer, parent_source)
            
            # Handle NewExpression arguments (e.g., new https.Agent({...}))
            if hasattr(node, 'arguments') and node.arguments is not None:
                for arg in node.arguments:
                    if arg is not None:
                        extract_nodes(arg, parent_source)
            
            # Handle CallExpression arguments
            if hasattr(node, 'callee') and node.callee is not None:
                extract_nodes(node.callee, parent_source)
        
        # Extract all nodes from AST
        if hasattr(ast, 'body'):
            for node in ast.body:
                extract_nodes(node, source_code)
        
        return {
            'node_type': 'CompilationUnit',
            'filename': file_path,
            'source': source_code,
            'children': nodes,
            'ast': ast  # Keep original esprima AST for advanced analysis
        }
    
    except esprima.Error as e:
        # Fallback to basic regex parsing if esprima fails
        print(f"Warning: esprima parsing failed for {file_path}: {str(e)}", file=sys.stderr)
        print(f"Falling back to regex-based parsing", file=sys.stderr)
        return parse_js_file_fallback(file_path)

def parse_js_file_fallback(file_path):
    """
    Fallback regex-based parser for when esprima fails.
    This is the old implementation kept as a backup.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    var_assignments = {}

    # Extract assignment statements from all lines
    for idx, line in enumerate(lines):
        stmt_strip = line.strip()
        if stmt_strip and not stmt_strip.startswith('//') and not stmt_strip.startswith('/*') and stmt_strip not in ['{', '}']:
            # Extract variable declarations (let, const, var)
            if re.match(r'^(let|const|var)\s+\w+', stmt_strip):
                stmt_type = 'VariableDeclaration'
                nodes.append({
                    'node_type': 'Statement',
                    'type': stmt_type,
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_function': None
                })
            # Extract normal assignments
            elif '=' in stmt_strip and not stmt_strip.startswith('if') and not stmt_strip.startswith('for') and not stmt_strip.startswith('while'):
                stmt_type = 'Assignment'
                nodes.append({
                    'node_type': 'Statement',
                    'type': stmt_type,
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_function': None
                })
            # Extract chained assignments: a = b = c;
            if re.search(r'(\w+)\s*=\s*(\w+)\s*=\s*[^;]+;?', stmt_strip):
                nodes.append({
                    'node_type': 'Statement',
                    'type': 'Assignment',
                    'lineno': idx + 1,
                    'source': stmt_strip,
                    'position': idx,
                    'parent_source': '\n'.join(lines),
                    'parent_function': None
                })
    # Extract function declarations and expressions
    for midx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Function declarations: function name() {}
        if line_strip.startswith('function ') and '{' in line_strip:
            func_lines = []
            brace_count = 0
            start_found = False
            block_start = midx - 1
            for i in range(block_start, len(lines)):
                current_line = lines[i]
                func_lines.append(current_line)
                for char in current_line:
                    if char == '{':
                        brace_count += 1
                        start_found = True
                    elif char == '}':
                        brace_count -= 1
                if start_found and brace_count == 0:
                    break
            # Extract function name
            func_name_match = re.search(r'function\s+(\w+)', line_strip)
            func_name = func_name_match.group(1) if func_name_match else 'anonymous'
            
            nodes.append({
                'node_type': 'FunctionDeclaration',
                'name': func_name,
                'lineno': midx,
                'source': '\n'.join(func_lines),
                'declaration': line_strip
            })
        # Arrow functions: const func = () => {}
        elif '=>' in line_strip and (line_strip.startswith('const ') or line_strip.startswith('let ') or line_strip.startswith('var ')):
            nodes.append({
                'node_type': 'ArrowFunction',
                'lineno': midx,
                'source': line_strip,
                'declaration': line_strip
            })
    """
    Enhanced parser to extract for-loops, classes, functions, and method invocations from JavaScript source.
    Returns a root node containing all extracted nodes and the source.
    """
    
    # Extract for-loops (ForStatement nodes) and try-catch blocks (TryStatement nodes)
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Track variable assignments to empty arrays/objects
        match = re.match(r'.*\b(\w+)\s*=\s*\[\s*\].*', line_strip)
        if match:
            var_assignments[match.group(1)] = 'emptyArray'
        match = re.match(r'.*\b(\w+)\s*=\s*\{\s*\}.*', line_strip)
        if match:
            var_assignments[match.group(1)] = 'emptyObject'
        
        # ForStatement extraction (for, for...in, for...of)
        if (line_strip.startswith('for (') or line_strip.startswith('for(') or 
            'for (' in line_strip):
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

    # Extract decorators (if using TypeScript or experimental JS)
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        if line_strip.startswith('@'):
            parts = line_strip.split()
            decorator = parts[0][1:] if parts else None
            if decorator:
                nodes.append({
                    'node_type': 'Decorator',
                    'id': decorator,
                    'lineno': idx,
                    'source': line_strip
                })

    # Extract classes, functions, method invocations, expressions, and test assertions
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Extract Jest/Mocha/Chai assertion calls
        if ('expect(' in line_strip or 'assert(' in line_strip or 'should.' in line_strip):
            nodes.append({
                'node_type': 'TestAssertion',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        # Extract class declarations
        if 'class ' in line_strip and not line_strip.startswith('//') and not line_strip.startswith('/*'):
            class_match = re.search(r'class\s+(\w+)', line_strip)
            if class_match:
                class_name = class_match.group(1)
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
                nodes.append({
                    'node_type': 'Class',
                    'name': class_name,
                    'lineno': idx,
                    'source': class_source,
                    'declaration': line_strip
                })
        # Extract method/function invocation (any function call, e.g., console.log(...))
        elif '(' in line_strip and ')' in line_strip and not line_strip.startswith('//') and not line_strip.startswith('/*'):
            # Try to extract function name before '('
            invocation = line_strip
            function_name = None
            before_paren = invocation.split('(')[0].strip()
            # If it's like obj.method(...), get method
            if '.' in before_paren:
                function_name = before_paren.split('.')[-1]
            else:
                # Remove variable declarations if present
                if any(keyword in before_paren for keyword in ['const', 'let', 'var']):
                    function_name = before_paren.split('=')[-1].strip()
                else:
                    function_name = before_paren
            # Extract arguments inside (...)
            args_str = invocation.split('(',1)[-1].rsplit(')',1)[0]
            arguments = [a.strip() for a in args_str.split(',') if a.strip()]
            nodes.append({
                'node_type': 'CallExpression',
                'name': function_name,
                'lineno': idx,
                'source': invocation,
                'parent_source': source_code,
                'arguments': arguments
            })
        # Extract Expression nodes for ==, !=, ===, !==
        elif (('===' in line_strip or '!==' in line_strip or '==' in line_strip or '!=' in line_strip) and not line_strip.startswith('//') and not line_strip.startswith('/*')):
            nodes.append({
                'node_type': 'Expression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        # Function expression and method extraction
        elif ('function' in line_strip or '=>' in line_strip) and '(' in line_strip:
            # Function declarations already handled above
            if not line_strip.startswith('function '):
                # Method in class or function expression
                method_match = re.search(r'(\w+)\s*\(', line_strip)
                if method_match:
                    method_name = method_match.group(1)
                elif '=>' in line_strip:
                    # Arrow function
                    method_name = 'anonymous'
                else:
                    method_name = 'unknown'
                
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
                nodes.append({
                    'node_type': 'FunctionExpression',
                    'name': method_name,
                    'lineno': idx,
                    'source': method_source
                })

    # Return a root node containing all extracted nodes and the source
    return {
        'node_type': 'CompilationUnit',
        'filename': file_path,
        'source': source_code,
        'children': nodes
    }

def run_scanner(scan_path):
    rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    js_files = get_all_js_files(scan_path)
    all_findings = []
    for js_file in js_files:
        ast_tree = parse_js_file(js_file)
        for rule in rules:
            findings = generic_rule_engine.run_rule(rule, ast_tree, js_file)
            if findings:
                for finding in findings:
                    finding['file'] = js_file
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
    Scans a single JavaScript file or directory and returns findings.
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
        "javascript": [".js", ".mjs", ".jsx"],
        "typescript": [".ts", ".tsx"],
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

def parse_java_file(file_path):
    """
    Basic Java file parser - extracts classes, methods, and basic statements.
    Returns a structure similar to the JavaScript parser.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    
    # Extract classes, methods, and basic constructs
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip comments and empty lines
        if not line_strip or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
            
        # Extract class declarations
        if line_strip.startswith('public class ') or line_strip.startswith('class '):
            class_match = re.search(r'class\s+(\w+)', line_strip)
            if class_match:
                class_name = class_match.group(1)
                nodes.append({
                    'node_type': 'ClassDeclaration',
                    'name': class_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
        
        # Extract method declarations
        elif ('public ' in line_strip or 'private ' in line_strip or 'protected ' in line_strip) and '(' in line_strip and ')' in line_strip:
            method_match = re.search(r'(\w+)\s*\(', line_strip)
            if method_match:
                method_name = method_match.group(1)
                nodes.append({
                    'node_type': 'MethodDeclaration',
                    'name': method_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
        
        # Extract for loops
        elif line_strip.startswith('for ') or line_strip.startswith('for('):
            nodes.append({
                'node_type': 'ForStatement',
                'lineno': idx,
                'source': line_strip
            })
        
        # Extract method calls
        elif '(' in line_strip and ')' in line_strip and '=' not in line_strip:
            # Try to extract method name before '('
            before_paren = line_strip.split('(')[0].strip()
            if '.' in before_paren:
                method_name = before_paren.split('.')[-1]
            else:
                method_name = before_paren.split()[-1] if before_paren else 'unknown'
            
            nodes.append({
                'node_type': 'CallExpression',
                'name': method_name,
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
    
    return {
        'node_type': 'CompilationUnit',
        'filename': file_path,
        'source': source_code,
        'children': nodes
    }

def parse_file_to_ast(file_path: str, language: str) -> Dict:
    """
    Parse a file to AST based on language.
    Currently supports JavaScript and Java.
    """
    if language.lower() == "javascript" or language.lower() == "js":
        return parse_js_file(file_path)
    elif language.lower() == "java":
        return parse_java_file(file_path)
    else:
        # Placeholder for other languages
        return {"node_type": "Module", "body": []}

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: scanner.py <input_path> [language]")
        sys.exit(1)
        
    input_path = sys.argv[1]
    language = sys.argv[2].lower() if len(sys.argv) > 2 else "javascript"
    
    try:
        # Use the scanner function that loads from js_docs by default
        findings = run_scanner(input_path)
        
        # Count actual files scanned
        if language == "javascript" or language == "js":
            files_scanned = len(get_all_js_files(input_path))
        else:
            files_scanned = len(get_all_files(input_path, language))
            
        result = {
            "language": language,
            "files_scanned": files_scanned,
            "findings": findings
        }
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)