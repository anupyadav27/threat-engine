import sys
import re
import os
import json
from . import csharp_generic_rule_engine
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

def load_rule_metadata(folder="csharp_docs"):
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

def get_all_csharp_files(scan_path):
    cs_files = []
    if os.path.isfile(scan_path) and scan_path.endswith(".cs"):
        cs_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file.endswith(".cs"):
                    cs_files.append(os.path.join(root, file))
    return cs_files

def parse_csharp_file(file_path):
    """
    Parse C# file using regex-based approach to extract language constructs.
    Returns a structured AST-like tree with all relevant nodes.
    """
    try:
        # Try to use Microsoft.CodeAnalysis.CSharp if available
        return parse_csharp_with_roslyn(file_path)
    except (ImportError, Exception):
        # Fall back to regex-based parsing
        return parse_csharp_file_regex(file_path)

def parse_csharp_with_roslyn(file_path):
    """
    Parse C# file using Microsoft.CodeAnalysis.CSharp (Roslyn) for proper AST.
    This would require the .NET SDK and pythonnet package.
    """
    try:
        import clr  # type: ignore
        import sys
        
        # Add reference to Microsoft.CodeAnalysis
        clr.AddReference("Microsoft.CodeAnalysis")
        clr.AddReference("Microsoft.CodeAnalysis.CSharp")
        
        from Microsoft.CodeAnalysis.CSharp import CSharpSyntaxTree  # type: ignore
        from Microsoft.CodeAnalysis import SyntaxNode  # type: ignore
        
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Parse using Roslyn
        tree = CSharpSyntaxTree.ParseText(source_code)
        root = tree.GetRoot()
        
        nodes = []
        
        def extract_roslyn_nodes(node, parent_source=source_code):
            """Recursively extract nodes from Roslyn AST."""
            if node is None:
                return
            
            node_dict = {
                'type': str(node.GetType().Name),
                'node_type': str(node.GetType().Name),
                'parent_source': parent_source,
                'source': str(node.ToString()),
                'span': {
                    'start': node.Span.Start,
                    'end': node.Span.End
                }
            }
            
            # Add line number
            line_span = tree.GetLineSpan(node.Span)
            node_dict['lineno'] = line_span.StartLinePosition.Line + 1
            
            # Add specific properties for different node types
            node_type = str(node.GetType().Name)
            
            if 'ClassDeclaration' in node_type:
                node_dict['node_type'] = 'ClassDeclaration'
                # Try to get class name
                if hasattr(node, 'Identifier'):
                    node_dict['name'] = str(node.Identifier.ValueText)
            
            elif 'MethodDeclaration' in node_type:
                node_dict['node_type'] = 'MethodDeclaration'
                if hasattr(node, 'Identifier'):
                    node_dict['name'] = str(node.Identifier.ValueText)
            
            elif 'PropertyDeclaration' in node_type:
                node_dict['node_type'] = 'PropertyDeclaration'
                if hasattr(node, 'Identifier'):
                    node_dict['name'] = str(node.Identifier.ValueText)
            
            elif 'InvocationExpression' in node_type:
                node_dict['node_type'] = 'CallExpression'
                # Try to extract method name
                expression_str = str(node.Expression) if hasattr(node, 'Expression') else ''
                if '.' in expression_str:
                    node_dict['name'] = expression_str.split('.')[-1]
                else:
                    node_dict['name'] = expression_str
            
            elif 'ForStatement' in node_type or 'ForEachStatement' in node_type:
                node_dict['node_type'] = 'ForStatement'
            
            elif 'TryStatement' in node_type:
                node_dict['node_type'] = 'TryStatement'
            
            elif 'AssignmentExpression' in node_type:
                node_dict['node_type'] = 'Assignment'
                node_dict['assignment_type'] = 'Assignment'
            
            nodes.append(node_dict)
            
            # Recursively process child nodes
            for child in node.ChildNodes():
                extract_roslyn_nodes(child, parent_source)
        
        # Extract all nodes from AST
        extract_roslyn_nodes(root, source_code)
        
        return {
            'node_type': 'CompilationUnit',
            'filename': file_path,
            'source': source_code,
            'children': nodes,
            'ast': root
        }
        
    except Exception as e:
        print(f"Warning: Roslyn parsing failed for {file_path}: {str(e)}", file=sys.stderr)
        print(f"Falling back to regex-based parsing", file=sys.stderr)
        return parse_csharp_file_regex(file_path)

def parse_csharp_file_regex(file_path):
    """
    Regex-based C# parser for extracting language constructs.
    This is the main implementation when Roslyn is not available.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    lines = source_code.splitlines()
    nodes = []
    
    # Track variable assignments and declarations
    var_assignments = {}
    
    # Extract using statements and namespace declarations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Skip comments and empty lines
        if not line_strip or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
            
        # Extract using statements
        if line_strip.startswith('using ') and line_strip.endswith(';'):
            nodes.append({
                'node_type': 'UsingDirective',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract namespace declarations
        elif line_strip.startswith('namespace '):
            namespace_match = re.search(r'namespace\s+([\w\.]+)', line_strip)
            if namespace_match:
                namespace_name = namespace_match.group(1)
                nodes.append({
                    'node_type': 'NamespaceDeclaration',
                    'name': namespace_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
    
    # Extract class declarations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Class declarations (public class, internal class, etc.)
        if re.search(r'\b(public|internal|private|protected)?\s*class\s+\w+', line_strip):
            class_match = re.search(r'class\s+(\w+)', line_strip)
            if class_match:
                class_name = class_match.group(1)
                
                # Check for attributes on lines before class declaration
                attribute_lines = []
                attr_idx = idx - 2  # Start from line before class declaration (0-indexed)
                while attr_idx >= 0:
                    prev_line = lines[attr_idx].strip()
                    if prev_line.startswith('[') and prev_line.endswith(']'):
                        attribute_lines.insert(0, lines[attr_idx])
                        attr_idx -= 1
                    elif prev_line == '' or prev_line.startswith('//'):
                        attr_idx -= 1  # Skip empty lines and comments
                    else:
                        break
                
                # Extract full class body
                class_source = ""
                # Include attribute lines first
                for attr_line in attribute_lines:
                    class_source += attr_line + "\n"
                
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
                    'node_type': 'ClassDeclaration',
                    'name': class_name,
                    'lineno': idx,
                    'source': class_source,
                    'declaration': line_strip,
                    'parent_source': source_code
                })
        
        # Interface declarations
        elif re.search(r'\b(public|internal)?\s*interface\s+\w+', line_strip):
            interface_match = re.search(r'interface\s+(\w+)', line_strip)
            if interface_match:
                interface_name = interface_match.group(1)
                nodes.append({
                    'node_type': 'InterfaceDeclaration',
                    'name': interface_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
        
        # Struct declarations
        elif re.search(r'\b(public|internal|private|protected)?\s*struct\s+\w+', line_strip):
            struct_match = re.search(r'struct\s+(\w+)', line_strip)
            if struct_match:
                struct_name = struct_match.group(1)
                nodes.append({
                    'node_type': 'StructDeclaration',
                    'name': struct_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
        
        # Enum declarations
        elif re.search(r'\b(public|internal|private|protected)?\s*enum\s+\w+', line_strip):
            enum_match = re.search(r'enum\s+(\w+)', line_strip)
            if enum_match:
                enum_name = enum_match.group(1)
                nodes.append({
                    'node_type': 'EnumDeclaration',
                    'name': enum_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
        
        # Delegate declarations
        elif re.search(r'\b(public|internal|private|protected)?\s*delegate\s+', line_strip):
            delegate_match = re.search(r'delegate\s+\w+\s+(\w+)', line_strip)
            if delegate_match:
                delegate_name = delegate_match.group(1)
                nodes.append({
                    'node_type': 'DelegateDeclaration',
                    'name': delegate_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
    
    # Extract enum members (inside enum blocks)
    in_enum = False
    enum_brace_count = 0
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Track when we enter/exit enum blocks
        if re.search(r'\benum\s+\w+', line_strip):
            in_enum = True
            enum_brace_count = 0
        
        if in_enum:
            enum_brace_count += line_strip.count('{') - line_strip.count('}')
            if enum_brace_count == 0 and '{' in lines[idx-2] if idx > 1 else '':
                in_enum = False
            
            # Look for enum members with attributes
            if in_enum and '[' in line_strip and not line_strip.startswith('//'):
                # Check if next non-empty line is an enum member
                for next_idx in range(idx, min(idx + 3, len(lines) + 1)):
                    next_line = lines[next_idx - 1].strip()
                    if next_line and not next_line.startswith('[') and not next_line.startswith('//'):
                        enum_member_match = re.match(r'^(\w+)\s*[,=]?', next_line)
                        if enum_member_match:
                            member_name = enum_member_match.group(1)
                            nodes.append({
                                'node_type': 'EnumMemberDeclaration',
                                'name': member_name,
                                'lineno': idx,
                                'source': line_strip + ' ' + next_line,
                                'declaration': next_line
                            })
                        break
    
    # Extract method declarations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Method declarations (with access modifiers and return types)
        method_pattern = r'\b(public|private|protected|internal|static|virtual|override|abstract)\s+.*?\s+(\w+)\s*\('
        method_match = re.search(method_pattern, line_strip)
        if method_match and not line_strip.startswith('//') and '{' not in line_strip.split('(')[0]:
            method_name = method_match.group(2)
            
            # Skip constructors, properties, and keywords but allow proper C# methods (that start with uppercase)
            keywords = ['class', 'interface', 'namespace', 'using', 'if', 'for', 'while', 'switch', 'return', 'new']
            # Allow methods that start with uppercase (proper C# convention) but filter out obvious non-methods
            if (method_name not in keywords and 
                '(' in line_strip and
                not line_strip.strip().startswith('new ') and
                not line_strip.strip().startswith('return ') and
                method_name not in ['Console', 'WriteLine', 'ReadLine']):  # Common non-method patterns
                
                # Extract full method body
                method_source = ""
                brace_count = 0
                start_found = False
                semicolon_method = line_strip.endswith(';')  # Abstract or interface method
                
                for i in range(idx - 1, len(lines)):
                    current_line = lines[i]
                    method_source += current_line + "\n"
                    
                    if semicolon_method and current_line.strip().endswith(';'):
                        break
                    
                    for char in current_line:
                        if char == '{':
                            brace_count += 1
                            start_found = True
                        elif char == '}':
                            brace_count -= 1
                    if start_found and brace_count == 0:
                        break
                
                nodes.append({
                    'node_type': 'MethodDeclaration',
                    'name': method_name,
                    'lineno': idx,
                    'source': method_source,
                    'declaration': line_strip,
                    'parent_source': source_code
                })
    
    # Extract property declarations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Property declarations with get/set
        if ('{ get;' in line_strip or '{ set;' in line_strip or 
            '=> ' in line_strip and not line_strip.startswith('//')):
            
            property_pattern = r'\b(public|private|protected|internal|static).*?\s+(\w+)\s*\{'
            property_match = re.search(property_pattern, line_strip)
            if property_match:
                property_name = property_match.group(2)
                nodes.append({
                    'node_type': 'PropertyDeclaration',
                    'name': property_name,
                    'lineno': idx,
                    'source': line_strip,
                    'declaration': line_strip
                })
    
    # Extract for loops, foreach loops
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        if (line_strip.startswith('for ') or line_strip.startswith('for(') or 
            line_strip.startswith('foreach ') or line_strip.startswith('foreach(')):
            
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
    
    # Extract try-catch blocks
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
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
    
    # Extract method invocations and assignments
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        if not line_strip or line_strip.startswith('//') or line_strip.startswith('/*'):
            continue
        
        # Track variable assignments
        assignment_match = re.match(r'.*\b(\w+)\s*=\s*(new\s+\w+\(\)|new\s+\w+\[\]|\[\]|\{\})', line_strip)
        if assignment_match:
            var_name = assignment_match.group(1)
            assignment_value = assignment_match.group(2)
            if 'new' in assignment_value and '[]' in assignment_value:
                var_assignments[var_name] = 'emptyArray'
            elif assignment_value in ['{}', 'new {}']:
                var_assignments[var_name] = 'emptyObject'
        
        # Extract method calls (exclude control flow statements and declarations)
        control_keywords = ['if', 'for', 'foreach', 'while', 'switch', 'catch', 'using', 'lock']
        declaration_keywords = ['public', 'private', 'protected', 'internal', 'static', 'virtual', 'override', 'abstract']
        
        if ('(' in line_strip and ')' in line_strip and 
            not any(line_strip.strip().startswith(kw) for kw in control_keywords) and
            not any(kw in line_strip.split('(')[0] for kw in declaration_keywords) and
            not line_strip.strip().startswith('new ') and
            '=' not in line_strip.split('(')[0]):
            
            # Extract method name before '('
            before_paren = line_strip.split('(')[0].strip()
            
            # Handle different call patterns
            if '.' in before_paren:
                method_name = before_paren.split('.')[-1]
            elif '=' in before_paren:
                # Assignment with method call on right side
                right_side = before_paren.split('=')[-1].strip()
                if '.' in right_side:
                    method_name = right_side.split('.')[-1]
                else:
                    method_name = right_side
            else:
                # Simple method call
                method_name = before_paren.split()[-1] if before_paren else 'unknown'
            
            # Extract arguments
            args_part = line_strip.split('(', 1)[-1].rsplit(')', 1)[0]
            arguments = [a.strip() for a in args_part.split(',') if a.strip()]
            
            nodes.append({
                'node_type': 'CallExpression',
                'name': method_name,
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code,
                'arguments': arguments
            })
        
        # Extract assignment expressions
        elif '=' in line_strip and not line_strip.startswith('//'):
            nodes.append({
                'node_type': 'Assignment',
                'assignment_type': 'Assignment',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract comparison expressions
        elif any(op in line_strip for op in ['==', '!=', '>=', '<=', '>', '<']) and not line_strip.startswith('//'):
            nodes.append({
                'node_type': 'Expression',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
        
        # Extract unit test assertions (NUnit, xUnit, MSTest)
        if any(test_keyword in line_strip for test_keyword in ['Assert.', 'Should.', 'Expect(', '.Should()']):
            nodes.append({
                'node_type': 'TestAssertion',
                'lineno': idx,
                'source': line_strip,
                'parent_source': source_code
            })
    
    # Extract attributes/annotations
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        if line_strip.startswith('[') and line_strip.endswith(']'):
            attribute_match = re.search(r'\[(\w+)', line_strip)
            if attribute_match:
                attribute_name = attribute_match.group(1)
                nodes.append({
                    'node_type': 'Attribute',
                    'id': attribute_name,
                    'lineno': idx,
                    'source': line_strip
                })
    
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
    cs_files = get_all_csharp_files(scan_path)
    all_findings = []
    
    for cs_file in cs_files:
        ast_tree = parse_csharp_file(cs_file)
        for rule in rules:
            findings = csharp_generic_rule_engine.run_rule(rule, ast_tree, cs_file)
            if findings:
                for finding in findings:
                    finding['file'] = cs_file
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
        "csharp": [".cs"],
        "c#": [".cs"],
        "terraform": [".tf", ".hcl"],
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
    Parse a file to AST based on language.
    Currently supports C# and other languages from the original scanner.
    """
    if language.lower() in ["csharp", "c#", "cs"]:
        return parse_csharp_file(file_path)
    else:
        # Placeholder for other languages
        return {"node_type": "Module", "body": []}

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))

def run_scan(file_path):
    """
    Wrapper function for plugin compatibility.
    Scans a single C# file or directory and returns findings.
    This function is called by the scanner_plugin system.
    """
    findings = run_scanner(file_path)
    # Clean findings for API consistency
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict):
            # Create a copy to avoid modifying original
            cleaned_finding = finding.copy()
            cleaned_results.append(cleaned_finding)
        else:
            cleaned_results.append(finding)
    return cleaned_results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: csharp_scanner.py <input_path> [language]")
        sys.exit(1)
        
    input_path = sys.argv[1]
    language = sys.argv[2].lower() if len(sys.argv) > 2 else "csharp"
    
    try:
        # Use the scanner function that loads from csharp_docs by default
        findings = run_scanner(input_path)
        
        # Count actual files scanned
        if language in ["csharp", "c#", "cs"]:
            files_scanned = len(get_all_csharp_files(input_path))
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