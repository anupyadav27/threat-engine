import sys
import re
import os
import json
from . import arm_generic_rule_engine
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

# --- AST Node Classes ---

class ASTNode:
    def __init__(self, node_type, children=None, parent=None, line=None, col=None, source_span=None):
        self.node_type = node_type
        self.children = children or []
        self.parent = parent
        self.line = line
        self.col = col
        self.source_span = source_span  # (start_line, start_col, end_line, end_col)
    
    def add_child(self, child):
        self.children.append(child)
        child.parent = self

class TemplateNode(ASTNode):
    def __init__(self, body, line=None, col=None, source_span=None):
        super().__init__('TemplateNode', [], None, line, col, source_span)

class ResourceNode(ASTNode):
    def __init__(self, type_, name, apiVersion, properties, location=None, path=None, line=None, col=None, source_span=None):
        super().__init__('ResourceNode', [], None, line, col, source_span)
        self.type = type_
        self.name = name
        self.apiVersion = apiVersion
        self.location = location
        self.path = path or []
        self.depends_on = []  # List of resource IDs this node depends on
        self.consumers = []   # List of ResourceNodes that depend on this node
        self.child_resources = []  # Nested/child resources
        
        # Add property nodes
        self._add_property_nodes(properties, self.path + ['properties'])
        
        # Add location as a property node if it exists
        if location is not None:
            location_path = self.path + ['location']
            location_node = build_property_node(location_path, location)
            self.add_child(location_node)

    def _add_property_nodes(self, properties, path_prefix):
        if isinstance(properties, dict):
            for k, v in properties.items():
                full_path = path_prefix + [k]
                pnode = build_property_node(full_path, v)
                self.add_child(pnode)
        elif isinstance(properties, list):
            for idx, v in enumerate(properties):
                full_path = path_prefix + [str(idx)]
                pnode = build_property_node(full_path, v)
                self.add_child(pnode)

    def get_attached_resources(self):
        """Get list of resources this resource depends on"""
        return getattr(self, 'depends_on', [])

    def get_consumers(self):
        """Get list of resources that depend on this resource"""
        return getattr(self, 'consumers', [])

class PropertyNode(ASTNode):
    def __init__(self, path, value, line=None, col=None, source_span=None):
        super().__init__('PropertyNode', [], None, line, col, source_span)
        self.path = path
        # Only add child nodes, never store raw value
        if isinstance(value, dict):
            for k, v in value.items():
                child_path = path + [k]
                child = build_property_node(child_path, v)
                self.add_child(child)
        elif isinstance(value, list):
            for idx, v in enumerate(value):
                child_path = path + [str(idx)]
                child = build_property_node(child_path, v)
                self.add_child(child)
        else:
            # If value is a string and looks like an ARM expression, parse it
            if isinstance(value, str) and value.strip().startswith('[') and value.strip().endswith(']'):
                expr_ast = parse_arm_expression(value)
                self.add_child(expr_ast)
            elif value is not None:
                self.add_child(LiteralNode(value))

class ParameterNode(ASTNode):
    def __init__(self, name, definition, line=None, col=None, source_span=None):
        super().__init__('ParameterNode', [], None, line, col, source_span)
        self.name = name
        self.definition = definition  # Full parameter definition including type, allowedValues, etc.
        self.value = definition.get('defaultValue') if isinstance(definition, dict) else None

class VariableNode(ASTNode):
    def __init__(self, name, value, line=None, col=None, source_span=None):
        super().__init__('VariableNode', [], None, line, col, source_span)
        self.name = name
        self.value = value

class OutputNode(ASTNode):
    def __init__(self, name, value, line=None, col=None, source_span=None):
        super().__init__('OutputNode', [], None, line, col, source_span)
        self.name = name
        self.value = value

# --- ARM Expression AST ---
class ExpressionNode(ASTNode):
    pass

class FunctionCallNode(ExpressionNode):
    def __init__(self, function_name, args, line=None, col=None, source_span=None):
        super().__init__('FunctionCallNode', [], None, line, col, source_span)
        self.function_name = function_name
        self.args = args
        for arg in args:
            self.add_child(arg)

class ParameterReferenceNode(ExpressionNode):
    def __init__(self, parameter_name, line=None, col=None, source_span=None):
        super().__init__('ParameterReferenceNode', [], None, line, col, source_span)
        self.parameter_name = parameter_name

class VariableReferenceNode(ExpressionNode):
    def __init__(self, variable_name, line=None, col=None, source_span=None):
        super().__init__('VariableReferenceNode', [], None, line, col, source_span)
        self.variable_name = variable_name

class LiteralNode(ExpressionNode):
    def __init__(self, value, line=None, col=None, source_span=None):
        super().__init__('LiteralNode', [], None, line, col, source_span)
        self.value = value

class UnknownExpressionNode(ExpressionNode):
    def __init__(self, expr_str, line=None, col=None, source_span=None):
        super().__init__('UnknownExpressionNode', [], None, line, col, source_span)
        self.expr_str = expr_str

# --- Forward declarations for functions that will be defined later ---
def build_property_node(path, value, line=None, col=None, source_span=None):
    """Forward declaration - defined below"""
    pass

def parse_arm_expression(expr_str):
    """Forward declaration - defined below"""
    pass

# --- Utility Functions ---

def get_language_extensions(language: str) -> List[str]:
    """Map ARM to its file extensions."""
    extensions = {
        "arm": [".json"],
    }
    return extensions.get(language, [])

@dataclass
class Finding:
    rule_id: str
    message: str
    file: str
    line: Optional[int]
    severity: str
    property_path: List[str]
    def __hash__(self) -> int:
        return hash((self.rule_id, self.file, self.line, self.message))

def load_metadata(folder="azure_docs"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "rule_id" in data:
                        rules_meta[data["rule_id"]] = data
            except Exception:
                continue
    return rules_meta

def get_all_files(scan_path, language):
    target_files = []
    extensions = get_language_extensions(language)
    if os.path.isfile(scan_path) and any(scan_path.endswith(ext) for ext in extensions):
        target_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    target_files.append(os.path.join(root, file))
    return target_files

def is_arm_template(json_data: dict) -> bool:
    # $schema check
    if "$schema" in json_data and "schema.management.azure.com" in str(json_data["$schema"]):
        return True
    # resources[] at top level with type/apiVersion
    if "resources" in json_data and isinstance(json_data["resources"], list):
        for res in json_data["resources"]:
            if isinstance(res, dict) and "type" in res and "apiVersion" in res:
                return True
    return False

# --- ARM Expression Parser (enhanced) ---
def parse_arm_expression(expr_str):
    # If not an ARM expression, treat as literal
    if not (isinstance(expr_str, str) and expr_str.startswith('[') and expr_str.endswith(']')):
        return LiteralNode(expr_str)
    
    expr = expr_str[1:-1].strip()
    if not expr:
        return UnknownExpressionNode(expr_str)
    
    def parse_arguments(args_str):
        """Parse comma-separated function arguments, respecting nested parentheses and quotes"""
        args = []
        depth = 0
        current = ''
        in_quotes = False
        quote_char = None
        
        for i, c in enumerate(args_str):
            if not in_quotes:
                if c in ['"', "'"]:
                    in_quotes = True
                    quote_char = c
                elif c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                elif c == ',' and depth == 0:
                    args.append(current.strip())
                    current = ''
                    continue
            else:
                if c == quote_char and (i == 0 or args_str[i-1] != '\\'):
                    in_quotes = False
                    quote_char = None
            current += c
            
        if current.strip():
            args.append(current.strip())
        return args
    
    def parse_expr(s):
        s = s.strip()
        if not s:
            return LiteralNode('')
            
        # Match function calls: func(arg1, arg2, ...)
        m = re.match(r"(\w+)\((.*)\)$", s)
        if m:
            func = m.group(1).lower()  # ARM functions are case-insensitive
            args_str = m.group(2)
            args = parse_arguments(args_str)
            parsed_args = [parse_expr(arg) for arg in args]
            
            # Recognize parameter/variable references
            if func == 'parameters' and len(parsed_args) == 1 and isinstance(parsed_args[0], LiteralNode):
                return ParameterReferenceNode(parsed_args[0].value)
            if func == 'variables' and len(parsed_args) == 1 and isinstance(parsed_args[0], LiteralNode):
                return VariableReferenceNode(parsed_args[0].value)
            
            return FunctionCallNode(func, parsed_args)
            
        # Literal string or number
        if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
            return LiteralNode(s[1:-1])
            
        # Boolean literals
        if s.lower() in ['true', 'false']:
            return LiteralNode(s.lower() == 'true')
            
        # Null literal
        if s.lower() == 'null':
            return LiteralNode(None)
            
        # Try to parse as number
        try:
            if '.' in s:
                return LiteralNode(float(s))
            else:
                return LiteralNode(int(s))
        except ValueError:
            pass
            
        # Array or object literals (simplified)
        if s.startswith('[') and s.endswith(']'):
            # Array literal - simplified parsing
            return UnknownExpressionNode(s)
        if s.startswith('{') and s.endswith('}'):
            # Object literal - simplified parsing  
            return UnknownExpressionNode(s)
            
        # Unknown/complex expression
        return UnknownExpressionNode(s)
        
    return parse_expr(expr)

# Helper to build PropertyNode recursively
def build_property_node(path, value, line=None, col=None, source_span=None):
    # If value is a string and looks like an ARM expression, parse it
    if isinstance(value, str) and value.strip().startswith('[') and value.strip().endswith(']'):
        expr_ast = parse_arm_expression(value)
        node = PropertyNode(path, None, line, col, source_span)
        node.add_child(expr_ast)
        node.value = value  # Keep original for reference
        return node
    return PropertyNode(path, value, line, col, source_span)

# --- AST Construction: Build Semantic AST ---
def build_semantic_ast(data, line=None, col=None):
    if not is_arm_template(data):
        return None
    root = TemplateNode(data, line, col)
    
    # Parameters
    params = data.get('parameters', {})
    for pname, pval in params.items():
        pnode = ParameterNode(pname, pval)
        root.add_child(pnode)
    
    # Variables
    variables = data.get('variables', {})
    for vname, vval in variables.items():
        vnode = VariableNode(vname, vval)
        root.add_child(vnode)
    
    # Resources
    resource_index = {}
    for idx, res in enumerate(data.get('resources', [])):
        rtype = res.get('type')
        rname = res.get('name')
        rapiver = res.get('apiVersion')
        rprops = res.get('properties', {})
        rlocation = res.get('location')
        rdepends_on = res.get('dependsOn', [])
        rnode = ResourceNode(rtype, rname, rapiver, rprops, rlocation, path=['resources', str(idx)])
        
        # Add dependsOn as a property node if it exists
        if rdepends_on:
            depends_on_path = rnode.path + ['dependsOn']
            depends_on_node = build_property_node(depends_on_path, rdepends_on)
            rnode.add_child(depends_on_node)
        
        # Handle resource names that might be expressions
        if rtype and rname:
            # If name is an ARM expression, we'll resolve it later
            if isinstance(rname, str) and rname.startswith('[') and rname.endswith(']'):
                resource_id = f"{rtype}/<expression>"
            else:
                resource_id = f"{rtype}/{rname}"
            resource_index[resource_id] = rnode
        root.add_child(rnode)
    
    # Outputs
    outputs = data.get('outputs', {})
    for oname, oval in outputs.items():
        onode = OutputNode(oname, oval)
        root.add_child(onode)
    
    root.resource_index = resource_index
    return root

# --- Parse and process a single ARM file ---
def parse_arm_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except Exception:
            return None
    if not is_arm_template(data):
        return None
    ast = build_semantic_ast(data)
    if ast is not None:
        resolve_ast_symbols_and_eval(ast, data)
    return ast

# --- AST Resolution Pass: Symbol Tables & Expression Evaluation ---
def resolve_ast_symbols_and_eval(ast_root, template_data):
    """
    Second pass: build symbol tables, resolve references, and evaluate expressions.
    Populates ast_root.symbol_tables = {parameters, variables, resources}
    Sets .eval_state for expressions.
    """
    # Build symbol tables
    parameters = template_data.get('parameters', {})
    variables = template_data.get('variables', {})
    resources = {}
    def collect_resources(node):
        if getattr(node, 'node_type', None) == 'ResourceNode':
            rid = f"{getattr(node, 'type', None)}/{getattr(node, 'name', None)}"
            if rid:
                resources[rid] = node
        for child in getattr(node, 'children', []):
            collect_resources(child)
    collect_resources(ast_root)

    ast_root.symbol_tables = {
        'parameters': parameters,
        'variables': variables,
        'resources': resources
    }

    # --- Dependency Graph ---
    resource_nodes = list(resources.values())
    id_to_node = {rid: node for rid, node in resources.items()}
    
    # Initialize dependency tracking
    for node in resource_nodes:
        node.depends_on = []
        node.consumers = []
        
        # Find dependsOn property
        depends_on_node = None
        try:
            for child in getattr(node, 'children', []):
                if (getattr(child, 'node_type', None) == 'PropertyNode' and 
                    child.path and child.path[-1] == 'dependsOn'):
                    depends_on_node = child
                    break
        except Exception as e:
            print(f"Warning: Error processing dependencies for node: {e}")
            continue
            
        if depends_on_node:
            dep_ids = []
            try:
                for dep_child in getattr(depends_on_node, 'children', []):
                    if hasattr(dep_child, 'value') and dep_child.value:
                        dep_ids.append(str(dep_child.value))
                    elif (getattr(dep_child, 'node_type', None) == 'FunctionCallNode' and 
                          getattr(dep_child, 'function_name', None) == 'resourceid'):
                        args = getattr(dep_child, 'args', [])
                        if len(args) >= 2:
                            # Extract type and name from resourceId function
                            dep_type = getattr(args[0], 'value', None) if hasattr(args[0], 'value') else None
                            dep_name = getattr(args[1], 'value', None) if hasattr(args[1], 'value') else None
                            if dep_type and dep_name:
                                dep_ids.append(f"{dep_type}/{dep_name}")
                node.depends_on = dep_ids
            except Exception as e:
                print(f"Warning: Error parsing dependency IDs: {e}")
                node.depends_on = []
    
    # Build consumer relationships
    for node in resource_nodes:
        for dep_id in getattr(node, 'depends_on', []):
            dep_node = id_to_node.get(dep_id)
            if dep_node and hasattr(dep_node, 'consumers'):
                dep_node.consumers.append(node)

    # Resolve references and evaluate expressions
    def resolve_node(node):
        # Expression nodes: set eval_state
        if hasattr(node, 'node_type') and node.node_type.endswith('Node'):
            if node.node_type == 'ParameterReferenceNode':
                pname = getattr(node, 'parameter_name', None)
                node.eval_state = 'RESOLVED' if pname in parameters else 'UNRESOLVED'
            elif node.node_type == 'VariableReferenceNode':
                vname = getattr(node, 'variable_name', None)
                node.eval_state = 'RESOLVED' if vname in variables else 'UNRESOLVED'
            elif node.node_type == 'LiteralNode':
                node.eval_state = 'CONSTANT'
            elif node.node_type == 'FunctionCallNode':
                fn = getattr(node, 'function_name', None)
                args = getattr(node, 'args', [])
                for arg in args:
                    resolve_node(arg)
                if fn == 'if' and len(args) == 3:
                    cond = getattr(args[0], 'eval_state', 'UNKNOWN')
                    true_val = getattr(args[1], 'eval_state', 'UNKNOWN')
                    false_val = getattr(args[2], 'eval_state', 'UNKNOWN')
                    if cond == 'CONSTANT_TRUE':
                        node.eval_state = true_val
                    elif cond == 'CONSTANT_FALSE':
                        node.eval_state = false_val
                    elif cond == 'UNKNOWN' or true_val == 'UNKNOWN' or false_val == 'UNKNOWN':
                        node.eval_state = 'CONDITIONAL'
                    else:
                        node.eval_state = 'CONDITIONAL'
                elif fn == 'equals' and len(args) == 2:
                    a, b = args
                    if getattr(a, 'eval_state', None) == 'CONSTANT' and getattr(b, 'eval_state', None) == 'CONSTANT':
                        node.eval_state = 'CONSTANT_TRUE' if getattr(a, 'value', None) == getattr(b, 'value', None) else 'CONSTANT_FALSE'
                    else:
                        node.eval_state = 'UNKNOWN'
                else:
                    node.eval_state = 'UNKNOWN'
            elif node.node_type == 'UnknownExpressionNode':
                node.eval_state = 'UNKNOWN'
        for child in getattr(node, 'children', []):
            resolve_node(child)
    resolve_node(ast_root)

# --- Utility Functions ---
def load_metadata(folder="azure_docs"):
    """Load all rule metadata JSON files from the specified folder."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        print(f"Warning: Metadata folder '{folder}' not found in {script_dir}.", file=sys.stderr)
        return {}
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
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

def get_all_files(scan_path, language="arm"):
    """Get all ARM template files from the scan path."""
    arm_files = []
    
    if os.path.isfile(scan_path):
        if scan_path.endswith('.json'):
            try:
                with open(scan_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if is_arm_template(json.loads(content)):
                        arm_files.append(scan_path)
            except Exception:
                pass
        return arm_files
    
    # Directory scanning
    for root, dirs, files in os.walk(scan_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if is_arm_template(json.loads(content)):
                            arm_files.append(file_path)
                except Exception:
                    continue
    
    return arm_files

# --- Scanner pipeline: process all files and run rules ---
def run_scanner(scan_path):
    from .arm_logic_implementations import set_current_template_file_path

    try:
        from database.rule_cache import rule_cache
        rules_meta = rule_cache.get_rules("azure")
    except Exception:
        rules_meta = load_metadata()
    rules = list(rules_meta.values())
    arm_files = get_all_files(scan_path, "arm")
    all_findings = []
    for arm_file in arm_files:
        # Set the current template file path for custom functions
        set_current_template_file_path(arm_file)
        
        ast_tree = parse_arm_file(arm_file)
        if ast_tree is None:
            continue
        semantic_context = {
            'resource_index': getattr(ast_tree, 'resource_index', {}),
            'file': arm_file,
        }
        for rule in rules:
            findings = arm_generic_rule_engine.run_rule(rule, ast_tree, arm_file)
            if findings:
                for finding in findings:
                    finding['file'] = arm_file
                    all_findings.append(finding)
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        # Include property_path, value, and node in deduplication key to ensure unique violations are preserved
        property_path_str = str(f.get('property_path', []))
        value_str = str(f.get('value', ''))
        node_str = str(f.get('node', ''))
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'), property_path_str, value_str, node_str)
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

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    return list(set(findings))

def run_scan(file_path):
    """
    Wrapper function for plugin compatibility.
    Scans a single ARM template file or directory and returns findings.
    This function is called by the scanner_plugin system.
    """
    findings = run_scanner(file_path)
    # Clean findings for API consistency
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict):
            # Create a copy to avoid modifying original
            cleaned_finding = finding.copy()
            # Remove file key if present to avoid duplication
            if 'file' in cleaned_finding:
                del cleaned_finding['file']
            cleaned_results.append(cleaned_finding)
        else:
            cleaned_results.append(finding)
    return cleaned_results

# --- Main entry point ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: arm_scanner.py <input_path>")
        sys.exit(1)
    input_path = sys.argv[1]
    language = "arm"
    try:
        findings = run_scanner(input_path)
        result = {
            "language": language,
            "files_scanned": len(get_all_files(input_path, language)),
            "findings": findings
        }
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)