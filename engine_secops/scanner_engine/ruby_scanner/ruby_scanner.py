import sys
import re
import os
import json
import subprocess
import tempfile
from typing import Dict, List, Optional, Set, Any, Union
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
        self.scope = None
        
    def add_child(self, child):
        self.children.append(child)
        if child:
            child.parent = self

class ProgramNode(ASTNode):
    """Root node representing the entire Ruby program"""
    def __init__(self, name="main", line=None, col=None, source_span=None):
        super().__init__('ProgramNode', [], None, line, col, source_span)
        self.name = name
        self.requires = []  # List of required files/gems
        self.classes = {}   # Map of class names to ClassNode
        self.modules = {}   # Map of module names to ModuleNode
        self.methods = {}   # Top-level method definitions

class ClassNode(ASTNode):
    """Ruby class definition"""
    def __init__(self, name, superclass=None, line=None, col=None, source_span=None):
        super().__init__('ClassNode', [], None, line, col, source_span)
        self.name = name
        self.superclass = superclass
        self.methods = {}
        self.constants = {}
        self.instance_variables = {}
        self.class_variables = {}
        self.visibility = 'public'

class ModuleNode(ASTNode):
    """Ruby module definition"""
    def __init__(self, name, line=None, col=None, source_span=None):
        super().__init__('ModuleNode', [], None, line, col, source_span)
        self.name = name
        self.methods = {}
        self.constants = {}
        self.included_modules = []

class MethodNode(ASTNode):
    """Ruby method definition"""
    def __init__(self, name, params=None, visibility='public', line=None, col=None, source_span=None):
        super().__init__('MethodNode', [], None, line, col, source_span)
        self.name = name
        self.params = params or []
        self.visibility = visibility
        self.local_variables = {}
        self.is_class_method = False
        self.return_nodes = []

class BlockNode(ASTNode):
    """Ruby block (proc/lambda)"""
    def __init__(self, params=None, line=None, col=None, source_span=None):
        super().__init__('BlockNode', [], None, line, col, source_span)
        self.params = params or []
        self.local_variables = {}

class CallNode(ASTNode):
    """Ruby method call or operator usage"""
    def __init__(self, receiver=None, method_name=None, args=None, line=None, col=None, source_span=None):
        super().__init__('CallNode', [], None, line, col, source_span)
        self.receiver = receiver
        self.method_name = method_name
        self.args = args or []
        self.is_safe_navigation = False  # &. operator
        
    def get_full_call_chain(self):
        """Get the full method call chain as a string"""
        if self.receiver:
            if isinstance(self.receiver, str):
                return f"{self.receiver}.{self.method_name}"
            elif hasattr(self.receiver, 'get_full_call_chain'):
                return f"{self.receiver.get_full_call_chain()}.{self.method_name}"
        return self.method_name or "unknown_call"

class AssignmentNode(ASTNode):
    """Ruby variable assignment"""
    def __init__(self, target, value, operator='=', line=None, col=None, source_span=None):
        super().__init__('AssignmentNode', [], None, line, col, source_span)
        self.target = target
        self.value = value
        self.operator = operator  # =, +=, -=, etc.

class VariableNode(ASTNode):
    """Ruby variable reference"""
    def __init__(self, name, var_type='local', line=None, col=None, source_span=None):
        super().__init__('VariableNode', [], None, line, col, source_span)
        self.name = name
        self.var_type = var_type  # local, instance, class, global, constant
        self.defined_at = None

class LiteralNode(ASTNode):
    """Ruby literal value (string, number, symbol, etc.)"""
    def __init__(self, value, literal_type='string', line=None, col=None, source_span=None):
        super().__init__('LiteralNode', [], None, line, col, source_span)
        self.value = value
        self.literal_type = literal_type  # string, integer, float, symbol, nil, boolean

class ConditionalNode(ASTNode):
    """Ruby if/unless/case statements"""
    def __init__(self, condition, condition_type='if', line=None, col=None, source_span=None):
        super().__init__('ConditionalNode', [], None, line, col, source_span)
        self.condition = condition
        self.condition_type = condition_type  # if, unless, case
        self.then_branch = None
        self.else_branch = None
        self.when_branches = []  # For case statements

class LoopNode(ASTNode):
    """Ruby loop constructs (while, for, each, etc.)"""
    def __init__(self, loop_type, condition=None, line=None, col=None, source_span=None):
        super().__init__('LoopNode', [], None, line, col, source_span)
        self.loop_type = loop_type  # while, until, for, each
        self.condition = condition
        self.body = None

class ReturnNode(ASTNode):
    """Ruby return statement"""
    def __init__(self, value=None, line=None, col=None, source_span=None):
        super().__init__('ReturnNode', [], None, line, col, source_span)
        self.value = value

class RescueNode(ASTNode):
    """Ruby rescue/exception handling"""
    def __init__(self, exception_types=None, var_name=None, line=None, col=None, source_span=None):
        super().__init__('RescueNode', [], None, line, col, source_span)
        self.exception_types = exception_types or []
        self.var_name = var_name
        self.body = None

# --- Scope and Symbol Table Classes ---

class Scope:
    def __init__(self, scope_type, name, parent=None):
        self.scope_type = scope_type  # global, class, module, method, block
        self.name = name
        self.parent = parent
        self.variables = {}
        self.methods = {}
        self.constants = {}
        
    def define_variable(self, name, node):
        self.variables[name] = node
        
    def lookup_variable(self, name):
        if name in self.variables:
            return self.variables[name]
        if self.parent:
            return self.parent.lookup_variable(name)
        return None

class SymbolTable:
    def __init__(self):
        self.current_scope = None
        self.global_scope = Scope('global', 'main')
        self.current_scope = self.global_scope
        
    def enter_scope(self, scope_type, name):
        new_scope = Scope(scope_type, name, self.current_scope)
        self.current_scope = new_scope
        return new_scope
        
    def exit_scope(self):
        if self.current_scope.parent:
            self.current_scope = self.current_scope.parent
            
    def define_variable(self, name, node):
        self.current_scope.define_variable(name, node)
        
    def lookup_variable(self, name):
        return self.current_scope.lookup_variable(name)

# --- Ruby Parser using whitequark parser approach ---

class WhitequarkRubyParser:
    """
    Ruby parser that follows SonarSource's approach using whitequark parser.
    
    SonarSource's actual implementation:
    1. Uses JRuby runtime (Ruby on JVM) 
    2. Leverages whitequark parser gem (same as RuboCop)
    3. Produces Ruby AST with nodes like: send, def, class, if, block, etc.
    4. Maps Ruby AST to Sonar's unified AST model
    5. Applies rule engine to detect vulnerabilities
    
    This implementation:
    - Uses Ruby subprocess with parser gem when available (ruby_ast_parser.rb)
    - Falls back to simplified parsing when Ruby not available
    - Produces similar AST structure to enable proper rule engine operation
    """
    
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.current_line = 1
        
    def parse_file(self, file_path):
        """Parse a Ruby file using whitequark parser approach and return AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.parse_content(content, file_path)
        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return None
    
    def parse_content(self, content, filename="<string>"):
        """
        Parse Ruby content using whitequark parser approach.
        This simulates what SonarSource does with JRuby + whitequark parser gem.
        """
        try:
            # First, try to get proper Ruby AST using Ruby's parser
            ast_data = self._parse_with_ruby_parser(content, filename)
            if ast_data:
                root = self._build_ast_from_parser_output(ast_data, filename)
            else:
                # Fallback to simplified parsing if Ruby parser not available
                root = self._fallback_parse(content, filename)
            
            # Build symbol table - NO SECURITY ANALYSIS (belongs in FlowAnalyzer)
            self._build_symbol_table(root)
            
            return root
            
        except Exception as e:
            # Don't print to stdout as it interferes with JSON output
            # Use fallback parsing instead
            return self._fallback_parse(content, filename)
    
    def _parse_with_ruby_parser(self, content, filename):
        """
        Use Ruby's parser gem (like whitequark) to get proper AST.
        This simulates SonarSource's approach of using JRuby + whitequark parser.
        """
        try:
            # Use our Ruby AST parser script
            ruby_script_path = os.path.join(os.path.dirname(__file__), 'ruby_ast_parser.rb')
            
            if not os.path.exists(ruby_script_path):
                # Don't print to stdout as it interferes with JSON output
                return None
            
            # Create temporary Ruby file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Run Ruby AST parser
                result = subprocess.run(
                    ['ruby', ruby_script_path, temp_file_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    # Parse the JSON output from Ruby parser
                    ast_data = json.loads(result.stdout.strip())
                    if ast_data.get('success'):
                        return ast_data
                    else:
                        # Don't print to stdout as it interferes with JSON output
                        pass
                elif result.stderr:
                    # Don't print to stdout as it interferes with JSON output
                    pass
                    
            finally:
                os.unlink(temp_file_path)
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
            # Don't print to stdout as it interferes with JSON output
            # print(f"Ruby parser not available (install Ruby + parser gem for better analysis): {e}")
            pass
            
        return None
    
    def _build_ast_from_parser_output(self, parser_result, filename):
        """Build our internal AST from Ruby parser output"""
        root = ProgramNode(filename)
        
        if not parser_result.get('success'):
            # Don't print to stdout as it interferes with JSON output
            # print(f"Parser failed: {parser_result.get('error', 'Unknown error')}")
            return root
        
        ast_data = parser_result.get('ast', {})
        security_issues = parser_result.get('security_issues', [])
        
        def build_node(data, parent=None):
            if not isinstance(data, dict):
                return None
                
            node_type = data.get('type', 'unknown')
            location = data.get('location', {})
            line = location.get('line', 1)
            
            # Create appropriate node based on Ruby AST type
            if node_type == 'def':
                name = data.get('name', 'unknown')
                params = data.get('params', [])
                param_names = [p.get('name', '') for p in params if isinstance(p, dict)]
                node = MethodNode(name, param_names, line=line)
                
            elif node_type == 'class':
                name = data.get('name', 'unknown') 
                superclass = data.get('superclass', None)
                node = ClassNode(name, superclass, line=line)
                
            elif node_type == 'module':
                name = data.get('name', 'unknown')
                node = ModuleNode(name, line=line)
                
            elif node_type == 'send':
                receiver = data.get('receiver')
                method_name = data.get('method_name', 'unknown')
                args = data.get('args', [])
                
                receiver_str = None
                if receiver and isinstance(receiver, dict):
                    if receiver.get('type') == 'lvar':
                        receiver_str = receiver.get('var_name', '')
                    elif receiver.get('type') == 'const':
                        receiver_str = receiver.get('name', '')
                    else:
                        receiver_str = str(receiver.get('name', ''))
                
                node = CallNode(receiver_str, method_name, args, line=line)
                    
            elif node_type in ['lvasgn', 'ivasgn', 'cvasgn', 'gvasgn', 'casgn']:
                var_name = data.get('var_name', 'unknown')
                var_type = data.get('var_type', 'local')
                value = data.get('value')
                
                var_node = VariableNode(var_name, var_type, line=line)
                node = AssignmentNode(var_node, value, '=', line=line)
                
            elif node_type in ['lvar', 'ivar', 'cvar', 'gvar']:
                var_name = data.get('var_name', 'unknown')
                var_type = data.get('var_type', 'local')
                node = VariableNode(var_name, var_type, line=line)
                
            elif node_type in ['if', 'unless', 'case']:
                condition = data.get('condition')
                node = ConditionalNode(condition, node_type, line=line)
                
            elif node_type in ['while', 'until', 'for']:
                condition = data.get('condition')
                node = LoopNode(node_type, condition, line=line)
                
            elif node_type == 'rescue':
                exception_types = data.get('exception_types', [])
                node = RescueNode(exception_types, None, line=line)
                
            elif node_type in ['str', 'int', 'float', 'sym', 'true', 'false', 'nil']:
                literal_type = node_type
                value = data.get('value')
                node = LiteralNode(value, literal_type, line=line)
                
            elif node_type == 'return':
                value = data.get('value')
                node = ReturnNode(value, line=line)
                
            else:
                # Generic node for other types
                node = ASTNode(node_type, line=line)
                node.name = data.get('name', 'unknown')
            
            if parent:
                parent.add_child(node)
            
            # Process children
            children = data.get('children', [])
            for child_data in children:
                if isinstance(child_data, dict):
                    build_node(child_data, node)
                    
            return node
        
        # Build AST from parser data
        build_node(ast_data, root)
        
        # NOTE: Security findings from Ruby parser are ignored in Sonar architecture
        # Security decisions belong in FlowAnalyzer + Rules, not parser
        
        return root
    

    
    def _fallback_parse(self, content, filename):
        """
        Fallback parser when Ruby parser is not available.
        This provides basic parsing functionality.
        """
        lines = content.split('\n')
        root = ProgramNode(filename)
        
        current_node = root
        for i, line in enumerate(lines):
            self.current_line = i + 1
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
                
            node = self._parse_line_simple(line, self.current_line)
            if node:
                current_node.add_child(node)
                if isinstance(node, (ClassNode, ModuleNode, MethodNode)):
                    current_node = node
                elif line.strip() == 'end':
                    if current_node.parent:
                        current_node = current_node.parent
        
        return root
    
    def _parse_line_simple(self, line, line_num):
        """Simple line-based parsing for fallback"""
        line = line.strip()
        
        # Class definition
        if line.startswith('class '):
            match = re.match(r'class\s+(\w+)(?:\s*<\s*(\w+))?', line)
            if match:
                name, superclass = match.groups()
                return ClassNode(name, superclass, line_num)
        
        # Module definition
        if line.startswith('module '):
            match = re.match(r'module\s+(\w+)', line)
            if match:
                return ModuleNode(match.group(1), line_num)
        
        # Method definition
        if line.startswith('def '):
            match = re.match(r'def\s+(\w+)(?:\((.*?)\))?', line)
            if match:
                name, params_str = match.groups()
                params = [p.strip() for p in params_str.split(',')] if params_str else []
                return MethodNode(name, params, line=line_num)
        
        # Method call with security checking
        if re.search(r'\w+(?:\.\w+)*\s*(?:\(.*?\))?', line):
            return self._parse_method_call_simple(line, line_num)
        
        # Assignment
        if '=' in line and not line.startswith('='):
            return self._parse_assignment_simple(line, line_num)
        
        # Control flow
        if line.startswith(('if ', 'unless ', 'case ')):
            condition_type = line.split()[0]
            condition = line[len(condition_type):].strip()
            return ConditionalNode(condition, condition_type, line_num)
        
        # Rescue clause
        if line.startswith('rescue'):
            # Check if it's bare rescue
            rescue_text = line[6:].strip()
            if not rescue_text or rescue_text.startswith('=>'):
                return RescueNode([], None, line_num)  # Bare rescue
            else:
                exception_types = [rescue_text.split()[0]]
                return RescueNode(exception_types, None, line_num)
        
        # Return statement
        if line.startswith('return'):
            value = line[6:].strip() if len(line) > 6 else None
            return ReturnNode(value, line_num)
        
        return None
    
    def _parse_method_call_simple(self, line, line_num):
        """Parse method call with security analysis"""
        # Method call with receiver
        match = re.match(r'(.*?)\.(\w+)(?:\((.*?)\))?', line)
        if match:
            receiver_str, method_name, args_str = match.groups()
            receiver = receiver_str.strip() if receiver_str else None
            args = [a.strip() for a in args_str.split(',')] if args_str else []
            
            call_node = CallNode(receiver, method_name, args, line_num)
            return call_node
        
        # Simple method call without receiver
        match = re.match(r'(\w+)(?:\((.*?)\))?', line)
        if match:
            method_name, args_str = match.groups()
            args = [a.strip() for a in args_str.split(',')] if args_str else []
            
            call_node = CallNode(None, method_name, args, line_num)
            return call_node
        
        return None
    
    def _parse_assignment_simple(self, line, line_num):
        """Parse assignment with security analysis"""
        if '=' in line:
            parts = line.split('=', 1)
            target = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else None
            
            # Determine variable type
            var_type = 'local'
            if target.startswith('@@'):
                var_type = 'class'
            elif target.startswith('@'):
                var_type = 'instance'
            elif target.startswith('$'):
                var_type = 'global'
            elif target and target[0].isupper():
                var_type = 'constant'
                
            var_node = VariableNode(target, var_type, line_num)
            return AssignmentNode(var_node, value, '=', line_num)
        
        return None
    
    def _build_symbol_table(self, node):
        """Build symbol table by traversing AST"""
        if isinstance(node, ClassNode):
            self.symbol_table.enter_scope('class', node.name)
        elif isinstance(node, ModuleNode):
            self.symbol_table.enter_scope('module', node.name)
        elif isinstance(node, MethodNode):
            self.symbol_table.enter_scope('method', node.name)
        elif isinstance(node, BlockNode):
            self.symbol_table.enter_scope('block', 'block')
        
        # Set scope reference on node
        node.scope = self.symbol_table.current_scope
        
        # Register variables and methods
        if isinstance(node, AssignmentNode) and isinstance(node.target, VariableNode):
            self.symbol_table.define_variable(node.target.name, node.target)
        
        # Process children
        for child in node.children:
            self._build_symbol_table(child)
        
        # Exit scope
        if isinstance(node, (ClassNode, ModuleNode, MethodNode, BlockNode)):
            self.symbol_table.exit_scope()
    


# --- File Processing Functions ---

def get_language_extensions(language: str) -> List[str]:
    """Map Ruby to its file extensions."""
    extensions = {
        "ruby": [".rb", ".rake", ".gemspec"],
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

def load_metadata(folder="ruby_docs"):
    """Load rule metadata from JSON files"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        # Try the 'final' folder as fallback
        folder_path = os.path.join(script_dir, 'final')
        
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
            try:
                with open(os.path.join(folder_path, filename), 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)
                    rule_id = rule_data.get('rule_id') or filename.replace('_metadata.json', '')
                    rules_meta[rule_id] = rule_data
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    
    return rules_meta

def get_all_files(scan_path, language):
    """Get all Ruby files in the scan path"""
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

# --- Main Scanner Function ---

def run_scanner(scan_path):
    """Main scanner function"""
    from .ruby_logic_implementations import set_current_file_path
    from . import ruby_generic_rule_engine
    
    rules_meta = load_metadata()
    rules = list(rules_meta.values())
    ruby_files = get_all_files(scan_path, "ruby")
    all_findings = []
    
    parser = WhitequarkRubyParser()  # Use the proper Ruby parser approach
    
    for ruby_file in ruby_files:
        set_current_file_path(ruby_file)
        
        ast_tree = parser.parse_file(ruby_file)
        if ast_tree is None:
            continue
            
        for rule in rules:
            try:
                findings = ruby_generic_rule_engine.run_rule(rule, ast_tree, ruby_file)
                all_findings.extend(findings)
            except Exception as e:
                print(f"Error running rule {rule.get('rule_id', 'unknown')} on {ruby_file}: {e}")
    
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        property_path_str = str(f.get('property_path', []))
        value_str = str(f.get('value', ''))
        node_str = str(f.get('node_type', ''))
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'), property_path_str, value_str, node_str)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    return deduped

# API entry point for plugin system
def run_scan(file_path):
    """Scan a single Ruby file and return findings as a list of dicts."""
    findings = run_scanner(file_path)
    # Clean findings for API
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict) and 'file' in finding:
            del finding['file']
        cleaned_results.append(clean_for_json(finding))
    return cleaned_results

def clean_for_json(obj, depth=0, max_depth=10):
    """Clean objects for JSON serialization"""
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

# --- Main entry point ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ruby_scanner.py <input_path>")
        sys.exit(1)
        
    input_path = sys.argv[1]
    language = "ruby"
    
    try:
        findings = run_scanner(input_path)
        result = {
            "language": language,
            "findings": [clean_for_json(f) for f in findings],
            "summary": {
                "total_findings": len(findings),
                "files_scanned": len(get_all_files(input_path, language))
            }
        }
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


# --- Module Level Convenience Functions ---

def parse_file_to_ast(file_path):
    """Convenience function to parse a Ruby file to AST."""
    parser = WhitequarkRubyParser()
    return parser.parse_file(file_path)

def parse_ruby_file(file_path):
    """Alias for parse_file_to_ast for backwards compatibility."""
    return parse_file_to_ast(file_path)