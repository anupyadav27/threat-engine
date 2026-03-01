"""
Go Generic Rule Engine - Semantic Analysis Version

A sophisticated rule engine that applies semantic rules to Go AST with deep understanding of:
- Package imports and visibility (exported/unexported)
- Interface implementations and type assertions
- Goroutines, channels, and concurrency patterns
- Error handling idioms and panic/recover
- Pointer vs value semantics and nil safety
- Method sets and receiver types
- defer statement semantics and resource management
- Go modules and package organization
- Type switches and type assertions
- Embedding and composition patterns

This engine performs semantic analysis similar to what the Go compiler frontend does,
going beyond syntactic pattern matching to understand program behavior and flow.
"""

import re
import json
import sys
from . import logic_implementations
from typing import Any, Dict, List, Optional, Union, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class GoCheckType(Enum):
    """Enumeration of Go-specific check types for semantic analysis."""
    
    # Syntactic checks (legacy support)
    REGEX_MATCH = "regex_match"
    PROPERTY_COMPARISON = "property_comparison"
    
    # Core semantic checks
    TYPE_ASSERTION_CHECK = "type_assertion_check"
    INTERFACE_IMPLEMENTATION_CHECK = "interface_implementation_check"
    METHOD_SET_CHECK = "method_set_check"
    PACKAGE_VISIBILITY_CHECK = "package_visibility_check"
    
    # Go-specific semantic checks
    NIL_SAFETY_CHECK = "nil_safety_check"
    ERROR_HANDLING_CHECK = "error_handling_check"
    GOROUTINE_LEAK_CHECK = "goroutine_leak_check"
    CHANNEL_OPERATION_CHECK = "channel_operation_check"
    DEFER_USAGE_CHECK = "defer_usage_check"
    PANIC_RECOVER_CHECK = "panic_recover_check"
    
    # Memory and performance checks
    SLICE_BOUNDS_CHECK = "slice_bounds_check"
    MAP_ACCESS_CHECK = "map_access_check"
    POINTER_ESCAPE_CHECK = "pointer_escape_check"
    COPY_PERFORMANCE_CHECK = "copy_performance_check"
    
    # Design pattern checks
    CONTEXT_PROPAGATION_CHECK = "context_propagation_check"
    RECEIVER_TYPE_CHECK = "receiver_type_check"
    EMBEDDING_CHECK = "embedding_check"
    COMPOSITION_CHECK = "composition_check"
    
    # Package and module checks
    IMPORT_USAGE_CHECK = "import_usage_check"
    PACKAGE_NAMING_CHECK = "package_naming_check"
    MODULE_STRUCTURE_CHECK = "module_structure_check"
    EXPORTED_API_CHECK = "exported_api_check"
    
    # Control flow and data flow
    CONTROL_FLOW_CHECK = "control_flow_check"
    DATA_FLOW_TAINT_CHECK = "data_flow_taint_check"
    UNREACHABLE_CODE_CHECK = "unreachable_code_check"


@dataclass
class GoTypeInfo:
    """Rich type information for Go semantic analysis."""
    name: str
    package: Optional[str] = None
    is_pointer: bool = False
    is_interface: bool = False
    is_channel: bool = False
    is_slice: bool = False
    is_map: bool = False
    is_func: bool = False
    is_struct: bool = False
    is_exported: bool = False
    
    # Channel specific
    channel_direction: Optional[str] = None  # "send", "receive", "bidirectional"
    
    # Function specific
    func_params: List[str] = None
    func_returns: List[str] = None
    is_variadic: bool = False
    
    # Composite type info
    element_type: Optional[str] = None  # For slices, maps, channels
    key_type: Optional[str] = None      # For maps
    value_type: Optional[str] = None    # For maps
    
    # Interface info
    interface_methods: List[str] = None
    implements_interfaces: List[str] = None
    
    # Struct info
    struct_fields: List[str] = None
    embedded_types: List[str] = None
    
    def __post_init__(self):
        if self.func_params is None:
            self.func_params = []
        if self.func_returns is None:
            self.func_returns = []
        if self.interface_methods is None:
            self.interface_methods = []
        if self.implements_interfaces is None:
            self.implements_interfaces = []
        if self.struct_fields is None:
            self.struct_fields = []
        if self.embedded_types is None:
            self.embedded_types = []


@dataclass
class GoConcurrencyInfo:
    """Track Go concurrency patterns and safety."""
    has_goroutines: bool = False
    channel_operations: List[str] = None
    mutex_usage: bool = False
    race_condition_risk: bool = False
    goroutine_leak_risk: bool = False
    channel_close_pattern: Optional[str] = None
    context_usage: bool = False
    
    def __post_init__(self):
        if self.channel_operations is None:
            self.channel_operations = []


@dataclass
class GoErrorInfo:
    """Track Go error handling patterns."""
    returns_error: bool = False
    error_ignored: bool = False
    panic_usage: bool = False
    recover_usage: bool = False
    proper_error_wrapping: bool = True
    error_handling_pattern: Optional[str] = None


@dataclass
class GoProgramModel:
    """Semantic model of a Go program - the core that powers all analysis."""
    symbols: Dict[str, Dict[str, Any]]  # var_name -> {type, scope, decl_node, origins}
    data_flow: Dict[str, List[str]]     # var_name -> list of origin variables
    calls: Dict[str, List[str]]         # function_name -> called functions
    functions: Dict[str, Dict[str, Any]] # func_name -> {params, returns, body_node}
    goroutines: List[Dict[str, Any]]    # goroutine creation sites
    channels: Dict[str, Dict[str, Any]] # channel_var -> {type, direction, operations}
    errors: Dict[str, Dict[str, Any]]   # error variables and handling
    taint_flows: List[Dict[str, Any]]   # taint flow tracking
    
    def __post_init__(self):
        if not isinstance(self.symbols, dict):
            self.symbols = {}
        if not isinstance(self.data_flow, dict):
            self.data_flow = {}
        if not isinstance(self.calls, dict):
            self.calls = {}
        if not isinstance(self.functions, dict):
            self.functions = {}
        if not isinstance(self.goroutines, list):
            self.goroutines = []
        if not isinstance(self.channels, dict):
            self.channels = {}
        if not isinstance(self.errors, dict):
            self.errors = {}
        if not isinstance(self.taint_flows, list):
            self.taint_flows = []
    
    def trace_origin(self, var_name: str, depth: int = 0, max_depth: int = 5) -> Set[str]:
        """Trace the origin of a variable through data flow."""
        if depth > max_depth or var_name not in self.data_flow:
            return {var_name}
        
        origins = set()
        for source in self.data_flow.get(var_name, [var_name]):
            if source == var_name:  # self-reference, it's a source
                origins.add(source)
            else:
                # Recursively trace
                origins.update(self.trace_origin(source, depth + 1, max_depth))
        
        return origins
    
    def is_tainted(self, var_name: str, taint_sources: Set[str]) -> bool:
        """Check if variable is tainted by any of the given sources."""
        origins = self.trace_origin(var_name)
        
        # Check for exact matches first
        if origins.intersection(taint_sources):
            return True
        
        # Check for prefixed taint sources (e.g., 'TAINT_SOURCE:filename' matches 'filename')
        for origin in origins:
            for taint_source in taint_sources:
                if origin.endswith(f':{taint_source}') or origin == taint_source:
                    return True
        
        return False
    
    def get_error_handling_for(self, var_name: str) -> Optional[Dict[str, Any]]:
        """Get error handling information for a variable."""
        return self.errors.get(var_name)
    
    def get_goroutine_context(self, goroutine_id: int) -> Dict[str, Any]:
        """Get context information for a specific goroutine."""
        if 0 <= goroutine_id < len(self.goroutines):
            return self.goroutines[goroutine_id]
        return {}


class GoSemanticAnalyzer:
    """Semantic analyzer for Go code understanding."""
    
    def __init__(self):
        self.symbol_table = {}
        self.package_info = {}
        self.import_graph = {}
        self.type_hierarchy = {}
        self.interface_implementations = {}
        self.current_package = ""
        
    def build_model(self, ast_tree) -> GoProgramModel:
        """Build comprehensive semantic model from Go AST."""
        self._extract_package_info(ast_tree)
        self._build_import_graph(ast_tree)
        
        # Initialize the program model
        model = GoProgramModel(
            symbols={},
            data_flow={},
            calls={},
            functions={},
            goroutines=[],
            channels={},
            errors={},
            taint_flows=[]
        )
        
        # Build core semantic components
        self._build_symbol_table(ast_tree, model)
        self._build_data_flow_graph(ast_tree, model)
        self._build_call_graph(ast_tree, model)
        # Comment out complex analysis for now to focus on taint tracking
        # self._analyze_goroutines(ast_tree, model)
        # self._analyze_channels(ast_tree, model)
        # self._analyze_error_handling(ast_tree, model)
        
        return model
        
    def analyze_type(self, node: Dict) -> GoTypeInfo:
        """Extract rich type information from Go AST node."""
        if not isinstance(node, dict):
            return GoTypeInfo("unknown")
        
        # Get type string from various possible fields
        type_str = (node.get('type') or node.get('datatype') or 
                   node.get('return_type') or node.get('var_type') or
                   str(node.get('name', 'unknown')))
        
        # Determine if exported (starts with capital letter)
        name_for_export = node.get('name', '')
        is_exported = name_for_export and name_for_export[0].isupper() if name_for_export else False
        
        # Parse Go type characteristics
        is_pointer = '*' in type_str
        is_interface = self._is_interface_type(node, type_str)
        is_channel = self._is_channel_type(type_str)
        is_slice = self._is_slice_type(type_str)
        is_map = self._is_map_type(type_str)
        is_func = self._is_func_type(node, type_str)
        is_struct = self._is_struct_type(node, type_str)
        
        # Extract package information
        package = self._extract_type_package(type_str)
        
        # Channel direction
        channel_direction = self._get_channel_direction(type_str) if is_channel else None
        
        # Extract element/key/value types for composite types
        element_type = self._extract_element_type(type_str)
        key_type, value_type = self._extract_map_types(type_str) if is_map else (None, None)
        
        # Function signature analysis
        func_params, func_returns, is_variadic = self._analyze_function_signature(node) if is_func else ([], [], False)
        
        # Clean type name
        clean_name = self._clean_go_type_name(type_str)
        
        return GoTypeInfo(
            name=clean_name,
            package=package,
            is_pointer=is_pointer,
            is_interface=is_interface,
            is_channel=is_channel,
            is_slice=is_slice,
            is_map=is_map,
            is_func=is_func,
            is_struct=is_struct,
            is_exported=is_exported,
            channel_direction=channel_direction,
            func_params=func_params,
            func_returns=func_returns,
            is_variadic=is_variadic,
            element_type=element_type,
            key_type=key_type,
            value_type=value_type
        )
    
    def analyze_concurrency(self, node: Dict) -> GoConcurrencyInfo:
        """Analyze Go concurrency patterns and risks."""
        concurrency_info = GoConcurrencyInfo()
        
        # Check for goroutine usage
        if self._has_goroutine_creation(node):
            concurrency_info.has_goroutines = True
            concurrency_info.goroutine_leak_risk = not self._has_proper_goroutine_cleanup(node)
        
        # Analyze channel operations
        concurrency_info.channel_operations = self._extract_channel_operations(node)
        
        # Check for synchronization primitives
        concurrency_info.mutex_usage = self._has_mutex_usage(node)
        concurrency_info.context_usage = self._has_context_usage(node)
        
        # Race condition detection (simplified)
        concurrency_info.race_condition_risk = self._detect_race_condition_risk(node)
        
        return concurrency_info
    
    def analyze_error_handling_from_model(self, model: GoProgramModel, var_name: str) -> GoErrorInfo:
        """Analyze Go error handling patterns using the semantic model."""
        error_data = model.get_error_handling_for(var_name)
        
        if error_data:
            return GoErrorInfo(
                returns_error=error_data.get('returns_error', False),
                error_ignored=error_data.get('ignored', False),
                panic_usage=error_data.get('panic_usage', False),
                recover_usage=error_data.get('recover_usage', False),
                proper_error_wrapping=error_data.get('proper_wrapping', True),
                error_handling_pattern=error_data.get('pattern', 'unknown')
            )
        
        return GoErrorInfo()
    
    def check_interface_implementation(self, type_name: str, interface_name: str) -> bool:
        """Check if a type implements an interface (simplified)."""
        return interface_name in self.interface_implementations.get(type_name, [])
    
    def check_nil_safety(self, node: Dict, type_info: GoTypeInfo) -> bool:
        """Check for potential nil pointer dereferences."""
        if not (type_info.is_pointer or type_info.is_interface or 
                type_info.is_slice or type_info.is_map or type_info.is_channel):
            return True  # Cannot be nil
        
        # Check for nil checks in the surrounding context
        return self._has_nil_check_before_use(node)
    
    # Helper methods for type analysis
    
    def _extract_package_info(self, ast_tree):
        """Extract package information from AST."""
        if isinstance(ast_tree, dict):
            package_name = ast_tree.get('package_name')
            if package_name:
                self.current_package = package_name
                self.package_info[package_name] = ast_tree
    
    def _build_import_graph(self, ast_tree):
        """Build import dependency graph."""
        imports = self._find_imports(ast_tree)
        self.import_graph[self.current_package] = imports
    
    def _analyze_type_declarations(self, ast_tree):
        """Analyze type declarations for interface and struct definitions."""
        # Find all type declarations in the AST
        type_decls = self._find_nodes_by_type(ast_tree, ['type_declaration', 'TypeDecl'])
        for decl in type_decls:
            self._process_type_declaration(decl)
    
    def _analyze_function_declarations(self, ast_tree):
        """Analyze function declarations for signatures and patterns."""
        func_decls = self._find_nodes_by_type(ast_tree, ['function_declaration', 'FuncDecl', 'method_declaration'])
        for decl in func_decls:
            self._process_function_declaration(decl)
    
    def _analyze_variable_declarations(self, ast_tree):
        """Analyze variable declarations and assignments."""
        var_decls = self._find_nodes_by_type(ast_tree, ['variable_declaration', 'VarDecl', 'assignment'])
        for decl in var_decls:
            self._process_variable_declaration(decl)
    
    def _is_interface_type(self, node: Dict, type_str: str) -> bool:
        """Check if type is an interface."""
        return ('interface{' in type_str or 
                node.get('node_type') == 'interface_type' or
                node.get('kind') == 'interface')
    
    def _is_channel_type(self, type_str: str) -> bool:
        """Check if type is a channel."""
        return 'chan' in type_str
    
    def _is_slice_type(self, type_str: str) -> bool:
        """Check if type is a slice."""
        return type_str.startswith('[]') and not self._is_map_type(type_str)
    
    def _is_map_type(self, type_str: str) -> bool:
        """Check if type is a map."""
        return type_str.startswith('map[') or 'map[' in type_str
    
    def _is_func_type(self, node: Dict, type_str: str) -> bool:
        """Check if type is a function."""
        return (type_str.startswith('func(') or 
                node.get('node_type') == 'function_type' or
                node.get('kind') == 'func')
    
    def _is_struct_type(self, node: Dict, type_str: str) -> bool:
        """Check if type is a struct."""
        return (type_str.startswith('struct{') or 
                node.get('node_type') == 'struct_type' or
                node.get('kind') == 'struct')
    
    def _extract_type_package(self, type_str: str) -> Optional[str]:
        """Extract package from qualified type name."""
        if '.' in type_str and not type_str.startswith('*'):
            parts = type_str.split('.')
            if len(parts) >= 2:
                return parts[0]
        return None
    
    def _get_channel_direction(self, type_str: str) -> Optional[str]:
        """Get channel direction (send, receive, bidirectional)."""
        if '<-chan' in type_str:
            return "receive"
        elif 'chan<-' in type_str:
            return "send"
        elif 'chan' in type_str:
            return "bidirectional"
        return None
    
    def _extract_element_type(self, type_str: str) -> Optional[str]:
        """Extract element type from slice or channel."""
        if type_str.startswith('[]'):
            return type_str[2:]
        elif 'chan' in type_str:
            # Extract type after chan
            chan_match = re.search(r'chan\s*(<-\s*)?(\w+)', type_str)
            if chan_match:
                return chan_match.group(2)
        return None
    
    def _extract_map_types(self, type_str: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract key and value types from map."""
        map_match = re.search(r'map\[([^\]]+)\](.+)', type_str)
        if map_match:
            return map_match.group(1), map_match.group(2)
        return None, None
    
    def _analyze_function_signature(self, node: Dict) -> Tuple[List[str], List[str], bool]:
        """Analyze function signature for parameters and returns."""
        params = []
        returns = []
        is_variadic = False
        
        # Extract parameters
        param_list = node.get('parameters', []) or node.get('params', [])
        for param in param_list:
            if isinstance(param, dict):
                param_type = param.get('type', '')
                params.append(param_type)
                if param_type.startswith('...'):
                    is_variadic = True
        
        # Extract return types
        return_list = node.get('returns', []) or node.get('return_types', [])
        for ret in return_list:
            if isinstance(ret, dict):
                returns.append(ret.get('type', ''))
            else:
                returns.append(str(ret))
        
        return params, returns, is_variadic
    
    def _clean_go_type_name(self, type_str: str) -> str:
        """Clean Go type name of modifiers."""
        # Remove pointer marker
        clean = type_str.lstrip('*')
        # Remove channel direction markers
        clean = re.sub(r'<-\s*chan\s*<-|chan\s*<-|<-\s*chan', 'chan', clean)
        # Clean whitespace
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean
    
    def _build_symbol_table(self, ast_tree, model: GoProgramModel):
        """Build symbol table for variables, functions, types."""
        def traverse(node, scope_path="global"):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', '')
            
            # Variable declarations - use correct tree-sitter node names
            if node_type in ['variable_declaration', 'VarDecl', 'assignment', 'short_var_declaration']:
                self._process_variable_declaration(node, model, scope_path)
            
            # Function declarations
            elif node_type in ['function_declaration', 'FuncDecl', 'method_declaration']:
                func_name = self._extract_node_name(node)
                params = self._extract_function_params(node)
                model.functions[func_name] = {
                    'params': params,
                    'returns': self._extract_function_returns(node),
                    'body_node': node,
                    'scope': scope_path
                }
                
                # Mark function parameters as potential taint sources for security rules
                for param in params:
                    if param not in model.data_flow:
                        model.data_flow[param] = []
                    # Add the parameter itself as a taint source
                    model.data_flow[param].append(f'TAINT_SOURCE:{param}')
                    
                    # Create taint flow for function parameters (external input)
                    model.taint_flows.append({
                        'source': param,
                        'sink': 'TBD',  # Will be determined when used in calls
                        'type': 'function_parameter_taint',
                        'taint_type': param
                    })
                
                # Recurse into function body with new scope
                for child in node.get('children', []):
                    traverse(child, f"{scope_path}.{func_name}")
                return
            
            # Recurse into children
            for child in node.get('children', []):
                traverse(child, scope_path)
        
        traverse(ast_tree)
    
    def _build_data_flow_graph(self, ast_tree, model: GoProgramModel):
        """Build data flow graph tracking variable assignments."""
        def traverse(node):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', '')
            
            # Assignment operations - use correct tree-sitter node names
            if node_type in ['assignment', 'short_var_declaration', 'assignment_expression']:
                self._process_assignment(node, model)
            
            # Function calls that return values
            elif node_type in ['call_expression', 'CallExpr']:
                self._process_function_call(node, model)
            
            # Recurse
            for child in node.get('children', []):
                traverse(child)
        
        traverse(ast_tree)
    
    def _build_call_graph(self, ast_tree, model: GoProgramModel):
        """Build call graph of function calls."""
        current_function = None
        
        def traverse(node):
            nonlocal current_function
            
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', '')
            
            # Track current function context
            if node_type in ['function_declaration', 'FuncDecl', 'method_declaration']:
                current_function = self._extract_node_name(node)
                model.calls[current_function] = []
            
            # Record function calls
            elif node_type in ['call_expression', 'CallExpr'] and current_function:
                called_func = self._extract_called_function(node)
                if called_func:
                    model.calls[current_function].append(called_func)
            
            # Recurse
            for child in node.get('children', []):
                traverse(child)
        
        traverse(ast_tree)
    
    def _analyze_goroutines(self, ast_tree, model: GoProgramModel):
        """Analyze goroutine creation and management."""
        def traverse(node):
            if not isinstance(node, dict):
                return
            
            # Look for 'go' statements
            if (node.get('node_type') == 'go_statement' or
                'go ' in str(node.get('source', ''))):
                
                goroutine_info = {
                    'node': node,
                    'line': node.get('line', 0),
                    'called_function': self._extract_goroutine_function(node),
                    'has_context': self._goroutine_has_context(node),
                    'has_cleanup': self._goroutine_has_cleanup(node)
                }
                model.goroutines.append(goroutine_info)
            
            # Recurse
            for child in node.get('children', []):
                traverse(child)
        
        traverse(ast_tree)
    
    def _analyze_channels(self, ast_tree, model: GoProgramModel):
        """Analyze channel declarations and operations."""
        def traverse(node):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', '')
            
            # Channel declarations
            if (node_type in ['variable_declaration', 'VarDecl'] and
                'chan' in str(node.get('type', ''))):
                
                var_name = self._extract_node_name(node)
                model.channels[var_name] = {
                    'type': node.get('type', ''),
                    'direction': self._get_channel_direction(str(node.get('type', ''))),
                    'operations': [],
                    'closed': False
                }
            
            # Channel operations
            elif '<-' in str(node.get('source', '')):
                self._process_channel_operation(node, model)
            
            # Recurse
            for child in node.get('children', []):
                traverse(child)
        
        traverse(ast_tree)
    
    def _analyze_error_handling(self, ast_tree, model: GoProgramModel):
        """Analyze error handling patterns in the code."""
        def traverse(node):
            if not isinstance(node, dict):
                return
            
            # Look for error variables
            if self._is_error_variable(node):
                var_name = self._extract_node_name(node)
                model.errors[var_name] = {
                    'returns_error': True,
                    'checked': self._is_error_checked(node, ast_tree),
                    'ignored': self._is_error_ignored(node, ast_tree),
                    'panic_usage': self._has_panic_in_context(node, ast_tree),
                    'pattern': self._determine_error_pattern_semantic(node, ast_tree)
                }
            
            # Recurse
            for child in node.get('children', []):
                traverse(child)
        
        traverse(ast_tree)
    
    # Concurrency analysis helpers
    
    def _has_goroutine_creation(self, node: Dict) -> bool:
        """Check for 'go' keyword indicating goroutine creation."""
        return self._contains_keyword(node, 'go ')
    
    def _has_proper_goroutine_cleanup(self, node: Dict) -> bool:
        """Check for proper goroutine cleanup patterns."""
        # Look for context.Done(), channels, or waitgroups
        return (self._contains_keyword(node, 'context.Done') or
                self._contains_keyword(node, 'WaitGroup') or
                self._contains_keyword(node, 'sync.WaitGroup'))
    
    def _extract_channel_operations(self, node: Dict) -> List[str]:
        """Extract channel operations (send, receive, close)."""
        operations = []
        source = self._get_node_source(node)
        
        if '<-' in source:
            operations.append('receive')
        if 'close(' in source:
            operations.append('close')
        # Send operations are harder to detect without full parsing
        
        return operations
    
    def _has_mutex_usage(self, node: Dict) -> bool:
        """Check for mutex usage."""
        return (self._contains_keyword(node, 'sync.Mutex') or
                self._contains_keyword(node, 'sync.RWMutex') or
                self._contains_keyword(node, '.Lock()') or
                self._contains_keyword(node, '.Unlock()'))
    
    def _has_context_usage(self, node: Dict) -> bool:
        """Check for context package usage."""
        return (self._contains_keyword(node, 'context.') or
                self._contains_keyword(node, 'Context'))
    
    def _detect_race_condition_risk(self, node: Dict) -> bool:
        """Simple race condition risk detection."""
        # This is a simplified check - real implementation would need data flow analysis
        source = self._get_node_source(node)
        has_shared_state = any(keyword in source for keyword in ['global', 'var ', 'map['])
        has_concurrency = self._has_goroutine_creation(node)
        has_sync = self._has_mutex_usage(node)
        
        return has_shared_state and has_concurrency and not has_sync
    
    # Error handling analysis helpers
    
    def _returns_error_type(self, node: Dict) -> bool:
        """Check if function returns error type."""
        return_types = node.get('return_types', []) or node.get('returns', [])
        return any('error' in str(ret) for ret in return_types)
    
    def _has_ignored_errors(self, node: Dict) -> bool:
        """Check for ignored error return values."""
        source = self._get_node_source(node)
        # Look for patterns like: _, err := or just function calls without error checking
        return '_,' in source.replace(' ', '') or ', _' in source
    
    def _has_panic_calls(self, node: Dict) -> bool:
        """Check for panic() calls."""
        return self._contains_keyword(node, 'panic(')
    
    def _has_recover_calls(self, node: Dict) -> bool:
        """Check for recover() calls."""
        return self._contains_keyword(node, 'recover(')
    
    def _determine_error_pattern(self, node: Dict) -> Optional[str]:
        """Determine the error handling pattern used."""
        source = self._get_node_source(node)
        
        if 'if err != nil' in source:
            return "explicit_check"
        elif self._has_panic_calls(node):
            return "panic"
        elif self._has_ignored_errors(node):
            return "ignored"
        else:
            return "unknown"
    
    def _has_nil_check_before_use(self, node: Dict) -> bool:
        """Check for nil checks before pointer/interface use."""
        # This would require more sophisticated control flow analysis
        source = self._get_node_source(node)
        return 'nil' in source and ('!=' in source or '==' in source)
    
    # Utility methods
    
    def _contains_keyword(self, node: Dict, keyword: str) -> bool:
        """Check if node contains a specific keyword."""
        source = self._get_node_source(node)
        return keyword in source
    
    def _get_node_source(self, node: Dict) -> str:
        """Get source code from node."""
        return node.get('source', '') or node.get('text', '') or str(node)
    
    def _find_imports(self, ast_tree) -> List[str]:
        """Find all import statements."""
        imports = []
        import_nodes = self._find_nodes_by_type(ast_tree, ['import_declaration', 'ImportDecl'])
        for imp_node in import_nodes:
            import_path = imp_node.get('path', '') or imp_node.get('import_path', '')
            if import_path:
                imports.append(import_path.strip('"'))
        return imports
    
    def _find_nodes_by_type(self, ast_tree, node_types):
        """Find all nodes of specified types."""
        found_nodes = []
        
        def traverse(node):
            if isinstance(node, dict):
                node_type = (node.get('type') or node.get('node_type') or 
                           node.get('kind') or node.get('declaration_type'))
                if node_type in node_types:
                    found_nodes.append(node)
                
                for value in node.values():
                    traverse(value)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
        
        traverse(ast_tree)
        return found_nodes
    
    def _process_type_declaration(self, decl):
        """Process a type declaration for the symbol table."""
        pass  # Implementation would build type hierarchy
    
    def _process_function_declaration(self, decl):
        """Process a function declaration for the symbol table.""" 
        pass  # Implementation would record function signatures
    
    def _process_variable_declaration(self, decl, model=None, scope_path="global"):
        """Process a variable declaration for the symbol table."""
        if model is None:
            return  # Skip if no model provided
        
        # Extract variable information and add to model
        if isinstance(decl, dict):
            node_type = decl.get('node_type', '')
            if node_type in ['variable_declaration', 'short_var_declaration']:
                # Extract variable name and type info
                var_name = self._extract_node_name(decl)
                if var_name and var_name != 'unknown':
                    model.symbols[var_name] = {
                        'type': 'unknown',  # Could extract type from AST
                        'scope': scope_path,
                        'decl_node': decl,
                        'line': decl.get('line', 0)
                    }

    def _extract_node_name(self, node):
        """Extract meaningful name from Go AST node."""
        if not isinstance(node, dict):
            return 'root'
        
        # Go specific name fields
        go_name_fields = [
            'name', 'identifier', 'id', 'function_name', 'method_name',
            'type_name', 'package_name', 'variable_name', 'field_name'
        ]
        
        for field in go_name_fields:
            name = node.get(field)
            if name:
                return str(name)
        
        return node.get('type', node.get('node_type', 'unknown'))

    def _extract_function_params(self, node):
        """Extract function parameters from AST node."""
        params = []
        
        if isinstance(node, dict):
            for child in node.get('children', []):
                if child.get('node_type') == 'parameter_list':
                    for param_child in child.get('children', []):
                        if param_child.get('node_type') == 'parameter_declaration':
                            # Extract parameter name from the parameter declaration
                            param_text = param_child.get('source_text', '')
                            if param_text:
                                # Extract the parameter name (first word before the type)
                                import re
                                match = re.match(r'(\w+)', param_text.strip())
                                if match:
                                    param_name = match.group(1)
                                    params.append(param_name)
        
        return params

    def _extract_function_returns(self, node):
        """Extract function return types from AST node."""
        # Simplified implementation
        return []

    def _process_assignment(self, node, model):
        """Process assignment operations for data flow with proper tree-sitter AST parsing."""
        if not isinstance(node, dict):
            return
        
        node_type = node.get('node_type', '')
        
        if node_type in ['assignment', 'short_var_declaration', 'assignment_expression']:
            # For tree-sitter AST, assignments have structure:
            # short_var_declaration:
            #   - children[0]: expression_list (targets) 
            #   - children[1]: := (operator)
            #   - children[2]: expression_list (sources)
            
            children = node.get('children', [])
            if len(children) >= 3:
                target_node = children[0]  # Left side
                source_node = children[2]  # Right side
                
                # Extract target and source text from expression_list nodes
                target_text = target_node.get('source_text', '') if isinstance(target_node, dict) else ''
                source_text = source_node.get('source_text', '') if isinstance(source_node, dict) else ''
                
                if target_text and source_text:
                    # Extract variable names
                    target_vars = self._extract_variables_from_text(target_text)
                    source_vars = self._extract_variables_from_text(source_text)
                    
                    # Track data flow
                    for target_var in target_vars:
                        if target_var not in model.data_flow:
                            model.data_flow[target_var] = []
                        
                        # Add source variables to data flow
                        for source_var in source_vars:
                            if source_var not in model.data_flow[target_var]:
                                model.data_flow[target_var].append(source_var)
                        
                        # Check for taint sources based on the actual source text
                        self._check_assignment_taint(target_var, source_text, model)
            
            # Fallback: also try the old method with source_text on the assignment node itself  
            elif ':=' in node.get('source_text', '') or '=' in node.get('source_text', ''):
                source_text = node.get('source_text', '')
                parts = source_text.split(':=' if ':=' in source_text else '=', 1)
                if len(parts) == 2:
                    target = parts[0].strip()
                    source = parts[1].strip()
                    
                    # Extract variable names
                    target_vars = self._extract_variables_from_text(target)
                    source_vars = self._extract_variables_from_text(source)
                    
                    # Track data flow
                    for target_var in target_vars:
                        if target_var not in model.data_flow:
                            model.data_flow[target_var] = []
                        
                        # Add source variables to data flow
                        for source_var in source_vars:
                            if source_var not in model.data_flow[target_var]:
                                model.data_flow[target_var].append(source_var)
                        
                        # Check for taint sources
                        self._check_assignment_taint(target_var, source, model)

    def _extract_variables_from_text(self, text):
        """Extract variable names from text."""
        import re
        # Find all Go identifiers (variables)
        variables = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text)
        # Filter out Go keywords and common values
        go_keywords = {'if', 'for', 'func', 'var', 'const', 'package', 'import', 'return', 'nil', 'true', 'false'}
        return [var for var in variables if var not in go_keywords]

    def _check_assignment_taint(self, target_var, source_text, model):
        """Check if assignment introduces taint sources."""
        taint_patterns = [
            'os.Args', 'request.', 'http.', 'input', 'param', 'query', 
            'form', 'header', 'cookie', 'user', 'stdin',
            # Go crypto-specific taint sources  
            'make([]byte', 'zero', 'fixed', 'predictable'
        ]
        
        # Check for specific patterns
        for pattern in taint_patterns:
            if pattern.lower() in source_text.lower():
                # Mark as taint source
                if target_var not in model.data_flow:
                    model.data_flow[target_var] = []
                model.data_flow[target_var].append(f"TAINT_SOURCE:{pattern}")
                
                # Create taint flow entry for this assignment
                if not hasattr(model, 'taint_flows'):
                    model.taint_flows = []
                model.taint_flows.append({
                    'source': target_var,
                    'sink': 'TBD',  # Will be filled when we find sinks
                    'type': 'assignment_taint',
                    'taint_type': pattern
                })
                break
        
        # Special case: 'iv' variable name is considered a taint source for IV predictability
        if target_var.lower() == 'iv':
            if target_var not in model.data_flow:
                model.data_flow[target_var] = []
            model.data_flow[target_var].append("TAINT_SOURCE:iv")
            
            if not hasattr(model, 'taint_flows'):
                model.taint_flows = []
            model.taint_flows.append({
                'source': target_var,
                'sink': 'TBD',
                'type': 'assignment_taint', 
                'taint_type': 'iv'
            })

    def _is_error_variable(self, node):
        """Check if node represents an error variable."""
        if not isinstance(node, dict):
            return False
        
        source_text = node.get('source_text', '')
        node_type = node.get('node_type', '')
        
        # Check for error variable patterns
        if node_type == 'identifier' and 'err' in source_text:
            return True
        
        # Check for error type
        if 'error' in source_text:
            return True
            
        return False

    def _is_error_checked(self, node, ast_tree):
        """Check if error variable is properly checked."""
        # Simplified implementation
        return False

    def _process_function_call(self, node, model):
        """Process function calls for data flow."""
        if not isinstance(node, dict):
            return
        
        # Extract function name and arguments for data flow tracking
        func_name = self._extract_called_function(node)
        if func_name:
            # Track function calls in model
            if hasattr(model, 'calls') and func_name not in model.calls:
                model.calls[func_name] = []
            
            # Track arguments for taint analysis
            self._track_function_arguments(node, model, func_name)

    def _extract_called_function(self, node):
        """Extract the called function name from a call expression node."""
        if not isinstance(node, dict):
            return None
        
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '')
        
        if node_type == 'call_expression':
            # For Go, function calls can be:
            # 1. Simple: func()
            # 2. Method: obj.method()
            # 3. Package: pkg.func()
            
            # Try to extract from source_text first
            if source_text:
                import re
                # Match patterns like: exec.Command, cipher.NewCBCEncrypter, etc.
                match = re.match(r'(\w+(?:\.\w+)*)\s*\(', source_text)
                if match:
                    return match.group(1)
            
            # Try to extract from children (selector_expression)
            for child in node.get('children', []):
                if isinstance(child, dict):
                    if child.get('node_type') == 'selector_expression':
                        return self._extract_selector_name(child)
                    elif child.get('node_type') == 'identifier':
                        return child.get('source_text', '')
        
        return None

    def _extract_selector_name(self, node):
        """Extract name from selector expression like package.function."""
        if not isinstance(node, dict):
            return None
        
        source_text = node.get('source_text', '')
        if source_text:
            return source_text
        
        # Build from children: identifier . field_identifier
        parts = []
        for child in node.get('children', []):
            if isinstance(child, dict):
                child_type = child.get('node_type', '')
                if child_type in ['identifier', 'field_identifier']:
                    parts.append(child.get('source_text', ''))
                elif child_type == '.':
                    parts.append('.')
        
        return ''.join(parts)

    def _track_function_arguments(self, node, model, func_name):
        """Track function arguments for taint analysis."""
        # Find argument_list in children
        for child in node.get('children', []):
            if isinstance(child, dict) and child.get('node_type') == 'argument_list':
                # Extract argument expressions for taint tracking
                for arg_child in child.get('children', []):
                    if isinstance(arg_child, dict):
                        arg_type = arg_child.get('node_type', '')
                        if arg_type in ['identifier', 'string_literal', 'interpreted_string_literal']:
                            # Track potential taint sources
                            arg_text = arg_child.get('source_text', '')
                            if arg_text:
                                self._check_taint_flow_to_sink(arg_text, model, func_name)

    def _check_taint_flow_to_sink(self, arg_text, model, func_name):
        """Check if argument flows tainted data to a sink function."""
        # Check if this argument is a variable that has been marked as tainted
        var_name = arg_text.strip()
        
        # Check if variable is in our taint sources
        if var_name in model.data_flow:
            taint_sources = model.data_flow.get(var_name, [])
            has_taint = any(source.startswith('TAINT_SOURCE:') for source in taint_sources)
            
            if has_taint:
                # Update existing taint flows or create new one
                updated_existing = False
                for flow in model.taint_flows:
                    if flow.get('source') == var_name and flow.get('sink') == 'TBD':
                        flow['sink'] = func_name
                        updated_existing = True
                        break
                
                if not updated_existing:
                    # Create new taint flow
                    model.taint_flows.append({
                        'source': var_name,
                        'sink': func_name,
                        'type': 'taint_to_sink'
                    })
        
        # Also check traditional taint indicators
        taint_indicators = [
            'os.Args', 'request.', 'http.', 'user', 'input', 'param',
            'query', 'form', 'header', 'cookie'
        ]
        
        for indicator in taint_indicators:
            if indicator.lower() in arg_text.lower():
                # Mark as potential taint flow
                model.taint_flows.append({
                    'source': arg_text,
                    'sink': func_name,
                    'type': 'potential_taint'
                })
                break

    def check_data_flow_taint(self, node: Dict, check_config: Dict, model: Any) -> List[Dict]:
        """Check for tainted data flow from sources to sinks."""
        findings = []
        
        if not model or not hasattr(model, 'taint_flows'):
            return findings
        
        taint_sources = check_config.get('taint_sources', [])
        sink_functions = check_config.get('sink_functions', [])
        sanitizers = check_config.get('sanitizers', [])
        message = check_config.get('message', 'Tainted data flow detected')
        
        # Check each taint flow
        for flow in model.taint_flows:
            source = flow.get('source', '')
            sink = flow.get('sink', '')
            
            # Check if source matches taint sources
            source_matches = any(ts.lower() in source.lower() for ts in taint_sources)
            # Check if sink matches sink functions  
            sink_matches = any(sf in sink for sf in sink_functions)
            
            if source_matches and sink_matches:
                # Check if sanitized
                is_sanitized = any(san.lower() in source.lower() for san in sanitizers)
                
                if not is_sanitized:
                    findings.append({
                        'type': 'data_flow_taint',
                        'message': f"{message}: {source} -> {sink}",
                        'source_info': source,
                        'sink_info': sink,
                        'line': node.get('line', 0),
                        'severity': 'high'
                    })
        
        return findings


class GoGenericRule:
    """Enhanced Go rule engine with semantic analysis capabilities."""
    
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")
        self.semantic_analyzer = GoSemanticAnalyzer()
        
        # Go specific features
        self.requires_semantic_analysis = self._requires_semantic_analysis()
        self.supported_check_types = self._get_supported_check_types()
        
    def _requires_semantic_analysis(self) -> bool:
        """Check if this rule requires semantic analysis."""
        check_types = []
        if isinstance(self.logic.get('checks'), list):
            check_types = [check.get('type', check.get('check_type')) for check in self.logic.get('checks', [])]
        else:
            check_types = [self.logic.get('type', self.logic.get('check_type'))]
            
        semantic_types = {
            GoCheckType.TYPE_ASSERTION_CHECK.value,
            GoCheckType.INTERFACE_IMPLEMENTATION_CHECK.value,
            GoCheckType.METHOD_SET_CHECK.value,
            GoCheckType.NIL_SAFETY_CHECK.value,
            GoCheckType.ERROR_HANDLING_CHECK.value,
            GoCheckType.GOROUTINE_LEAK_CHECK.value,
            GoCheckType.CHANNEL_OPERATION_CHECK.value,
            GoCheckType.DATA_FLOW_TAINT_CHECK.value
        }
        
        return any(ct in semantic_types for ct in check_types if ct)
    
    def _get_supported_check_types(self) -> Set[str]:
        """Get all supported Go check types."""
        return {check_type.value for check_type in GoCheckType}

    def is_applicable(self, ast_tree):
        """Check if this rule is applicable to the given Go AST tree."""
        if not self.metadata or not self.rule_id:
            return False
            
        # Check for custom functions
        function_name = self._get_custom_function_name()
        if function_name:
            custom_function = self._get_custom_function(function_name)
            if custom_function:
                return True
        
        # Check for matching node types
        required_node_types = self.logic.get("node_types", [])
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
            return len(matching_nodes) > 0
            
        # If no specific requirements, rule is applicable
        return True

    def check(self, ast_tree, filename):
        """Apply all checks defined in the rule metadata to the Go AST."""
        try:
            findings = []
            seen_findings = set()
            
            # Build semantic model if required
            model = None
            if self.requires_semantic_analysis:
                model = self.semantic_analyzer.build_model(ast_tree)
            
            # Apply generic logic checks with semantic model
            generic_findings = self._apply_generic_logic(ast_tree, filename, seen_findings, model)
            findings.extend(generic_findings)
            
            # Apply custom function checks
            custom_function_name = self._get_custom_function_name()
            if custom_function_name:
                custom_function = self._get_custom_function(custom_function_name)
                if custom_function:
                    custom_findings = self._apply_custom_function(ast_tree, filename, custom_function_name, seen_findings)
                    findings.extend(custom_findings)
            
            return findings
        except Exception as e:
            import traceback
            traceback.print_exc()
            return []

    def _apply_generic_logic(self, ast_tree, filename, seen_findings, model=None):
        """Apply generic rule checks with Go semantic awareness."""
        findings = []
        checks = self.logic.get('checks', [])
        
        # Handle both single check and multiple checks
        if not isinstance(checks, list):
            if self._is_valid_go_check(self.logic):
                findings.extend(self._apply_single_check(ast_tree, filename, self.logic, seen_findings, model, is_root_check=True))
        else:
            for check in checks:
                if self._is_valid_go_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, model, is_root_check=False))
        
        return findings

    def _apply_single_check(self, ast_tree, filename, check, seen_findings, model=None, is_root_check=False):
        """Apply a single Go rule check with semantic analysis."""
        findings = []
        check_type = check.get("type") or check.get("check_type")
        
        if check_type not in self.supported_check_types:
            return findings
        
        # Get target nodes
        if is_root_check:
            required_node_types = self.logic.get("node_types", [])
        else:
            required_node_types = check.get("node_types", self.logic.get("node_types", []))
        
        matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types) if required_node_types else [ast_tree]
        
        # Apply check based on type
        for node in matching_nodes:
            node_findings = self._apply_check_by_type(check_type, check, node, filename, seen_findings, model)
            findings.extend(node_findings)
        
        return findings
    
    def _apply_check_by_type(self, check_type, check, node, filename, seen_findings, model=None):
        """Apply specific check type with Go semantic understanding."""
        findings = []
        
        # Map check types to methods - pass model to semantic checks
        check_methods = {
            GoCheckType.REGEX_MATCH.value: lambda c, n, f, s: self._apply_regex_check(c, n, f, s),
            GoCheckType.PROPERTY_COMPARISON.value: lambda c, n, f, s: self._apply_property_comparison_check(c, n, f, s),
            GoCheckType.DATA_FLOW_TAINT_CHECK.value: lambda c, n, f, s: self._apply_data_flow_taint_check(c, n, f, s, model),
            GoCheckType.ERROR_HANDLING_CHECK.value: lambda c, n, f, s: self._apply_error_handling_check(c, n, f, s, model),
            GoCheckType.GOROUTINE_LEAK_CHECK.value: lambda c, n, f, s: self._apply_goroutine_leak_check(c, n, f, s, model),
            GoCheckType.NIL_SAFETY_CHECK.value: lambda c, n, f, s: self._apply_nil_safety_check(c, n, f, s, model),
            # Keep other checks for now
            GoCheckType.TYPE_ASSERTION_CHECK.value: self._apply_type_assertion_check,
            GoCheckType.INTERFACE_IMPLEMENTATION_CHECK.value: self._apply_interface_implementation_check,
            GoCheckType.METHOD_SET_CHECK.value: self._apply_method_set_check,
            GoCheckType.PACKAGE_VISIBILITY_CHECK.value: self._apply_package_visibility_check,
            GoCheckType.CHANNEL_OPERATION_CHECK.value: self._apply_channel_operation_check,
            GoCheckType.DEFER_USAGE_CHECK.value: self._apply_defer_usage_check,
            GoCheckType.PANIC_RECOVER_CHECK.value: self._apply_panic_recover_check,
            GoCheckType.SLICE_BOUNDS_CHECK.value: self._apply_slice_bounds_check,
            GoCheckType.MAP_ACCESS_CHECK.value: self._apply_map_access_check,
            GoCheckType.CONTEXT_PROPAGATION_CHECK.value: self._apply_context_propagation_check,
            GoCheckType.RECEIVER_TYPE_CHECK.value: self._apply_receiver_type_check,
            GoCheckType.IMPORT_USAGE_CHECK.value: self._apply_import_usage_check,
            GoCheckType.EXPORTED_API_CHECK.value: self._apply_exported_api_check
        }
        
        check_method = check_methods.get(check_type)
        if check_method:
            # Call with appropriate signature based on whether model is needed
            try:
                if check_type in [GoCheckType.DATA_FLOW_TAINT_CHECK.value, 
                                 GoCheckType.ERROR_HANDLING_CHECK.value,
                                 GoCheckType.GOROUTINE_LEAK_CHECK.value,
                                 GoCheckType.NIL_SAFETY_CHECK.value]:
                    findings = check_method(check, node, filename, seen_findings)
                else:
                    findings = check_method(check, node, filename, seen_findings)
            except Exception as e:
                print(f"Check {check_type} failed: {e}")
        
        return findings

    def _apply_check_by_type(self, check_type, check, node, filename, seen_findings, model=None):
        """Apply specific check type with Go semantic understanding."""
        findings = []
        
        # Map check types to methods - pass model to semantic checks
        check_methods = {
            GoCheckType.REGEX_MATCH.value: lambda c, n, f, s: self._apply_regex_check(c, n, f, s),
            GoCheckType.PROPERTY_COMPARISON.value: lambda c, n, f, s: self._apply_property_comparison_check(c, n, f, s),
            GoCheckType.DATA_FLOW_TAINT_CHECK.value: lambda c, n, f, s: self._apply_data_flow_taint_check(c, n, f, s, model),
            GoCheckType.ERROR_HANDLING_CHECK.value: lambda c, n, f, s: self._apply_error_handling_check(c, n, f, s, model),
            GoCheckType.GOROUTINE_LEAK_CHECK.value: lambda c, n, f, s: self._apply_goroutine_leak_check(c, n, f, s, model),
            GoCheckType.NIL_SAFETY_CHECK.value: lambda c, n, f, s: self._apply_nil_safety_check(c, n, f, s, model),
            # Keep other checks for now
            GoCheckType.TYPE_ASSERTION_CHECK.value: self._apply_type_assertion_check,
            GoCheckType.INTERFACE_IMPLEMENTATION_CHECK.value: self._apply_interface_implementation_check,
            GoCheckType.METHOD_SET_CHECK.value: self._apply_method_set_check,
            GoCheckType.PACKAGE_VISIBILITY_CHECK.value: self._apply_package_visibility_check,
            GoCheckType.CHANNEL_OPERATION_CHECK.value: self._apply_channel_operation_check,
            GoCheckType.DEFER_USAGE_CHECK.value: self._apply_defer_usage_check,
            GoCheckType.PANIC_RECOVER_CHECK.value: self._apply_panic_recover_check,
            GoCheckType.SLICE_BOUNDS_CHECK.value: self._apply_slice_bounds_check,
            GoCheckType.MAP_ACCESS_CHECK.value: self._apply_map_access_check,
            GoCheckType.CONTEXT_PROPAGATION_CHECK.value: self._apply_context_propagation_check,
            GoCheckType.RECEIVER_TYPE_CHECK.value: self._apply_receiver_type_check,
            GoCheckType.IMPORT_USAGE_CHECK.value: self._apply_import_usage_check,
            GoCheckType.EXPORTED_API_CHECK.value: self._apply_exported_api_check
        }
        
        check_method = check_methods.get(check_type)
        if check_method:
            # Call with appropriate signature based on whether model is needed
            try:
                if check_type in [GoCheckType.DATA_FLOW_TAINT_CHECK.value, 
                                 GoCheckType.ERROR_HANDLING_CHECK.value,
                                 GoCheckType.GOROUTINE_LEAK_CHECK.value,
                                 GoCheckType.NIL_SAFETY_CHECK.value]:
                    findings = check_method(check, node, filename, seen_findings)
                else:
                    findings = check_method(check, node, filename, seen_findings)
            except Exception as e:
                print(f"Check {check_type} failed: {e}")
        
        return findings

    def _apply_nil_safety_check(self, check, node, filename, seen_findings, model=None):
        """Check for nil safety violations using semantic model."""
        findings = []
        
        if not model:
            return findings
        
        # Check for potential nil dereferences in the semantic model
        for var_name, symbol_info in model.symbols.items():
            var_type = symbol_info.get('type', '')
            
            # Check if variable can be nil (pointer, interface, slice, map, channel)
            can_be_nil = ('*' in var_type or 'interface' in var_type or 
                         '[]' in var_type or 'map[' in var_type or 'chan' in var_type)
            
            if can_be_nil:
                # Check if variable is used without nil check
                # This is a simplified check - real implementation would need control flow analysis
                var_line = symbol_info.get('line', 0)
                
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=var_name,
                    property_path=["nil_safety"],
                    value="potential_nil_dereference",
                    message=f"{check.get('message', 'Nil safety violation')}: Variable '{var_name}' of type '{var_type}' may be nil",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, var_line, var_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    # Go-specific check implementations
    
    def _apply_nil_safety_check(self, check, node, filename, seen_findings):
        """Check for nil safety violations."""
        findings = []
        
        type_info = self.semantic_analyzer.analyze_type(node)
        
        if not self.semantic_analyzer.check_nil_safety(node, type_info):
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["nil_safety"],
                value="potential_nil_dereference",
                message=f"{check.get('message', 'Nil safety violation')}: Potential nil pointer dereference",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), "nil_safety")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_error_handling_check(self, check, node, filename, seen_findings, model=None):
        """Check Go error handling patterns using semantic model."""
        findings = []
        
        if not model:
            return findings
        
        error_pattern = check.get("error_pattern")
        
        # Query the semantic model instead of parsing text
        for var_name, error_data in model.errors.items():
            violation = False
            violation_reason = ""
            
            if error_pattern == "no_ignored_errors" and error_data.get('ignored', False):
                violation = True
                violation_reason = f"Error '{var_name}' return value is ignored"
            elif error_pattern == "explicit_error_check" and not error_data.get('checked', False):
                violation = True
                violation_reason = f"Error '{var_name}' should be explicitly checked"
            elif error_pattern == "no_panic_in_library" and error_data.get('panic_usage', False):
                violation = True
                violation_reason = f"Library code should not use panic (related to error '{var_name}')"
            
            if violation:
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=var_name,
                    property_path=["error_handling"],
                    value=error_data.get('pattern', 'unknown'),
                    message=f"{check.get('message', 'Error handling violation')}: {violation_reason}",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), var_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_goroutine_leak_check(self, check, node, filename, seen_findings, model=None):
        """Check for potential goroutine leaks using semantic model."""
        findings = []
        
        if not model:
            return findings
        
        # Check each goroutine in the model
        for i, goroutine in enumerate(model.goroutines):
            if not goroutine.get('has_context', False) and not goroutine.get('has_cleanup', False):
                # This goroutine has no cleanup mechanism
                called_func = goroutine.get('called_function', 'unknown')
                
                # Check if the called function has any termination conditions
                if called_func in model.functions:
                    func_info = model.functions[called_func]
                    # Simple heuristic: if function doesn't take context and has infinite loops
                    params = func_info.get('params', [])
                    has_context_param = any('context.Context' in str(p) for p in params)
                    
                    if not has_context_param:
                        violation_reason = f"Goroutine calling '{called_func}' may leak - no context or cleanup mechanism"
                        finding = self._make_finding(
                            filename=filename,
                            node_type=goroutine['node'].get('node_type', 'unknown'),
                            node_name=called_func,
                            property_path=["concurrency"],
                            value="goroutine_leak_risk",
                            message=f"{check.get('message', 'Goroutine leak')}: {violation_reason}",
                            node=goroutine['node']
                        )
                        
                        unique_key = (self.rule_id, filename, goroutine.get('line', 0), called_func)
                        if unique_key not in seen_findings:
                            seen_findings.add(unique_key)
                            findings.append(finding)
        
        return findings

    def _apply_interface_implementation_check(self, check, node, filename, seen_findings):
        """Check interface implementation compliance."""
        findings = []
        
        expected_interface = check.get("expected_interface")
        type_info = self.semantic_analyzer.analyze_type(node)
        
        if expected_interface and not self.semantic_analyzer.check_interface_implementation(type_info.name, expected_interface):
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["interface_implementation"],
                value=f"missing_{expected_interface}",
                message=f"{check.get('message', 'Interface implementation')}: Type does not implement {expected_interface}",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), expected_interface)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_channel_operation_check(self, check, node, filename, seen_findings):
        """Check channel operation safety."""
        findings = []
        
        concurrency_info = self.semantic_analyzer.analyze_concurrency(node)
        channel_rule = check.get("channel_rule")
        
        if channel_rule == "close_sender_only" and "close" in concurrency_info.channel_operations:
            # This would require more sophisticated analysis to check if the closer is the sender
            pass
        elif channel_rule == "range_over_channel" and "receive" in concurrency_info.channel_operations:
            # Check if using range instead of explicit receive loop
            source = self.semantic_analyzer._get_node_source(node)
            if 'for {' in source and '<-' in source and 'range' not in source:
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=["channel_operation"],
                    value="explicit_receive_loop",
                    message=f"{check.get('message', 'Channel operation')}: Consider using range over channel",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "range_over_channel")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_package_visibility_check(self, check, node, filename, seen_findings):
        """Check package visibility rules."""
        findings = []
        
        type_info = self.semantic_analyzer.analyze_type(node)
        visibility_rule = check.get("visibility_rule")
        
        if visibility_rule == "no_exported_internals" and type_info.is_exported:
            # Check if this is in an internal package but exported
            if 'internal' in filename.lower() or '/internal/' in filename:
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=["visibility"],
                    value="exported_internal",
                    message=f"{check.get('message', 'Package visibility')}: Internal types should not be exported",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "exported_internal")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    # Enhanced regex check for Go
    def _apply_regex_check(self, check, node, filename, seen_findings):
        """Enhanced regex check with Go context awareness."""
        findings = []
        patterns = check.get("patterns", [])
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
        
        exclude_patterns = check.get("exclude_patterns", [])
        property_path = check.get("property_path")
        
        if not patterns or not property_path:
            return findings
        
        value = self._get_property(node, property_path)
        if not isinstance(value, str):
            return findings
            
        base_line = self._extract_line_number(node)
        
        for pattern in patterns:
            for match in re.finditer(pattern, value, re.MULTILINE | re.DOTALL):
                match_text = match.group(0).strip()
                
                # Check exclusions
                if any(re.search(exclude_pattern, match_text, re.MULTILINE | re.DOTALL) 
                       for exclude_pattern in exclude_patterns):
                    continue
                
                # Enhanced Go identifier extraction
                identifier = self._extract_go_identifier(match_text, pattern)
                
                lines_before_match = value[:match.start()].count('\n')
                actual_line = base_line + lines_before_match
                
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=property_path,
                    value=match_text,
                    message=f"Identifier '{identifier}': {check.get('message', 'Pattern match')}",
                    node=node
                )
                finding["line"] = actual_line
                
                unique_key = (self.rule_id, filename, actual_line, match.start(), pattern)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_type_assertion_check(self, check, node, filename, seen_findings):
        """Check type assertion safety - detect unchecked type assertions."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Look for type assertions: variable.(*Type) or variable.(Type)
        if node_type in ['Assignment', 'AssignStmt'] or 'assertion' in source:
            # Pattern: x := value.(*Type) - unsafe, no ok check
            if '.(' in source and ')' in source and ', ok' not in source:
                # Extract the assertion part
                assertion_match = re.search(r'\.(\*?\w+)', source)
                if assertion_match:
                    asserted_type = assertion_match.group(1)
                    
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=self._extract_node_name(node),
                        property_path=["type_assertion"],
                        value=f"unchecked_assertion_{asserted_type}",
                        message=f"{check.get('message', 'Unsafe type assertion')}: Use comma ok idiom - val, ok := x.({asserted_type})",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), asserted_type)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings
    
    def _apply_method_set_check(self, check, node, filename, seen_findings):
        """Check method set compliance - pointer vs value receivers."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        
        # Check for method definitions with mixed receiver types
        if node_type in ['FuncDecl', 'MethodDecl'] and 'func (' in source:
            # Extract receiver type
            receiver_match = re.search(r'func\s*\(\s*\w+\s+(\*?)(\w+)\s*\)', source)
            if receiver_match:
                is_pointer = bool(receiver_match.group(1))
                type_name = receiver_match.group(2)
                
                # Check for inconsistent receiver types (would need type analysis)
                # For now, flag methods on value receivers that modify state
                if not is_pointer and ('=' in source and 'return' not in source.split('=')[0]):
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=self._extract_node_name(node),
                        property_path=["receiver_type"],
                        value="value_receiver_mutation",
                        message=f"{check.get('message', 'Method set violation')}: Use pointer receiver (*{type_name}) for methods that modify state",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), type_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings
    
    def _apply_defer_usage_check(self, check, node, filename, seen_findings):
        """Check defer statement usage patterns - resource cleanup and order."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check for defer patterns
        if 'defer' in source:
            # 1. Check for defer in loops (potential resource leak)
            if node_type in ['ForStmt', 'RangeStmt'] and 'defer' in source:
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=self._extract_node_name(node),
                    property_path=["defer_usage"],
                    value="defer_in_loop",
                    message=f"{check.get('message', 'Defer usage issue')}: Defer in loop may accumulate resources - consider moving to separate function",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "defer_in_loop")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
            
            # 2. Check for missing defer after resource allocation
            elif any(pattern in source for pattern in ['os.Open', 'sql.Open', 'http.Get']) and 'defer' not in source:
                resource_pattern = next(p for p in ['os.Open', 'sql.Open', 'http.Get'] if p in source)
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=self._extract_node_name(node),
                    property_path=["defer_usage"],
                    value="missing_defer",
                    message=f"{check.get('message', 'Resource leak')}: {resource_pattern} should be followed by defer Close()",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "missing_defer")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings
    
    def _apply_panic_recover_check(self, check, node, filename, seen_findings):
        """Check panic/recover usage patterns - appropriate use cases."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check for panic usage
        if 'panic(' in source:
            # 1. Check for panic in library code (should return errors instead)
            if 'main' not in filename and node_type == 'FuncDecl':
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=self._extract_node_name(node),
                    property_path=["panic_usage"],
                    value="panic_in_library",
                    message=f"{check.get('message', 'Inappropriate panic')}: Library code should return errors, not panic",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "panic_in_library")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        # Check for naked recover (recover not in defer)
        if 'recover()' in source and 'defer' not in source:
            finding = self._make_finding(
                filename=filename,
                node_type=node_type,
                node_name=self._extract_node_name(node),
                property_path=["recover_usage"],
                value="naked_recover",
                message=f"{check.get('message', 'Invalid recover')}: recover() only works inside deferred functions",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), "naked_recover")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings
    
    def _apply_slice_bounds_check(self, check, node, filename, seen_findings):
        """Check slice bounds safety - detect potential out-of-bounds access."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Look for slice access patterns that might be unsafe
        if '[' in source and ']' in source:
            # Pattern: slice[index] without bounds checking
            slice_access_patterns = re.findall(r'(\w+)\[([^\]]+)\]', source)
            for slice_name, index_expr in slice_access_patterns:
                # Check if there's a bounds check nearby
                if f'len({slice_name})' not in source and 'cap(' not in source:
                    # Look for potential constant index that might be out of bounds
                    if index_expr.isdigit() and int(index_expr) > 0:
                        finding = self._make_finding(
                            filename=filename,
                            node_type=node_type,
                            node_name=self._extract_node_name(node),
                            property_path=["slice_bounds"],
                            value=f"unchecked_access_{slice_name}_{index_expr}",
                            message=f"{check.get('message', 'Slice bounds')}: Check slice bounds before accessing {slice_name}[{index_expr}] - use if {index_expr} < len({slice_name})",
                            node=node
                        )
                        
                        unique_key = (self.rule_id, filename, finding.get('line', 0), slice_name, index_expr)
                        if unique_key not in seen_findings:
                            seen_findings.add(unique_key)
                            findings.append(finding)
        
        return findings
    
    def _apply_map_access_check(self, check, node, filename, seen_findings):
        """Check map access safety - detect unchecked map access."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Look for map access without existence check
        if '[' in source and ']' in source and ':=' in source:
            # Pattern: value := myMap[key] - should be value, ok := myMap[key]
            map_access_pattern = re.search(r'(\w+)\s*:=\s*(\w+)\[([^\]]+)\]', source)
            if map_access_pattern and ', ok' not in source:
                var_name = map_access_pattern.group(1)
                map_name = map_access_pattern.group(2)
                key_expr = map_access_pattern.group(3)
                
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=self._extract_node_name(node),
                    property_path=["map_access"],
                    value=f"unchecked_map_access_{map_name}",
                    message=f"{check.get('message', 'Map access')}: Use comma ok idiom - {var_name}, ok := {map_name}[{key_expr}]",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), map_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings
    
    def _apply_context_propagation_check(self, check, node, filename, seen_findings):
        """Check context propagation patterns - ensure context is passed through call chains."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check for functions that should accept context
        if node_type == 'FuncDecl' and 'func' in source:
            # Function that makes HTTP requests or DB calls should accept context
            if any(pattern in source for pattern in ['http.Get', 'http.Post', 'db.Query', 'sql.Query']):
                # Check if function signature includes context.Context
                if 'context.Context' not in source and 'ctx' not in source:
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=self._extract_node_name(node),
                        property_path=["context_propagation"],
                        value="missing_context_parameter",
                        message=f"{check.get('message', 'Context propagation')}: Function should accept context.Context as first parameter for cancellation",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), "missing_context")
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        # Check for context.Background() in non-main functions
        elif 'context.Background()' in source and 'main' not in source:
            finding = self._make_finding(
                filename=filename,
                node_type=node_type,
                node_name=self._extract_node_name(node),
                property_path=["context_propagation"],
                value="context_background_misuse",
                message=f"{check.get('message', 'Context misuse')}: Use context from caller instead of context.Background()",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), "background_misuse")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings
    
    def _apply_receiver_type_check(self, check, node, filename, seen_findings):
        """Check receiver type patterns - consistent pointer/value receiver usage."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check method receiver consistency for the same type
        if node_type == 'FuncDecl' and 'func (' in source:
            # Extract receiver info
            receiver_match = re.search(r'func\s*\(\s*\w+\s+(\*?)(\w+)\s*\)', source)
            if receiver_match:
                is_pointer = bool(receiver_match.group(1))
                type_name = receiver_match.group(2)
                
                # Simple heuristic: large structs should use pointer receivers
                # This would ideally be enhanced with type size analysis
                if not is_pointer and check.get('prefer_pointer_receivers', False):
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=self._extract_node_name(node),
                        property_path=["receiver_type"],
                        value=f"value_receiver_{type_name}",
                        message=f"{check.get('message', 'Receiver type')}: Consider pointer receiver (*{type_name}) for better performance",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), type_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings
    
    def _apply_import_usage_check(self, check, node, filename, seen_findings):
        """Check import usage patterns - unused imports, security issues."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check for potentially dangerous imports
        dangerous_imports = check.get('dangerous_imports', [
            'unsafe', 'syscall', 'reflect'
        ])
        
        if node_type == 'ImportSpec' or 'import' in source:
            for dangerous in dangerous_imports:
                if f'"{dangerous}"' in source or f"'{dangerous}'" in source:
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=dangerous,
                        property_path=["import_usage"],
                        value=f"dangerous_import_{dangerous}",
                        message=f"{check.get('message', 'Dangerous import')}: Import '{dangerous}' should be used carefully - review for security implications",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), dangerous)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        # Check for dot imports (import . "package")
        if 'import .' in source:
            dot_import_match = re.search(r'import\s+\.\s+["\']([^"\']+)["\']', source)
            if dot_import_match:
                package_name = dot_import_match.group(1)
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=package_name,
                    property_path=["import_usage"],
                    value=f"dot_import_{package_name}",
                    message=f"{check.get('message', 'Dot import')}: Avoid dot imports - they pollute namespace. Use explicit import alias instead",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "dot_import")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings
    
    def _apply_exported_api_check(self, check, node, filename, seen_findings):
        """Check exported API design - naming conventions, documentation."""
        findings = []
        
        if not isinstance(node, dict):
            return findings
            
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        
        # Check for exported functions/types without documentation
        if node_type in ['FuncDecl', 'TypeDecl'] and source:
            # Check if identifier is exported (starts with uppercase)
            name_match = re.search(r'(?:func|type)\s+([A-Z]\w*)', source)
            if name_match:
                exported_name = name_match.group(1)
                
                # Simple check: look for comment above (would need better AST analysis)
                if not source.strip().startswith('//'):
                    finding = self._make_finding(
                        filename=filename,
                        node_type=node_type,
                        node_name=exported_name,
                        property_path=["exported_api"],
                        value=f"undocumented_{exported_name}",
                        message=f"{check.get('message', 'API documentation')}: Exported {node_type.lower()} '{exported_name}' should have documentation comment",
                        node=node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), exported_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        # Check for exported functions that return interface{} (bad API design)
        if 'func' in source and 'interface{}' in source:
            func_match = re.search(r'func\s+([A-Z]\w*)', source)
            if func_match:
                func_name = func_match.group(1)
                finding = self._make_finding(
                    filename=filename,
                    node_type=node_type,
                    node_name=func_name,
                    property_path=["exported_api"],
                    value=f"interface_any_{func_name}",
                    message=f"{check.get('message', 'API design')}: Avoid interface{{}} in public APIs - use specific types or generics",
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "interface_any")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings
    
    def _apply_data_flow_taint_check(self, check, node, filename, seen_findings, model=None):
        """Check data flow taint analysis using semantic model."""
        findings = []
        
        if not model:
            return findings
        
        taint_sources = set(check.get("taint_sources", []))
        sink_functions = set(check.get("sink_functions", []))
        sanitizers = set(check.get("sanitizers", []))
        
        # Look for function calls that are sinks
        def traverse(node):
            if isinstance(node, dict):
                if node.get('node_type') in ['call_expression', 'CallExpr']:
                    called_func = self._extract_called_function(node)
                    if called_func in sink_functions:
                        # Check if any arguments are tainted
                        # In tree-sitter, arguments are in argument_list child
                        args = []
                        for child in node.get('children', []):
                            if child.get('node_type') == 'argument_list':
                                # Extract identifier and binary_expression arguments from argument_list
                                for arg_child in child.get('children', []):
                                    if arg_child.get('node_type') == 'identifier':
                                        args.append(arg_child)
                                    elif arg_child.get('node_type') == 'binary_expression':
                                        # Extract identifiers from binary expressions (e.g., string concatenation)
                                        binary_identifiers = self._extract_identifiers_from_binary_expr(arg_child)
                                        args.extend(binary_identifiers)
                        
                        for i, arg in enumerate(args):
                            arg_name = self._extract_variable_from_arg(arg)
                            if arg_name and model.is_tainted(arg_name, taint_sources):
                                # Check if there's a sanitizer in the path
                                origins = model.trace_origin(arg_name)
                                if not any(origin in sanitizers for origin in origins):
                                    violation_reason = f"Tainted data '{arg_name}' flows to sink '{called_func}' without sanitization"
                                    finding = self._make_finding(
                                        filename=filename,
                                        node_type=node.get('node_type', 'unknown'),
                                        node_name=called_func,
                                        property_path=["data_flow"],
                                        value=f"taint:{arg_name}->{called_func}",
                                        message=f"{check.get('message', 'Data flow violation')}: {violation_reason}",
                                        node=node
                                    )
                                    
                                    unique_key = (self.rule_id, filename, finding.get('line', 0), arg_name, called_func)
                                    if unique_key not in seen_findings:
                                        seen_findings.add(unique_key)
                                        findings.append(finding)
                
                for child in node.get('children', []):
                    traverse(child)
        
        traverse(node)
        return findings

    def _extract_variable_from_arg(self, arg):
        """Extract variable name from function argument."""
        if not isinstance(arg, dict):
            return None
        
        # Try different ways to extract the variable name
        # 1. Direct identifier
        if arg.get('node_type') == 'identifier':
            return arg.get('source_text', '')
        
        # 2. From source_text (for simple expressions)
        source_text = arg.get('source_text', '')
        if source_text:
            import re
            # Extract simple identifier
            match = re.match(r'^(\w+)', source_text.strip())
            if match:
                return match.group(1)
        
        # 3. Look in children for identifier
        for child in arg.get('children', []):
            if isinstance(child, dict) and child.get('node_type') == 'identifier':
                return child.get('source_text', '')
        
        return None

    def _extract_identifiers_from_binary_expr(self, binary_expr):
        """Extract all identifier nodes from a binary expression tree."""
        identifiers = []
        
        if not isinstance(binary_expr, dict):
            return identifiers
        
        def traverse_binary(node):
            if isinstance(node, dict):
                if node.get('node_type') == 'identifier':
                    identifiers.append(node)
                
                # Recursively check children
                for child in node.get('children', []):
                    traverse_binary(child)
        
        traverse_binary(binary_expr)
        return identifiers

    # Utility methods
    
    def _extract_go_identifier(self, match_text, pattern):
        """Extract Go identifier with package support."""
        # Handle package-qualified identifiers
        package_match = re.search(r'(\w+\.)*(\w+)', match_text)
        if package_match:
            return package_match.group(0)
        
        # Fallback to simple identifier
        var_match = re.search(r'\b(\w+)\b', match_text)
        return var_match.group(1) if var_match else 'unknown'

    def _is_valid_go_check(self, check):
        """Check if the given check is a valid Go check type."""
        check_type = check.get("type") or check.get("check_type")
        return check_type in self.supported_check_types

    def _apply_property_comparison_check(self, check, node, filename, seen_findings):
        """Apply property comparison with Go semantic awareness."""
        findings = []
        property_path = check.get("property_path")
        operator = check.get("operator")
        value = check.get("value")
        
        node_value = self._get_property(node, property_path)
        if operator and node_value is not None:
            if self._evaluate_go_comparison(node_value, operator, value):
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=property_path,
                    value=node_value,
                    message=check.get('message', self.message),
                    node=node
                )
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        return findings

    def _evaluate_go_comparison(self, value, operator, target):
        """Evaluate comparison with Go type awareness."""
        # Go specific operators
        if operator == "is_channel_type":
            return 'chan' in str(value)
        elif operator == "is_interface_type":
            return 'interface{' in str(value) or str(value) == 'interface{}'
        elif operator == "is_goroutine_call":
            return str(value).strip().startswith('go ')
        elif operator == "is_error_type":
            return str(value) == 'error'
        elif operator == "is_exported":
            name = str(value)
            return name and name[0].isupper()
        elif operator == "is_slice_type":
            return str(value).startswith('[]')
        elif operator == "is_map_type":
            return str(value).startswith('map[')
        elif operator == "has_defer":
            return 'defer' in str(value)
        elif operator == "has_panic":
            return 'panic(' in str(value)
        elif operator == "has_recover":
            return 'recover(' in str(value)
        else:
            # Fall back to base evaluation
            return self._evaluate_comparison_base(value, operator, target)

    def _evaluate_comparison_base(self, value, operator, target):
        """Base comparison evaluation."""
        if value is None:
            return False
        
        if operator == "equals":
            return value == target
        elif operator == "strict_equals":
            return value is target
        elif operator == "contains":
            return str(target) in str(value)
        elif operator == "startswith":
            return str(value).startswith(str(target))
        elif operator == "endswith":
            return str(value).endswith(str(target))
        elif operator == "regex_match":
            try:
                return bool(re.search(str(target), str(value)))
            except re.error:
                return False
        elif operator in [">", "<", ">=", "<="]:
            try:
                val = float(value)
                tgt = float(target)
                if operator == ">": return val > tgt
                if operator == "<": return val < tgt
                if operator == ">=": return val >= tgt
                if operator == "<=": return val <= tgt
            except (ValueError, TypeError):
                return False
        
        return False

    # Core utility methods (adapted from C engine)
    def _get_custom_function_name(self):
        """Extract custom function name from rule metadata."""
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check.get('function')
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        return None

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
        """Apply custom rule functions with Go context."""
        findings = []
        custom_fn = getattr(logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        
        # Enhanced custom function support for Go
        try:
            import inspect
            sig = inspect.signature(custom_fn)
            params = list(sig.parameters.keys())
            
            # Check if function accepts semantic analyzer
            if len(params) >= 3 and 'semantic_analyzer' in params:
                custom_findings = custom_fn(ast_tree, filename, self.semantic_analyzer)
                if isinstance(custom_findings, list):
                    findings.extend(custom_findings)
                return findings
            elif len(params) >= 2 and 'ast_tree' in params and 'filename' in params:
                custom_findings = custom_fn(ast_tree, filename)
                if isinstance(custom_findings, list):
                    findings.extend(custom_findings)
                return findings
        except Exception:
            pass
        
        # Fallback to node-based approach
        def visit_node(node):
            if custom_fn(node):
                line_number = self._extract_line_number(node)
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                
                source = node.get('source', '') or node.get('text', '')
                unique_key = (self.rule_id, filename, line_number, source)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        def traverse(node):
            if isinstance(node, dict):
                visit_node(node)
                for v in node.values():
                    traverse(v)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
        
        traverse(ast_tree)
        return findings

    def _get_custom_function(self, function_name):
        """Get custom function from logic_implementations module."""
        if not function_name:
            return None
        if hasattr(logic_implementations, function_name):
            func = getattr(logic_implementations, function_name)
            if callable(func):
                return func
        return None

    def _find_nodes_by_type(self, ast_tree, node_types):
        """Find all nodes in the AST that match Go node types using deep recursive traversal."""
        found_nodes = []
        
        # Go specific node types
        go_node_types = {
            'package_declaration', 'import_declaration', 'type_declaration',
            'function_declaration', 'method_declaration', 'variable_declaration',
            'const_declaration', 'interface_type', 'struct_type', 'channel_type',
            'slice_type', 'map_type', 'function_type', 'array_type',
            'go_statement', 'defer_statement', 'select_statement', 'type_switch',
            'range_statement', 'if_statement', 'for_statement', 'switch_statement',
            'call_expression', 'assignment', 'assignment_expression', 'short_var_declaration',
            'selector_expression', 'argument_list', 'identifier', 'string_literal',
            'interpreted_string_literal', 'binary_expression', 'unary_expression'
        }
        
        # Include Go node types in search
        extended_node_types = set(node_types)
        if any(nt in go_node_types for nt in node_types):
            extended_node_types.update(node_types)
        
        def traverse(node, depth=0, max_depth=100):
            if depth > max_depth or not isinstance(node, (dict, list)):
                return
            
            if isinstance(node, dict):
                node_type = (node.get('type') or node.get('node_type') or 
                           node.get('kind') or node.get('declaration_type'))
                
                # If we're looking for all nodes or this node matches
                if "*" in node_types or node_type in extended_node_types:
                    found_nodes.append(node)
                
                # Always continue traversing to find nested nodes
                # Traverse children array if it exists (tree-sitter structure)
                if 'children' in node:
                    for child in node.get('children', []):
                        traverse(child, depth + 1, max_depth)
                        
                # Also traverse all other values
                for key, value in node.items():
                    if key != 'children':  # Avoid double processing children
                        traverse(value, depth + 1, max_depth)
                        
            elif isinstance(node, list):
                for item in node:
                    traverse(item, depth + 1, max_depth)
        
        traverse(ast_tree)
        return found_nodes

    def _get_property(self, node, property_path):
        """Navigate through nested properties in Go AST node."""
        current = node
        for part in property_path:
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    def _extract_line_number(self, node):
        """Extract line number from Go AST node."""
        if not isinstance(node, dict):
            return 0
        
        line_fields = ['line', 'lineno', 'line_number', 'start_line', 'row']
        for field in line_fields:
            line = node.get(field)
            if isinstance(line, int) and line > 0:
                return line
        
        # Try location information
        loc = node.get('location', {}) or node.get('loc', {}) or node.get('position', {})
        if isinstance(loc, dict):
            return loc.get('line', loc.get('start_line', loc.get('row', 0)))
        
        return 0

    def _make_finding(self, filename, node_type, node_name, property_path, value, message=None, node=None):
        """Create a finding dictionary with Go specific information."""
        finding = {
            "rule_id": self.rule_id,
            "message": message or self.message,
            "node": f"{node_type}.{node_name}",
            "file": filename,
            "property_path": property_path,
            "value": value,
            "status": "violation"
        }
        
        if node:
            finding["line"] = self._extract_line_number(node)
            
            # Add Go specific context
            if node_type in ['package_declaration']:
                finding["context"] = "package_definition"
            elif node_type in ['function_declaration', 'method_declaration']:
                finding["context"] = "function_definition"
            elif node_type in ['interface_type', 'struct_type']:
                finding["context"] = "type_definition"
            elif node_type in ['go_statement']:
                finding["context"] = "goroutine_creation"
            elif node_type in ['defer_statement']:
                finding["context"] = "defer_statement"
        
        # Add severity information
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        
        return finding

    def _extract_node_name(self, node):
        """Extract meaningful name from Go AST node."""
        if not isinstance(node, dict):
            return 'root'
        
        # Go specific name fields
        go_name_fields = [
            'name', 'identifier', 'id', 'function_name', 'method_name',
            'type_name', 'package_name', 'variable_name', 'field_name'
        ]
        
        for field in go_name_fields:
            name = node.get(field)
            if name:
                return str(name)
        
        return node.get('type', node.get('node_type', 'unknown'))

    def _extract_called_function(self, node):
        """Extract the called function name from a call expression node."""
        if not isinstance(node, dict):
            return None
        
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '')
        
        if node_type == 'call_expression':
            # For Go, function calls can be:
            # 1. Simple: func()
            # 2. Method: obj.method()
            # 3. Package: pkg.func()
            
            # Try to extract from source_text first
            if source_text:
                import re
                # Match patterns like: exec.Command, cipher.NewCBCEncrypter, etc.
                match = re.match(r'(\w+(?:\.\w+)*)\s*\(', source_text)
                if match:
                    return match.group(1)
            
            # Try to extract from children (selector_expression)
            for child in node.get('children', []):
                if isinstance(child, dict):
                    if child.get('node_type') == 'selector_expression':
                        return self._extract_selector_name(child)
                    elif child.get('node_type') == 'identifier':
                        return child.get('source_text', '')
        
        return None

    def _extract_selector_name(self, node):
        """Extract name from selector expression like package.function."""
        if not isinstance(node, dict):
            return None
        
        source_text = node.get('source_text', '')
        if source_text:
            return source_text
        
        # Build from children: identifier . field_identifier
        parts = []
        for child in node.get('children', []):
            if isinstance(child, dict):
                child_type = child.get('node_type', '')
                if child_type in ['identifier', 'field_identifier']:
                    parts.append(child.get('source_text', ''))
                elif child_type == '.':
                    parts.append('.')
        
        return ''.join(parts)


def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a Go rule against an AST.
    
    Args:
        rule_metadata: Dictionary containing rule configuration
        ast_tree: Parsed Go AST tree  
        filename: Source file name being analyzed
    
    Returns:
        List of findings (violations) found by the rule
    """
    try:
        rule = GoGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# Alternative names for compatibility
GenericRule = GoGenericRule
GoRule = GoGenericRule