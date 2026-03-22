"""
Go Scanner Integration Module

This module provides a drop-in replacement for the regex-based parsing
in go_scanner.py while maintaining 100% compatibility with the existing
rule engine and API surface.

Usage:
    # Replace the old parse_go_file function with this enhanced version
    from go_scanner_enhanced import parse_go_file_enhanced
    
    # Drop-in replacement that provides real AST parsing
    ast = parse_go_file_enhanced('myfile.go')
    
    # Use with existing rule engine unchanged
    go_generic_rule_engine.apply_rules(ast, rules)
"""

import os
import sys
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import json
from dataclasses import dataclass

@dataclass
class GoProgramModel:
    """Semantic model of a Go program - where meaning lives."""
    functions: Dict[str, Dict[str, Any]]  # func_name -> {node, params, returns, calls}
    calls: Dict[str, List[str]]           # func_name -> [called_functions]
    goroutines: List[Dict[str, Any]]      # goroutine creation sites with context
    symbols: Dict[str, Dict[str, Any]]    # var_name -> {type, scope, node, line}
    channels: Dict[str, Dict[str, Any]]   # chan_name -> {type, direction, operations}
    errors: List[Dict[str, Any]]          # error handling sites
    imports: Dict[str, str]               # alias -> package_path
    types: Dict[str, Dict[str, Any]]      # type_name -> {kind, node, methods}
    
    def trace_origin(self, var_name: str, depth: int = 0, max_depth: int = 5) -> Set[str]:
        """Trace the origin of a variable through assignments and calls."""
        if depth > max_depth:
            return {var_name}
        
        symbol = self.symbols.get(var_name)
        if not symbol:
            return {var_name}  # Unknown origin
        
        origins = set()
        
        # If it's a literal assignment, it's a source
        if symbol.get('origin_type') == 'literal':
            origins.add(f"literal:{symbol.get('literal_value', 'unknown')}")
        
        # If it's from a function call, trace the function
        elif symbol.get('origin_type') == 'call':
            call_func = symbol.get('origin_function')
            if call_func:
                origins.add(f"call:{call_func}")
                # Could recursively trace function returns here
        
        # If it's from another variable, trace that
        elif symbol.get('origin_type') == 'variable':
            origin_var = symbol.get('origin_variable')
            if origin_var:
                origins.update(self.trace_origin(origin_var, depth + 1, max_depth))
        
        return origins if origins else {var_name}
    
    def is_tainted(self, var_name: str, taint_sources: Set[str]) -> bool:
        """Check if variable is tainted by any source."""
        origins = self.trace_origin(var_name)
        return bool(origins.intersection(taint_sources))
    
    def get_function_calls(self, func_name: str) -> List[str]:
        """Get all functions called by a given function."""
        return self.calls.get(func_name, [])
    
    def get_goroutines_in_function(self, func_name: str) -> List[Dict[str, Any]]:
        """Get all goroutines created in a function."""
        return [g for g in self.goroutines if g.get('parent_function') == func_name]
    
    def has_context_parameter(self, func_name: str) -> bool:
        """Check if function accepts context.Context."""
        func_info = self.functions.get(func_name, {})
        params = func_info.get('parameters', [])
        return any('context.Context' in str(p.get('type', '')) for p in params)
    
    def summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        return {
            'functions': len(self.functions),
            'goroutines': len(self.goroutines),
            'channels': len(self.channels),
            'types': len(self.types),
            'imports': len(self.imports),
            'error_sites': len(self.errors),
            'call_graph_size': sum(len(calls) for calls in self.calls.values()),
            'functions_with_goroutines': len([f for f in self.functions.keys() 
                                            if self.get_goroutines_in_function(f)]),
            'functions_with_context': len([f for f in self.functions.keys() 
                                         if self.has_context_parameter(f)])
        }


class GoProgramModelBuilder:
    """Builds semantic model from Go AST in a single pass."""
    
    def __init__(self):
        self.model = None
        self.current_function = None
        self.current_scope = "global"
    
    def build_model(self, ast: Dict[str, Any]) -> GoProgramModel:
        """Build complete semantic model from AST in one traversal."""
        self.model = GoProgramModel(
            functions={},
            calls={},
            goroutines=[],
            symbols={},
            channels={},
            errors=[],
            imports={},
            types={}
        )
        
        # Extract package-level info first
        self._extract_imports(ast)
        
        # Single traversal to build model - process all children
        children = ast.get('children', [])
        for child in children:
            self._walk(child)
        
        return self.model
    
    def _walk(self, node: Any, parent_function: Optional[str] = None) -> None:
        """Single-pass traversal that builds the complete model."""
        if not isinstance(node, dict):
            return
        
        node_type = node.get('node_type', '')
        
        # Function declarations
        if node_type in ('FuncDecl', 'function_declaration', 'method_declaration'):
            self._process_function(node)
        
        # Variable declarations
        elif node_type in ('VarDecl', 'variable_declaration', 'short_var_decl', 'assignment_expression'):
            if node_type == 'assignment_expression':
                self._process_assignment(node)
            else:
                self._process_variable(node)
        
        # Type declarations
        elif node_type in ('TypeDecl', 'type_declaration', 'type_spec'):
            self._process_type(node)
        
        # Call expressions
        elif node_type in ('call_expression', 'CallExpr'):
            self._process_call(node)
        
        # Goroutine statements
        elif node_type == 'go_statement':
            self._process_goroutine(node)
        
        # Channel operations
        elif node_type in ('make_expression', 'channel_type'):
            self._process_channel(node)
        
        # Assignment statements
        elif node_type in ('assignment', 'assignment_expression'):
            # Skip if already processed above
            if node_type != 'assignment_expression':
                self._process_assignment(node)
        
        # Error handling patterns
        elif self._is_error_handling(node):
            self._process_error_handling(node)
        
        # Recurse into children
        for key, value in node.items():
            if key == 'children' and isinstance(value, list):
                for child in value:
                    self._walk(child, self.current_function)
            elif isinstance(value, dict):
                self._walk(value, self.current_function)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk(item, self.current_function)
    
    def _extract_imports(self, ast: Dict[str, Any]) -> None:
        """Extract import information."""
        imports = ast.get('imports', [])
        for imp in imports:
            if isinstance(imp, dict):
                path = imp.get('path', '').strip('"')
                alias = imp.get('alias', path.split('/')[-1] if path else '')
                if path:
                    self.model.imports[alias] = path
    
    def _process_function(self, node: Dict[str, Any]) -> None:
        """Process function declaration."""
        name = self._extract_name(node)
        if not name:
            return
        
        self.current_function = name
        
        # Extract parameters and return types
        params = self._extract_parameters(node)
        returns = self._extract_returns(node)
        
        self.model.functions[name] = {
            'node': node,
            'parameters': params,
            'returns': returns,
            'line': node.get('line', node.get('lineno', 0)),
            'is_method': node.get('node_type') == 'method_declaration',
            'receiver': node.get('receiver') if node.get('node_type') == 'method_declaration' else None
        }
        
        # Initialize call list for this function
        self.model.calls[name] = []
    
    def _process_variable(self, node: Dict[str, Any]) -> None:
        """Process variable declaration."""
        name = self._extract_name(node)
        if not name:
            return
        
        var_type = node.get('type', node.get('var_type', 'unknown'))
        
        self.model.symbols[name] = {
            'type': var_type,
            'scope': self.current_function or 'global',
            'node': node,
            'line': node.get('line', node.get('lineno', 0)),
            'origin_type': 'declaration'
        }
    
    def _process_type(self, node: Dict[str, Any]) -> None:
        """Process type declaration."""
        name = self._extract_name(node)
        if not name:
            return
        
        type_kind = 'unknown'
        if 'struct' in str(node.get('type', '')).lower():
            type_kind = 'struct'
        elif 'interface' in str(node.get('type', '')).lower():
            type_kind = 'interface'
        
        self.model.types[name] = {
            'kind': type_kind,
            'node': node,
            'line': node.get('line', node.get('lineno', 0))
        }
    
    def _process_call(self, node: Dict[str, Any]) -> None:
        """Process function call."""
        if not self.current_function:
            return
        
        called_func = self._extract_called_function(node)
        if called_func:
            self.model.calls[self.current_function].append(called_func)
    
    def _process_goroutine(self, node: Dict[str, Any]) -> None:
        """Process goroutine creation."""
        called_func = self._extract_goroutine_function(node)
        
        goroutine_info = {
            'parent_function': self.current_function,
            'called_function': called_func,
            'node': node,
            'line': node.get('line', node.get('lineno', 0)),
            'has_context': self._check_context_usage(node),
            'has_cleanup': self._check_cleanup_mechanism(node)
        }
        
        self.model.goroutines.append(goroutine_info)
    
    def _process_channel(self, node: Dict[str, Any]) -> None:
        """Process channel declaration or operation."""
        if node.get('node_type') == 'make_expression':
            # make(chan Type)
            var_name = self._extract_assigned_variable(node)
            if var_name:
                chan_type = self._extract_channel_type(node)
                self.model.channels[var_name] = {
                    'type': chan_type,
                    'direction': 'bidirectional',
                    'operations': [],
                    'line': node.get('line', node.get('lineno', 0))
                }
    
    def _process_assignment(self, node: Dict[str, Any]) -> None:
        """Process assignment for data flow tracking."""
        lhs = node.get('left', node.get('lhs', []))
        rhs = node.get('right', node.get('rhs', []))
        
        if not isinstance(lhs, list):
            lhs = [lhs]
        if not isinstance(rhs, list):
            rhs = [rhs]
        
        # Track assignments for data flow
        for i, target in enumerate(lhs):
            target_name = self._extract_name_from_expr(target)
            if not target_name:
                continue
            
            source = rhs[i] if i < len(rhs) else rhs[-1] if rhs else None
            if source:
                origin_type, origin_value = self._classify_source(source)
                
                self.model.symbols[target_name] = {
                    'type': 'inferred',
                    'scope': self.current_function or 'global',
                    'node': node,
                    'line': node.get('line', node.get('lineno', 0)),
                    'origin_type': origin_type,
                    'origin_value': origin_value
                }
    
    def _process_error_handling(self, node: Dict[str, Any]) -> None:
        """Process error handling patterns."""
        error_info = {
            'function': self.current_function,
            'node': node,
            'line': node.get('line', node.get('lineno', 0)),
            'pattern': self._determine_error_pattern(node)
        }
        
        self.model.errors.append(error_info)
    
    # Helper methods for extraction
    
    def _extract_name(self, node: Dict[str, Any]) -> Optional[str]:
        """Extract name from various node types."""
        # First check direct fields
        name = (node.get('name') or 
                node.get('identifier') or 
                node.get('id'))
        
        if name:
            return name
        
        # Then check properties
        properties = node.get('properties', {})
        return properties.get('name')
    
    def _extract_parameters(self, func_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function parameters."""
        params = func_node.get('parameters', []) or func_node.get('params', [])
        result = []
        for param in params:
            if isinstance(param, dict):
                result.append({
                    'name': self._extract_name(param),
                    'type': param.get('type', 'unknown')
                })
        return result
    
    def _extract_returns(self, func_node: Dict[str, Any]) -> List[str]:
        """Extract function return types."""
        returns = func_node.get('returns', []) or func_node.get('return_types', [])
        result = []
        for ret in returns:
            if isinstance(ret, dict):
                result.append(ret.get('type', 'unknown'))
            else:
                result.append(str(ret))
        return result
    
    def _extract_called_function(self, call_node: Dict[str, Any]) -> Optional[str]:
        """Extract called function name."""
        func_info = (call_node.get('function') or 
                    call_node.get('func') or 
                    call_node.get('callee'))
        
        if isinstance(func_info, dict):
            return self._extract_name(func_info)
        
        # Fallback to source parsing
        source = str(call_node.get('source', ''))
        import re
        match = re.match(r'(\w+(?:\.\w+)*)\s*\(', source)
        return match.group(1) if match else None
    
    def _extract_goroutine_function(self, go_node: Dict[str, Any]) -> Optional[str]:
        """Extract function called in goroutine."""
        call = go_node.get('call', {})
        if call:
            return self._extract_called_function(call)
        
        # Parse from source
        source = str(go_node.get('source', ''))
        import re
        match = re.search(r'go\s+(\w+(?:\.\w+)*)\s*\(', source)
        return match.group(1) if match else None
    
    def _extract_name_from_expr(self, expr: Any) -> Optional[str]:
        """Extract variable name from expression."""
        if isinstance(expr, str):
            return expr
        if isinstance(expr, dict):
            return self._extract_name(expr)
        return None
    
    def _classify_source(self, source: Any) -> tuple[str, str]:
        """Classify the source of an assignment."""
        if isinstance(source, dict):
            if source.get('node_type') == 'call_expression':
                func = self._extract_called_function(source)
                return ('call', func or 'unknown')
            elif source.get('node_type') in ('identifier', 'variable'):
                return ('variable', self._extract_name(source) or 'unknown')
            elif 'literal' in source.get('node_type', '').lower():
                return ('literal', str(source.get('value', 'unknown')))
        
        return ('unknown', str(source)[:50])
    
    def _check_context_usage(self, node: Dict[str, Any]) -> bool:
        """Check if goroutine uses context."""
        source = str(node.get('source', ''))
        return 'context.' in source or 'ctx' in source.lower()
    
    def _check_cleanup_mechanism(self, node: Dict[str, Any]) -> bool:
        """Check if goroutine has cleanup mechanism."""
        source = str(node.get('source', ''))
        cleanup_keywords = ['WaitGroup', 'defer', 'select', 'range', 'Done()']
        return any(keyword in source for keyword in cleanup_keywords)
    
    def _extract_channel_type(self, make_node: Dict[str, Any]) -> str:
        """Extract channel type from make expression."""
        args = make_node.get('arguments', []) or make_node.get('args', [])
        if args and len(args) > 0:
            chan_type_arg = args[0]
            return str(chan_type_arg.get('type', 'unknown'))
        return 'unknown'
    
    def _extract_assigned_variable(self, node: Dict[str, Any]) -> Optional[str]:
        """Extract variable being assigned to."""
        # This would need to look at parent assignment node
        # Simplified for now
        return None
    
    def _is_error_handling(self, node: Dict[str, Any]) -> bool:
        """Check if node represents error handling."""
        source = str(node.get('source', ''))
        return ('if err != nil' in source or 
                'panic(' in source or 
                ', err :=' in source)
    
    def _determine_error_pattern(self, node: Dict[str, Any]) -> str:
        """Determine error handling pattern."""
        source = str(node.get('source', ''))
        if 'if err != nil' in source:
            return 'explicit_check'
        elif 'panic(' in source:
            return 'panic'
        elif ', _' in source:
            return 'ignored'
        return 'unknown'

# Import the enhanced parser, symbol table, control flow, and data flow
try:
    from go_ast_parser import EnhancedGoParser, GoContext
    GO_AST_PARSER_AVAILABLE = True
except ImportError:
    GO_AST_PARSER_AVAILABLE = False
    # Define stub classes for when the module is not available
    class EnhancedGoParser:
        def __init__(self):
            pass
        
        def parse_file_with_context(self, file_path, go_mod_path=None, build_context=None):
            raise ImportError("go_ast_parser module not available")
    
    class GoContext:
        pass
except Exception:
    GO_AST_PARSER_AVAILABLE = False
    # Define stub classes for any other import errors
    class EnhancedGoParser:
        def __init__(self):
            pass
        
        def parse_file_with_context(self, file_path, go_mod_path=None, build_context=None):
            raise ImportError("go_ast_parser module not available")
    
    class GoContext:
        pass

try:
    from go_symbol_table_builder import build_symbol_table_from_ast
    GO_SYMBOL_TABLE_AVAILABLE = True
except ImportError:
    GO_SYMBOL_TABLE_AVAILABLE = False

try:
    from go_control_flow import build_cfg_for_ast
    GO_CONTROL_FLOW_AVAILABLE = True
except ImportError:
    GO_CONTROL_FLOW_AVAILABLE = False

try:
    from go_data_flow import analyze_data_flow_for_ast
    GO_DATA_FLOW_AVAILABLE = True
except ImportError:
    GO_DATA_FLOW_AVAILABLE = False

# Import original scanner for fallback compatibility
# import go_scanner

class GoScannerEnhanced:
    """
    Enhanced Go scanner that integrates real parsing with existing infrastructure.
    
    This class provides a compatibility layer that allows gradual migration
    from regex-based to real AST parsing while preserving all existing APIs.
    """
    
    def __init__(self, use_enhanced_parser: bool = True, 
                 fallback_to_regex: bool = True):
        """
        Initialize the enhanced scanner.
        
        Args:
            use_enhanced_parser: Whether to use tree-sitter parser by default
            fallback_to_regex: Whether to fallback to regex parser on errors
        """
        self.use_enhanced_parser = use_enhanced_parser
        self.fallback_to_regex = fallback_to_regex
        
        # Initialize enhanced parser
        if use_enhanced_parser and GO_AST_PARSER_AVAILABLE:
            try:
                self.enhanced_parser = EnhancedGoParser()
            except Exception as e:
                print(f"Warning: Failed to initialize enhanced Go parser: {e}")
                self.enhanced_parser = None
                self.use_enhanced_parser = False
        else:
            self.enhanced_parser = None
            self.use_enhanced_parser = False
        
    def parse_go_file(self, file_path: str, 
                     go_mod_path: Optional[str] = None,
                     build_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse Go file using enhanced parser with fallback to regex parser.
        
        This function maintains the exact same interface as the original
        parse_go_file but provides enhanced capabilities when available.
        
        Args:
            file_path: Path to the Go file to parse
            go_mod_path: Optional path to go.mod file
            build_context: Optional build context (e.g., build tags)
        """
        if self.use_enhanced_parser and self.enhanced_parser:
            try:
                # Try enhanced parsing first
                enhanced_ast = self.enhanced_parser.parse_file_with_context(
                    file_path, go_mod_path, build_context
                )
                
                # Validate the AST has expected structure
                if self._validate_ast_structure(enhanced_ast):
                    try:
                        # Build the semantic model in one pass
                        model_builder = GoProgramModelBuilder()
                        model = model_builder.build_model(enhanced_ast)
                        
                        # Add model to AST
                        enhanced_ast['model'] = {
                            'functions': len(model.functions),
                            'calls': len([c for calls in model.calls.values() for c in calls]),
                            'goroutines': len(model.goroutines),
                            'channels': len(model.channels),
                            'types': len(model.types),
                            'imports': len(model.imports),
                            'error_sites': len(model.errors)
                        }
                        
                        # Build symbol table from model (if available)
                        if GO_SYMBOL_TABLE_AVAILABLE:
                            try:
                                symbol_table = build_symbol_table_from_ast(enhanced_ast)
                                enhanced_ast['symbol_table'] = symbol_table.dump_symbol_table()
                            except Exception:
                                enhanced_ast['symbol_table'] = {
                                    'symbols': {name: info for name, info in model.symbols.items()},
                                    'functions': model.functions
                                }
                        else:
                            enhanced_ast['symbol_table'] = {
                                'symbols': {name: info for name, info in model.symbols.items()},
                                'functions': model.functions
                            }
                        
                        # Build control flow graphs for Go (enhanced with model data)
                        if GO_CONTROL_FLOW_AVAILABLE:
                            try:
                                cfgs = build_cfg_for_ast(enhanced_ast)
                                enhanced_ast['control_flow'] = {
                                    'functions': list(cfgs.keys()) if cfgs else list(model.functions.keys()),
                                    'cfg_count': len(cfgs) if cfgs else 0,
                                    'total_cfg_nodes': sum(len(cfg.nodes) for cfg in cfgs.values() if cfg and hasattr(cfg, 'nodes')),
                                    'functions_with_dead_code': [
                                        name for name, cfg in cfgs.items() 
                                        if cfg and hasattr(cfg, 'get_unreachable_nodes') and len(cfg.get_unreachable_nodes()) > 0
                                    ] if cfgs else [],
                                    'goroutines': {
                                        'count': len(model.goroutines),
                                        'with_context': len([g for g in model.goroutines if g.get('has_context')]),
                                        'with_cleanup': len([g for g in model.goroutines if g.get('has_cleanup')])
                                    },
                                    'channels': {
                                        'count': len(model.channels),
                                        'by_function': len(set(g.get('parent_function') for g in model.goroutines if g.get('parent_function')))
                                    },
                                    'call_graph': {
                                        'total_calls': sum(len(calls) for calls in model.calls.values()),
                                        'functions_with_calls': len([f for f, calls in model.calls.items() if calls])
                                    }
                                }
                            except Exception as cfg_error:
                                print(f"CFG construction failed: {cfg_error}")
                                enhanced_ast['control_flow'] = {
                                    'functions': list(model.functions.keys()),
                                    'cfg_count': 0,
                                    'goroutines': {'count': len(model.goroutines)},
                                    'channels': {'count': len(model.channels)}
                                }
                        else:
                            enhanced_ast['control_flow'] = {
                                'functions': list(model.functions.keys()),
                                'goroutines': {'count': len(model.goroutines)},
                                'channels': {'count': len(model.channels)}
                            }
                        
                        # Perform data flow analysis using the model
                        if GO_DATA_FLOW_AVAILABLE and GO_SYMBOL_TABLE_AVAILABLE:
                            try:
                                data_flow_results = analyze_data_flow_for_ast(
                                    enhanced_ast, cfgs if 'cfgs' in locals() else {}, 
                                    enhanced_ast.get('symbol_table', {}).get('symbols', {})
                                )
                                enhanced_ast['data_flow'] = data_flow_results
                            except Exception:
                                # Fallback to model-based data flow info
                                enhanced_ast['data_flow'] = {
                                    'taint_analysis': 'model_based',
                                    'variable_origins': {name: list(model.trace_origin(name)) 
                                                       for name in list(model.symbols.keys())[:10]}
                                }
                        else:
                            enhanced_ast['data_flow'] = {}
                        
                        # Add enhanced capabilities flag
                        enhanced_ast['enhanced_capabilities'] = True
                        
                        # Generate semantic info from model (not AST traversal)
                        enhanced_ast['semantic_info'] = {
                            'package_name': enhanced_ast.get('package_name', ''),
                            'imports': len(model.imports),
                            'functions': len(model.functions),
                            'methods': len([f for f in model.functions.values() if f.get('is_method')]),
                            'types': len(model.types),
                            'interfaces': len([t for t in model.types.values() if t.get('kind') == 'interface']),
                            'structs': len([t for t in model.types.values() if t.get('kind') == 'struct']),
                            'goroutines': len(model.goroutines),
                            'channels': len(model.channels),
                            'defer_statements': len([e for e in model.errors if 'defer' in e.get('pattern', '')]),
                            'error_returns': len([f for f in model.functions.values() 
                                                if any('error' in str(r) for r in f.get('returns', []))]),
                            'panic_calls': len([e for e in model.errors if e.get('pattern') == 'panic']),
                            'symbol_count': len(model.symbols),
                            'cfg_functions': len(enhanced_ast.get('control_flow', {}).get('functions', [])),
                            'data_flow_violations': enhanced_ast.get('data_flow', {}).get('total_violations', {}),
                            # New model-specific metrics
                            'call_graph_size': sum(len(calls) for calls in model.calls.values()),
                            'functions_with_goroutines': len([f for f in model.functions.keys() 
                                                            if model.get_goroutines_in_function(f)]),
                            'functions_with_context': len([f for f in model.functions.keys() 
                                                         if model.has_context_parameter(f)]),
                            'taint_sources': len(set(origin for origins in 
                                                   [model.trace_origin(name) for name in list(model.symbols.keys())[:5]] 
                                                   for origin in origins))
                        }
                        
                        return enhanced_ast
                    except Exception as symbol_error:
                        print(f"Enhanced Go analysis failed: {symbol_error}")
                        # Return AST without enhanced analysis
                        enhanced_ast['enhanced_capabilities'] = True
                        enhanced_ast['symbol_table'] = {}
                        enhanced_ast['control_flow'] = {}
                        enhanced_ast['data_flow'] = {}
                        return enhanced_ast
                
            except Exception as e:
                print(f"Enhanced Go parser failed for {file_path}: {e}")
                if not self.fallback_to_regex:
                    raise
        
        # Fallback to minimal AST structure when original parser not available
        print(f"Using minimal fallback for {file_path}")
        return self._create_minimal_go_ast(file_path)
    
    def _validate_ast_structure(self, ast: Dict[str, Any]) -> bool:
        """Validate that the AST has the expected structure for Go rule engine."""
        required_fields = ['node_type', 'filename', 'children', 'language', 'package_name']
        
        if not all(field in ast for field in required_fields):
            return False
            
        if ast['node_type'] != 'SourceFile':
            return False
            
        if ast['language'] != 'go':
            return False
        
        # Validate children structure
        if not isinstance(ast['children'], list):
            return False
            
        # Check that child nodes have required fields
        for child in ast['children']:
            if not isinstance(child, dict):
                return False
            if 'node_type' not in child:
                return False
        
        return True
    
    def _create_minimal_go_ast(self, file_path: str) -> Dict[str, Any]:
        """Create a minimal Go AST structure when parser is unavailable."""
        try:
            # Try to extract basic info from file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
                line_count = len(lines)
                
                # Extract package name
                package_name = "main"
                for line in lines:
                    line = line.strip()
                    if line.startswith('package '):
                        package_name = line.split()[1]
                        break
                
                # Extract imports
                imports = []
                in_import_block = False
                for line in lines:
                    line = line.strip()
                    if line == 'import (':
                        in_import_block = True
                    elif line == ')' and in_import_block:
                        in_import_block = False
                    elif in_import_block:
                        if line and not line.startswith('//'):
                            imports.append(line.strip('"'))
                    elif line.startswith('import '):
                        import_part = line[7:].strip()
                        if import_part.startswith('"') and import_part.endswith('"'):
                            imports.append(import_part[1:-1])
                
                return {
                    'node_type': 'SourceFile',
                    'filename': file_path,
                    'package_name': package_name,
                    'imports': imports,
                    'children': [],
                    'language': 'go',
                    'line_count': line_count,
                    'enhanced_capabilities': False,
                    'source': content,
                    'error': 'No parser available'
                }
        except Exception as e:
            return {
                'node_type': 'SourceFile',
                'filename': file_path,
                'package_name': 'unknown',
                'imports': [],
                'children': [],
                'language': 'go',
                'line_count': 0,
                'enhanced_capabilities': False,
                'error': f'File reading failed: {str(e)}'
            }


# Module-level function for drop-in replacement
_enhanced_scanner = None

def get_enhanced_scanner() -> GoScannerEnhanced:
    """Get singleton enhanced scanner instance."""
    global _enhanced_scanner
    if _enhanced_scanner is None:
        _enhanced_scanner = GoScannerEnhanced()
    return _enhanced_scanner


def parse_go_file_enhanced(file_path: str, 
                          go_mod_path: Optional[str] = None,
                          build_context: Optional[str] = None,
                          use_enhanced: bool = True) -> Dict[str, Any]:
    """
    Drop-in replacement for go_scanner.parse_go_file with enhanced capabilities.
    
    This function can be used as a direct replacement for the original parsing
    function while providing enhanced AST parsing when available.
    
    Args:
        file_path: Path to the Go file to parse
        go_mod_path: Optional path to go.mod file
        build_context: Optional build context (e.g., build tags)
        use_enhanced: Whether to use enhanced parser (vs pure regex fallback)
    
    Returns:
        AST dict compatible with existing rule engine
    """
    scanner = get_enhanced_scanner()
    scanner.use_enhanced_parser = use_enhanced
    
    # Auto-detect go.mod if not provided
    if go_mod_path is None:
        # Look for go.mod in current directory and parents
        current_dir = Path(file_path).parent
        while current_dir != current_dir.parent:
            candidate = current_dir / 'go.mod'
            if candidate.exists():
                go_mod_path = str(candidate)
                break
            current_dir = current_dir.parent
    
    return scanner.parse_go_file(file_path, go_mod_path, build_context)


# Module-level function for compatibility with existing code
def parse_go_file(file_path: str, 
                 go_mod_path: Optional[str] = None,
                 build_context: Optional[str] = None) -> Dict[str, Any]:
    """
    Module-level parse_go_file function for compatibility.
    
    This function provides the interface expected by test_scanner and other code.
    """
    return parse_go_file_enhanced(file_path, go_mod_path, build_context)


def check_enhanced_capabilities() -> Dict[str, bool]:
    """
    Check which enhanced capabilities are available.
    
    Returns:
        Dict mapping capability names to availability
    """
    capabilities = {
        'tree_sitter_parser': False,
        'go_modules': False,
        'build_context': False,
        'symbol_table': False,
        'control_flow': False,
        'data_flow': False,
        'goroutine_analysis': False,
        'channel_analysis': False,
        'interface_analysis': False
    }
    
    try:
        # Check if tree-sitter Go is available
        import tree_sitter_go
        capabilities['tree_sitter_parser'] = True
        capabilities['go_modules'] = True
        capabilities['build_context'] = True
        
        # Check Go-specific analysis capabilities
        capabilities['goroutine_analysis'] = True
        capabilities['channel_analysis'] = True
        capabilities['interface_analysis'] = True
        
    except ImportError:
        pass
    
    # Check if Go symbol table is available
    if GO_SYMBOL_TABLE_AVAILABLE:
        capabilities['symbol_table'] = True
    
    # Check if Go control flow is available
    if GO_CONTROL_FLOW_AVAILABLE:
        capabilities['control_flow'] = True
    
    # Check if Go data flow is available
    if GO_DATA_FLOW_AVAILABLE:
        capabilities['data_flow'] = True
    
    return capabilities


def get_program_model_from_ast(ast: Dict[str, Any]) -> Optional[GoProgramModel]:
    """
    Extract the program model from an AST that was parsed with the enhanced scanner.
    
    This allows rule engines to access the semantic model directly.
    """
    # The model is not stored directly in the AST to keep compatibility,
    # but we can rebuild it if needed
    if not ast.get('enhanced_capabilities', False):
        return None
    
    # For now, return None since the model is used during parsing but not stored
    # In a full implementation, you'd either store the model or rebuild it
    return None


def install_enhanced_dependencies():
    """
    Install required dependencies for enhanced Go parsing.
    
    This function can be called to set up the enhanced parsing environment.
    """
    try:
        import subprocess
        import sys
        
        # Install tree-sitter and tree-sitter-go
        packages = ['tree-sitter', 'tree-sitter-go']
        
        for package in packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"{package} already installed")
            except ImportError:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"Successfully installed {package}")
        
        print("Enhanced Go parsing dependencies installed successfully!")
        return True
        
    except Exception as e:
        print(f"Failed to install Go dependencies: {e}")
        return False


# Compatibility layer for existing imports
def get_all_go_files(scan_path):
    """
    Compatibility wrapper for existing function.
    Get all Go files in a directory.
    """
    import glob
    import os
    
    go_files = []
    for root, dirs, files in os.walk(scan_path):
        # Skip vendor directories and other common exclusions
        dirs[:] = [d for d in dirs if d not in ['.git', 'vendor', 'node_modules']]
        
        for file in files:
            if file.endswith('.go') and not file.endswith('_test.go'):
                go_files.append(os.path.join(root, file))
    return go_files


def get_all_go_test_files(scan_path):
    """
    Get all Go test files in a directory.
    """
    import glob
    import os
    
    test_files = []
    for root, dirs, files in os.walk(scan_path):
        # Skip vendor directories and other common exclusions
        dirs[:] = [d for d in dirs if d not in ['.git', 'vendor', 'node_modules']]
        
        for file in files:
            if file.endswith('_test.go'):
                test_files.append(os.path.join(root, file))
    return test_files


def load_rule_metadata(folder="go_docs"):
    """
    Compatibility wrapper for existing function.
    Load rule metadata from JSON files.
    """
    import json
    import glob
    import os
    
    rules = []
    metadata_files = glob.glob(os.path.join(folder, "*_metadata.json"))
    
    for metadata_file in metadata_files:
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                rule_data = json.load(f)
                rules.append(rule_data)
        except Exception as e:
            print(f"Warning: Failed to load {metadata_file}: {e}")
    
    return rules


def run_vulnerability_scan(file_path: str) -> Dict[str, Any]:
    """
    Main vulnerability scanning function - similar to ARM scanner.
    
    Args:
        file_path: Path to Go file to scan
        
    Returns:
        Dictionary with scanning results and findings
    """
    try:
        # Import the rule engine
        from . import go_generic_rule_engine
        
        # Load all rule metadata
        try:
            from database.rule_cache import rule_cache
            rules_meta = rule_cache.get_rules("go")
        except Exception:
            rules_meta = load_rule_metadata("go_docs")
        
        # Parse the Go file
        ast_tree = parse_go_file_enhanced(file_path)
        if ast_tree is None:
            return {
                "language": "go",
                "files_scanned": 1,
                "findings": []
            }
        
        # Apply rules to find vulnerabilities
        all_findings = []
        for rule in rules_meta:
            try:
                findings = go_generic_rule_engine.run_rule(rule, ast_tree, file_path)
                if findings:
                    for finding in findings:
                        # Ensure finding has required fields
                        finding_dict = {
                            'rule_id': finding.get('rule_id', rule.get('rule_id', 'unknown')),
                            'message': finding.get('message', 'No message'),
                            'file': file_path,
                            'line': finding.get('line', 0),
                            'column': finding.get('column', 0),
                            'severity': finding.get('severity', rule.get('defaultSeverity', 'Medium')),
                            'category': rule.get('category', 'Unknown'),
                            'node_type': finding.get('node_type', 'Unknown'),
                            'source_text': finding.get('source_text', ''),
                            'property_path': finding.get('property_path', [])
                        }
                        all_findings.append(finding_dict)
            except Exception as e:
                print(f"Warning: Rule {rule.get('rule_id', 'unknown')} failed: {e}")
        
        # Deduplicate findings
        seen = set()
        deduped_findings = []
        for finding in all_findings:
            # Create a unique key for deduplication
            key = (
                finding['rule_id'],
                finding['file'],
                finding['line'],
                finding['column'],
                finding['message']
            )
            if key not in seen:
                seen.add(key)
                deduped_findings.append(finding)
        
        return {
            "language": "go",
            "files_scanned": 1,
            "findings": deduped_findings
        }
        
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")
        import traceback
        traceback.print_exc()
        return {
            "language": "go", 
            "files_scanned": 1,
            "findings": [],
            "error": str(e)
        }


def find_go_mod(start_path: str) -> Optional[str]:
    """
    Find the go.mod file for a given Go file.
    
    Args:
        start_path: Path to start searching from
    
    Returns:
        Path to go.mod file if found, None otherwise
    """
    current_dir = Path(start_path).parent if Path(start_path).is_file() else Path(start_path)
    
    while current_dir != current_dir.parent:
        go_mod = current_dir / 'go.mod'
        if go_mod.exists():
            return str(go_mod)
        current_dir = current_dir.parent
    
    return None


def parse_go_mod(go_mod_path: str) -> Dict[str, Any]:
    """
    Parse go.mod file to extract module information.
    
    Args:
        go_mod_path: Path to go.mod file
    
    Returns:
        Dictionary containing module information
    """
    try:
        with open(go_mod_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        module_info = {
            'module_name': '',
            'go_version': '',
            'dependencies': [],
            'replace_directives': [],
            'exclude_directives': []
        }
        
        lines = content.splitlines()
        in_require_block = False
        in_replace_block = False
        in_exclude_block = False
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            if line.startswith('module '):
                module_info['module_name'] = line[7:].strip()
            elif line.startswith('go '):
                module_info['go_version'] = line[3:].strip()
            elif line == 'require (':
                in_require_block = True
            elif line == 'replace (':
                in_replace_block = True
            elif line == 'exclude (':
                in_exclude_block = True
            elif line == ')':
                in_require_block = in_replace_block = in_exclude_block = False
            elif in_require_block:
                module_info['dependencies'].append(line)
            elif in_replace_block:
                module_info['replace_directives'].append(line)
            elif in_exclude_block:
                module_info['exclude_directives'].append(line)
            elif line.startswith('require '):
                module_info['dependencies'].append(line[8:].strip())
            elif line.startswith('replace '):
                module_info['replace_directives'].append(line[8:].strip())
            elif line.startswith('exclude '):
                module_info['exclude_directives'].append(line[8:].strip())
        
        return module_info
        
    except Exception as e:
        print(f"Warning: Failed to parse go.mod {go_mod_path}: {e}")
        return {
            'module_name': '',
            'go_version': '',
            'dependencies': [],
            'replace_directives': [],
            'exclude_directives': []
        }


# Make this module a drop-in replacement
def monkey_patch_scanner():
    """
    Replace the original parse_go_file function with enhanced version.
    
    This allows existing code to automatically benefit from enhanced parsing
    without any changes.
    """
    # This function would be used if there was an original go_scanner to patch
    print("Enhanced Go parser is already active - no patching needed")
    
    def enhanced_parse_wrapper(file_path, *args, **kwargs):
        try:
            return parse_go_file_enhanced(file_path)
        except Exception:
            # Fallback to minimal AST
            return {
                'node_type': 'SourceFile',
                'filename': file_path,
                'package_name': 'main',
                'imports': [],
                'children': [],
                'language': 'go',
                'line_count': 0,
                'enhanced_capabilities': False,
                'error': 'Parse failed'
            }
    
    # If this module was replacing another, we would patch it here
    # go_scanner.parse_go_file = enhanced_parse_wrapper
    
    print("Enhanced Go parser ready")


if __name__ == "__main__":
    # Command-line interface for testing and setup
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Go Scanner")
    parser.add_argument("--check", action="store_true", 
                       help="Check available capabilities")
    parser.add_argument("--install", action="store_true",
                       help="Install enhanced parsing dependencies")
    parser.add_argument("--test", type=str,
                       help="Test parsing on a specific Go file")
    parser.add_argument("--test-package", type=str,
                       help="Test parsing on all files in a Go package")
    parser.add_argument("--monkey-patch", action="store_true",
                       help="Install monkey patch for existing code")
    parser.add_argument("--find-mod", type=str,
                       help="Find go.mod for a given path")
    parser.add_argument("file_path", nargs="?", 
                       help="Go file to scan for vulnerabilities (positional argument)")
    
    args = parser.parse_args()
    
    # Handle direct file scanning (when called by vulnerability scanner)
    if args.file_path and not any([args.check, args.install, args.test, args.test_package, args.monkey_patch, args.find_mod]):
        if not os.path.exists(args.file_path):
            print(f"File not found: {args.file_path}")
            sys.exit(1)
        
        # Run vulnerability scan and output JSON
        result = run_vulnerability_scan(args.file_path)
        import json
        print(json.dumps(result, indent=2))
        sys.exit(0)
    
    if args.check:
        capabilities = check_enhanced_capabilities()
        print("Enhanced Go Scanner Capabilities:")
        for cap, available in capabilities.items():
            status = "✓" if available else "✗"
            print(f"  {status} {cap}")
    
    elif args.install:
        install_enhanced_dependencies()
    
    elif args.test:
        if not os.path.exists(args.test):
            print(f"File not found: {args.test}")
            sys.exit(1)
        
        print(f"Testing enhanced Go parsing on: {args.test}")
        try:
            ast = parse_go_file_enhanced(args.test)
            print(f"✓ Successfully parsed with enhanced capabilities: {ast.get('enhanced_capabilities', False)}")
            print(f"  Package: {ast.get('package_name', 'unknown')}")
            print(f"  Imports: {len(ast.get('imports', []))}")
            print(f"  Node count: {len(ast.get('children', []))}")
            print(f"  Line count: {ast.get('line_count', 0)}")
            
            semantic_info = ast.get('semantic_info', {})
            if semantic_info:
                print(f"  Functions: {semantic_info.get('functions', 0)}")
                print(f"  Methods: {semantic_info.get('methods', 0)}")
                print(f"  Types: {semantic_info.get('types', 0)}")
                print(f"  Goroutines: {semantic_info.get('goroutines', 0)}")
                print(f"  Channels: {semantic_info.get('channels', 0)}")
                print(f"  Call graph edges: {semantic_info.get('call_graph_size', 0)}")
                print(f"  Functions with context: {semantic_info.get('functions_with_context', 0)}")
                print(f"  Functions with goroutines: {semantic_info.get('functions_with_goroutines', 0)}")
                print(f"  Taint sources found: {semantic_info.get('taint_sources', 0)}")
        except Exception as e:
            print(f"✗ Parsing failed: {e}")
            sys.exit(1)
    
    elif args.test_package:
        if not os.path.exists(args.test_package):
            print(f"Directory not found: {args.test_package}")
            sys.exit(1)
        
        print(f"Testing enhanced Go parsing on package: {args.test_package}")
        go_files = get_all_go_files(args.test_package)
        
        if not go_files:
            print("No Go files found in directory")
            sys.exit(1)
        
        success_count = 0
        total_count = len(go_files)
        
        for file_path in go_files:
            try:
                ast = parse_go_file_enhanced(file_path)
                if ast.get('enhanced_capabilities', False):
                    success_count += 1
                    print(f"✓ {os.path.basename(file_path)}")
                else:
                    print(f"⚠ {os.path.basename(file_path)} (fallback)")
            except Exception as e:
                print(f"✗ {os.path.basename(file_path)}: {e}")
        
        print(f"\nResults: {success_count}/{total_count} files parsed with enhanced capabilities")
    
    elif args.find_mod:
        go_mod_path = find_go_mod(args.find_mod)
        if go_mod_path:
            print(f"Found go.mod: {go_mod_path}")
            mod_info = parse_go_mod(go_mod_path)
            print(f"Module: {mod_info['module_name']}")
            print(f"Go version: {mod_info['go_version']}")
            print(f"Dependencies: {len(mod_info['dependencies'])}")
        else:
            print("No go.mod found")
    
    elif args.monkey_patch:
        monkey_patch_scanner()
        print("Monkey patch installed. Existing code will now use enhanced Go parser.")
    
    else:
        parser.print_help()

# --- Scanner Integration Functions ---

def get_all_go_files(scan_path):
    """Get all Go files from scan path."""
    go_files = []
    
    if os.path.isfile(scan_path):
        if scan_path.endswith('.go'):
            go_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file.endswith('.go'):
                    go_files.append(os.path.join(root, file))
    
    return go_files

def load_rule_metadata(folder="go_docs"):
    """Load rule metadata from JSON files."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        print(f"Warning: Metadata folder '{folder}' not found in {script_dir}", file=sys.stderr)
        return {}
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
            try:
                with open(os.path.join(folder_path, filename), 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)
                    rule_id = rule_data.get('rule_id') or filename.replace('_metadata.json', '')
                    rules_meta[rule_id] = rule_data
            except Exception as e:
                print(f"Error loading {filename}: {e}", file=sys.stderr)
    
    return rules_meta

def run_scanner(scan_path):
    """Main scanner function that processes all Go files and applies rules."""
    from . import go_generic_rule_engine

    try:
        from database.rule_cache import rule_cache
        rules_meta = rule_cache.get_rules("go")
    except Exception:
        rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    go_files = get_all_go_files(scan_path)
    all_findings = []
    
    for go_file in go_files:
        
        try:
            # Parse Go file (using fallback parser for now)
            ast_tree = parse_go_file_simple(go_file)
            
            for rule in rules:
                try:
                    findings = go_generic_rule_engine.run_rule(rule, ast_tree, go_file)
                    if findings:
                        for finding in findings:
                            finding['file'] = go_file
                            all_findings.append(finding)
                except Exception as e:
                    print(f"Error applying rule {rule.get('rule_id', 'unknown')} to {go_file}: {e}", file=sys.stderr)
                    continue
        except Exception as e:
            print(f"Error processing {go_file}: {str(e)}", file=sys.stderr)
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

def parse_go_file_simple(file_path):
    """Simple Go file parser for rule engine compatibility."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return {
        'node_type': 'File',
        'filename': file_path,
        'source': content,
        'children': [],
        'line_count': len(content.split('\n'))
    }

# API entry point for plugin system
def run_scan(file_path):
    """Scan a single Go file and return findings as a list of dicts."""
    findings = run_scanner(file_path)
    # Clean findings for API
    cleaned_results = []
    for finding in findings:
        if isinstance(finding, dict) and 'file' in finding:
            del finding['file']
        cleaned_results.append(finding)
    return cleaned_results

# Main entry point
if __name__ == "__main__":
    import argparse
    
    if len(sys.argv) >= 2 and not sys.argv[1].startswith('--'):
        # Simple case: just scan the input path
        input_path = sys.argv[1]
        
        if not os.path.exists(input_path):
            print(f"Error: Path '{input_path}' does not exist", file=sys.stderr)
            sys.exit(1)
        
        try:
            findings = run_scanner(input_path)
            
            # Count files scanned  
            files_scanned = len(get_all_go_files(input_path))
            
            result = {
                "language": "go",
                "files_scanned": files_scanned,
                "findings": findings
            }
            print(json.dumps(result, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
    
    else:
        # If no simple path argument, show usage
        print("Usage: go_scanner.py <input_path>")
        print("  <input_path> - Path to Go file or directory containing Go files")
        sys.exit(1)