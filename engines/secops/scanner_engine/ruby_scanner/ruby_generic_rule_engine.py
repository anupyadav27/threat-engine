"""
Ruby Generic Rule Engine - Sonar-Style Analysis Pipeline

ARCHITECTURE LAYERS (STRICT SEPARATION):
1. AST Phase: Structure only, no security decisions
2. Symbol Phase: Name binding, scope, inheritance  
3. Flow Phase: Taint propagation, data flow
4. Rule Phase: Query analysis results, raise findings

CORE INVARIANTS:
1. Parser describes code. Rules decide vulnerabilities.
2. Rules must NEVER mutate AST, symbol table, or taint tracker.
3. Rules are observers, not actors.

This discipline prevents 90% of static analyzer corruption bugs.
"""

import re
from typing import Any, Dict, List, Optional, Union
from . import ruby_logic_implementations


# ===== AST PHASE: STRUCTURE ONLY =====

class ASTNode:
    """
    Pure structural AST node. NO SECURITY KNOWLEDGE.
    Only describes "what the code looks like".
    """
    def __init__(self, node_type: str, line: int = 0):
        self.node_type = node_type
        self.line = line
        self.children = []
        self.parent = None
        
    def add_child(self, child):
        child.parent = self
        self.children.append(child)


# ===== SYMBOL PHASE: NAME RESOLUTION =====

class Scope:
    """Single scope level for symbol tracking."""
    
    def __init__(self, scope_type: str = "block"):
        self.scope_type = scope_type  # method, class, module, block
        self.symbols = {}  # name -> definition node
        self.parent_scope = None
        
    def define(self, name: str, node: Any):
        self.symbols[name] = node
        
    def lookup_local(self, name: str) -> Optional[Any]:
        return self.symbols.get(name)


class SymbolTable:
    """
    Tracks symbol definitions and bindings.
    SEMANTIC LAYER - answers "what names mean".
    
    CRITICAL: Rules can only QUERY this table, never mutate it.
    Use resolve_symbol(), is_defined_in_scope() for rule queries.
    """
    
    def __init__(self):
        self.current_scope = None
        self.scope_stack = []
        self._analysis_complete = False  # Prevent rule-time mutations
        
    def enter_scope(self, scope_type: str = "block") -> Scope:
        new_scope = Scope(scope_type)
        if self.current_scope:
            new_scope.parent_scope = self.current_scope
        self.scope_stack.append(new_scope)
        self.current_scope = new_scope
        return new_scope
        
    def exit_scope(self) -> Optional[Scope]:
        if self.scope_stack:
            exiting = self.scope_stack.pop()
            self.current_scope = self.scope_stack[-1] if self.scope_stack else None
            return exiting
        return None
        
    def define_symbol(self, name: str, node: Any):
        """Define symbol. ANALYSIS PHASE ONLY."""
        if self._analysis_complete:
            raise RuntimeError("INVARIANT VIOLATION: Rules cannot mutate symbol table")
        if self.current_scope:
            self.current_scope.define(name, node)
            
    def resolve_symbol(self, name: str) -> Optional[Any]:
        scope = self.current_scope
        while scope:
            result = scope.lookup_local(name)
            if result:
                return result
            scope = scope.parent_scope
        return None
        
    def is_defined_in_scope(self, name: str) -> bool:
        return self.resolve_symbol(name) is not None
        
    def finalize_analysis(self):
        """Mark analysis complete. After this, only queries allowed."""
        self._analysis_complete = True


# ===== FLOW PHASE: TAINT ANALYSIS =====

class TaintTracker:
    """
    Tracks data flow and taint propagation.
    DATAFLOW LAYER - answers "what data becomes dangerous".
    
    CRITICAL: Rules can only QUERY this tracker, never mutate it.
    Use is_tainted(), get_taint_source(), is_sanitized() for rule queries.
    """
    
    def __init__(self):
        self.taint_map = {}  # node_id -> TaintInfo
        self.source_patterns = []  # Configured by analysis, not rules
        self.sink_patterns = []
        self._analysis_complete = False  # Prevent rule-time mutations
        
    def mark_source(self, node: Any, source_type: str):
        """Mark node as taint source. ANALYSIS PHASE ONLY."""
        if self._analysis_complete:
            raise RuntimeError("INVARIANT VIOLATION: Rules cannot mutate taint tracker")
        self.taint_map[id(node)] = {
            'type': 'source',
            'source_type': source_type,
            'sanitized': False
        }
        
    def mark_sanitized(self, node: Any):
        """Mark node as sanitized. ANALYSIS PHASE ONLY."""
        if self._analysis_complete:
            raise RuntimeError("INVARIANT VIOLATION: Rules cannot mutate taint tracker")
        if id(node) in self.taint_map:
            self.taint_map[id(node)]['sanitized'] = True
            
    def propagate_taint(self, from_node: Any, to_node: Any):
        """Propagate taint from one node to another. ANALYSIS PHASE ONLY."""
        if self._analysis_complete:
            raise RuntimeError("INVARIANT VIOLATION: Rules cannot mutate taint tracker")
        from_id = id(from_node)
        if from_id in self.taint_map:
            self.taint_map[id(to_node)] = self.taint_map[from_id].copy()
            
    def is_tainted(self, node: Any) -> bool:
        """Query: Is this node tainted?"""
        return id(node) in self.taint_map
        
    def get_taint_source(self, node: Any) -> Optional[str]:
        """Query: What tainted this node?"""
        taint_info = self.taint_map.get(id(node))
        return taint_info.get('source_type') if taint_info else None
        
    def is_sanitized(self, node: Any) -> bool:
        """Query: Has this node been sanitized?"""
        taint_info = self.taint_map.get(id(node))
        return taint_info.get('sanitized', False) if taint_info else False
        
    def finalize_analysis(self):
        """Mark analysis complete. After this, only queries allowed."""
        self._analysis_complete = True


class FlowAnalyzer:
    """
    Performs data flow analysis on AST.
    Builds taint information for rules to query.
    """
    
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.taint_tracker = TaintTracker()
        
    def analyze(self, ast_tree: Any):
        """Perform complete flow analysis."""
        self._build_symbols(ast_tree)
        self._analyze_taint_flow(ast_tree)
        
        # CRITICAL: Finalize analysis to prevent rule mutations
        self.symbol_table.finalize_analysis()
        self.taint_tracker.finalize_analysis()
        
    def _build_symbols(self, node: Any):
        """Build symbol table from AST."""
        if not hasattr(node, 'node_type'):
            return
            
        node_type = node.node_type
        
        # Scope management
        if node_type in ['DefNode', 'ClassNode', 'ModuleNode']:
            self.symbol_table.enter_scope(node_type)
            
        # Symbol definitions
        if node_type == 'DefNode' and hasattr(node, 'name'):
            self.symbol_table.define_symbol(node.name, node)
        elif node_type == 'AssignNode' and hasattr(node, 'name'):
            self.symbol_table.define_symbol(node.name, node)
            
        # Traverse children
        for child in getattr(node, 'children', []):
            self._build_symbols(child)
            
        # Exit scope
        if node_type in ['DefNode', 'ClassNode', 'ModuleNode']:
            self.symbol_table.exit_scope()
            
    def _analyze_taint_flow(self, node: Any):
        """Analyze taint propagation."""
        if not hasattr(node, 'node_type'):
            return
            
        node_type = node.node_type
        
        # Mark taint sources (analysis decision, not rule decision)
        if node_type == 'CallNode' and hasattr(node, 'method_name'):
            method_name = node.method_name
            if method_name in ['params', 'request', 'gets', 'ARGV']:
                self.taint_tracker.mark_source(node, method_name)
                
        # Propagate through assignments
        elif node_type == 'AssignNode':
            if hasattr(node, 'value_node'):
                self.taint_tracker.propagate_taint(node.value_node, node)
                
        # Traverse children
        for child in getattr(node, 'children', []):
            self._analyze_taint_flow(child)


# ===== RULE PHASE: VULNERABILITY DETECTION =====

class CheckTypeRegistry:
    """
    Registry of valid check types organized by analysis layer.
    DEFINES CONTRACT: What engine capabilities must exist for each check type.
    """
    
    SYNTAX_CHECKS = {
        'node_type_match': 'Match specific AST node types',
        'method_name_match': 'Match method call names', 
        'child_node_exists': 'Check for child node presence',
        'literal_pattern_match': 'Pattern match literal values',
        'source_regex_match': 'Regex match on source code',
        'inheritance_check': 'Check class inheritance',
        'nesting_depth_check': 'Check code nesting depth',
        'custom_function': 'Call custom analysis function'
    }
    
    SEMANTIC_CHECKS = {
        'symbol_defined': 'Check if symbol is defined in scope',
        'symbol_unused': 'Check for unused symbols',
        'scope_violation': 'Check scope access violations',
        'property_comparison': 'Compare node properties'
    }
    
    DATAFLOW_CHECKS = {
        'taint_source_to_sink': 'Track taint from source to dangerous sink',
        'missing_sanitization': 'Detect missing input sanitization',
        'unsafe_data_flow': 'Detect unsafe data propagation'
    }
    
    @classmethod
    def get_check_layer(cls, check_type: str) -> Optional[str]:
        """Return which analysis layer a check type belongs to."""
        if check_type in cls.SYNTAX_CHECKS:
            return 'syntax'
        elif check_type in cls.SEMANTIC_CHECKS:
            return 'semantic'  
        elif check_type in cls.DATAFLOW_CHECKS:
            return 'dataflow'
        return None
        
    @classmethod
    def is_valid_check_type(cls, check_type: str) -> bool:
        """Validate check type exists in registry."""
        return cls.get_check_layer(check_type) is not None


class VulnerabilityPatterns:
    """
    Defines the 5 core vulnerability patterns this engine must support.
    Rules declare these patterns using check types.
    """
    
    EVAL_INJECTION = {
        'check_type': 'taint_source_to_sink',
        'sources': ['params', 'request', 'gets'],
        'sinks': ['eval'],
        'requires_sanitization': True
    }
    
    COMMAND_INJECTION = {
        'check_type': 'taint_source_to_sink', 
        'sources': ['params', 'request', 'gets'],
        'sinks': ['system', 'exec', '`'],
        'requires_sanitization': True
    }
    
    SQL_INJECTION = {
        'check_type': 'taint_source_to_sink',
        'sources': ['params', 'request'],
        'sinks': ['execute', 'find_by_sql', 'where'],
        'requires_sanitization': True
    }
    
    PATH_TRAVERSAL = {
        'check_type': 'taint_source_to_sink',
        'sources': ['params', 'request'],
        'sinks': ['File.open', 'File.read', 'File.write'],
        'requires_sanitization': True
    }
    
    UNSAFE_DESERIALIZATION = {
        'check_type': 'taint_source_to_sink',
        'sources': ['params', 'request', 'File.read'],
        'sinks': ['Marshal.load', 'YAML.load'],
        'requires_sanitization': True
    }


class RubyGenericRule:
    """
    Rule that queries analysis results to detect vulnerabilities.
    FOLLOWS SONAR CONTRACT: Rules query, analysis engines provide answers.
    
    CRITICAL DISCIPLINE: This rule can only QUERY analysis results.
    It must NEVER mutate AST nodes, symbol table, or taint tracker.
    Rules are observers, not actors.
    """
    
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")
        
        # Analysis context (injected by runner)
        self.flow_analyzer = None
        
    def set_analysis_context(self, flow_analyzer: FlowAnalyzer):
        """Inject analysis context - rules don't create their own."""
        self.flow_analyzer = flow_analyzer

    def is_applicable(self, ast_tree: Any) -> bool:
        """Check if rule applies - SYNTAX LAYER ONLY."""
        if not self.metadata or not self.rule_id:
            return False
            
        required_node_types = self.logic.get("node_types", [])
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
            return bool(matching_nodes)
            
        return True

    def check(self, ast_tree: Any, filename: str) -> List[Dict[str, Any]]:
        """Execute rule checks - QUERIES ANALYSIS RESULTS."""
        findings = []
        checks = self.logic.get('checks', [])
        
        for check in checks:
            check_type = check.get('type', '')
            layer = CheckTypeRegistry.get_check_layer(check_type)
            
            if layer == 'syntax':
                findings.extend(self._execute_syntax_check(check, ast_tree, filename))
            elif layer == 'semantic':
                findings.extend(self._execute_semantic_check(check, ast_tree, filename))
            elif layer == 'dataflow':
                findings.extend(self._execute_dataflow_check(check, ast_tree, filename))
        
        return findings
        
    def _execute_syntax_check(self, check: Dict, ast_tree: Any, filename: str) -> List[Dict]:
        """Execute syntax-level checks - AST STRUCTURE ONLY."""
        findings = []
        check_type = check.get('type')
        node_types = check.get('node_types', self.logic.get('node_types', []))
        
        # Store filename for use in pattern matching
        self._current_filename = filename
        
        matching_nodes = self._find_nodes_by_type(ast_tree, node_types) if node_types else [ast_tree]
        
        for node in matching_nodes:
            if check_type == 'method_name_match':
                if self._check_method_name_match(node, check):
                    findings.append(self._make_finding(node, filename, check))
                    
            elif check_type == 'source_regex_match':
                if self._check_source_regex(node, check):
                    findings.append(self._make_finding(node, filename, check))
                    
            elif check_type == 'node_type_match':
                if self._check_node_type_match(node, check):
                    findings.append(self._make_finding(node, filename, check))
                    
            elif check_type == 'property_comparison':
                if self._check_property_comparison(node, check):
                    findings.append(self._make_finding(node, filename, check))
                    
            elif check_type == 'custom_function':
                if self._check_custom_function(node, check):
                    findings.append(self._make_finding(node, filename, check))
                    
            elif check_type == 'literal_pattern_match':
                if self._check_literal_pattern_match(node, check):
                    findings.append(self._make_finding(node, filename, check))
        
        return findings
        
    def _execute_semantic_check(self, check: Dict, ast_tree: Any, filename: str) -> List[Dict]:
        """Execute semantic-level checks - QUERIES SYMBOL TABLE."""
        findings = []
        
        if not self.flow_analyzer:
            return findings
            
        check_type = check.get('type')
        
        if check_type == 'symbol_defined':
            # Query symbol table for undefined symbols
            # Implementation would traverse AST and query symbol_table.resolve_symbol()
            pass
            
        return findings
        
    def _execute_dataflow_check(self, check: Dict, ast_tree: Any, filename: str) -> List[Dict]:
        """Execute dataflow-level checks - QUERIES TAINT TRACKER."""
        findings = []
        
        if not self.flow_analyzer:
            return findings
            
        check_type = check.get('type')
        
        if check_type == 'taint_source_to_sink':
            findings.extend(self._check_taint_flow(check, ast_tree, filename))
            
        return findings
        
    def _check_taint_flow(self, check: Dict, ast_tree: Any, filename: str) -> List[Dict]:
        """Check for dangerous taint flows - CORE SECURITY CHECK."""
        findings = []
        
        # Rule declares what it considers dangerous
        declared_sinks = check.get('sinks', [])
        declared_sources = check.get('sources', [])
        
        # Find all call nodes that might be sinks
        call_nodes = self._find_nodes_by_type(ast_tree, ['CallNode'])
        
        for node in call_nodes:
            method_name = getattr(node, 'method_name', '')
            
            # Is this a sink the rule cares about?
            if method_name not in declared_sinks:
                continue
                
            # Query taint tracker: Are any arguments tainted?
            args = getattr(node, 'args', [])
            for arg in args:
                if self.flow_analyzer.taint_tracker.is_tainted(arg):
                    source_type = self.flow_analyzer.taint_tracker.get_taint_source(arg)
                    
                    # Does rule care about this source?
                    if not declared_sources or source_type in declared_sources:
                        # Check sanitization if required
                        if check.get('requires_sanitization', True):
                            if not self.flow_analyzer.taint_tracker.is_sanitized(arg):
                                findings.append(self._make_taint_finding(
                                    node, filename, source_type, method_name, check
                                ))
                                break
        
        return findings
    
    def _check_method_name_match(self, node: Any, check: Dict) -> bool:
        """Check if node method name matches pattern."""
        if not hasattr(node, 'method_name'):
            return False
            
        target_names = check.get('method_names', check.get('value', []))
        if isinstance(target_names, str):
            target_names = [target_names]
            
        return getattr(node, 'method_name', '') in target_names
        
    def _check_source_regex(self, node: Any, check: Dict) -> bool:
        """Check if node source matches regex pattern."""
        patterns = check.get('patterns', [])
        source_code = getattr(node, 'source', '')
        
        for pattern in patterns:
            if re.search(pattern, source_code):
                return True
        return False
        
    def _check_node_type_match(self, node: Any, check: Dict) -> bool:
        """Check if node type matches target."""
        target_types = check.get('target_types', [])
        return getattr(node, 'node_type', '') in target_types
        
    def _check_literal_pattern_match(self, node: Any, check: Dict) -> bool:
        """Check if node contains literal pattern matches."""
        patterns = check.get('patterns', [])
        
        # Check multiple potential sources of text content
        sources_to_check = []
        
        # Add source attribute if available
        if hasattr(node, 'source') and getattr(node, 'source'):
            sources_to_check.append(getattr(node, 'source'))
            
        # Add method_name if available (for CallNode)
        if hasattr(node, 'method_name') and getattr(node, 'method_name'):
            sources_to_check.append(getattr(node, 'method_name'))
            
        # Add name if available (for ClassNode, etc.)
        if hasattr(node, 'name') and getattr(node, 'name'):
            sources_to_check.append(getattr(node, 'name'))
            
        # Add line-based source reading (fallback)
        line = getattr(node, 'line', 0)
        if line and hasattr(self, '_current_filename'):
            try:
                with open(self._current_filename, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if 0 <= line - 1 < len(lines):
                        sources_to_check.append(lines[line - 1].strip())
            except Exception:
                pass
        
        # Check if any pattern matches any source
        for source_text in sources_to_check:
            for pattern in patterns:
                if pattern in source_text:
                    return True
                    
        return False

    def _check_custom_function(self, node: Any, check: Dict) -> bool:
        """Execute custom function check."""
        function_name = check.get('function')
        if not function_name:
            return False
            
        if hasattr(ruby_logic_implementations, function_name):
            func = getattr(ruby_logic_implementations, function_name)
            try:
                # Convert AST node to dict format for custom functions
                node_dict = self._ast_node_to_dict(node)
                return func(node_dict)
            except Exception as e:
                print(f"Warning: Custom function {function_name} failed: {e}")
                return False
        return False
        
    def _check_property_comparison(self, node: Any, check: Dict) -> bool:
        """Check property values against expected values."""
        property_path = check.get('property_path', [])
        operator = check.get('operator', 'equals')
        expected_value = check.get('value')
        
        if not property_path:
            return False
            
        # Get the property value from the node
        current_value = node
        for prop in property_path:
            if hasattr(current_value, prop):
                current_value = getattr(current_value, prop)
            else:
                return False
                
        # Apply the comparison operator
        if operator == 'equals':
            return current_value == expected_value
        elif operator == 'contains':
            return expected_value in str(current_value)
        elif operator == 'startswith':
            return str(current_value).startswith(str(expected_value))
        elif operator == 'endswith':
            return str(current_value).endswith(str(expected_value))
        elif operator == 'regex_match':
            import re
            return bool(re.search(str(expected_value), str(current_value)))
        elif operator == 'greater_than':
            return current_value > expected_value
        elif operator == 'less_than':
            return current_value < expected_value
            
        return False
        
    def _ast_node_to_dict(self, node: Any) -> Dict[str, Any]:
        """Convert AST node to dictionary format for custom functions."""
        if not hasattr(node, 'node_type'):
            return {}
            
        node_dict = {
            'node_type': getattr(node, 'node_type', ''),
            'line': getattr(node, 'line', 0),
            'source': getattr(node, 'source', ''),
            'method_name': getattr(node, 'method_name', ''),
            'receiver': getattr(node, 'receiver', ''),
            'args': getattr(node, 'args', []),
            'target': getattr(node, 'target', ''),
            'value': getattr(node, 'value', ''),
            'name': getattr(node, 'name', ''),  # For ClassNode and other named nodes
            'params': getattr(node, 'params', []),  # For MethodNode parameters
            'children': getattr(node, 'children', []),  # For traversing child nodes
        }
        
        return node_dict
    
    def _find_nodes_by_type(self, ast_tree: Any, node_types: List[str]) -> List[Any]:
        """Find all nodes matching specified types."""
        found_nodes = []
        
        def traverse(node):
            if hasattr(node, 'node_type') and node.node_type in node_types:
                found_nodes.append(node)
                
            for child in getattr(node, 'children', []):
                traverse(child)
        
        traverse(ast_tree)
        return found_nodes
        
    def _make_finding(self, node: Any, filename: str, check: Dict) -> Dict[str, Any]:
        """Create finding from syntax/semantic check."""
        return {
            'rule_id': self.rule_id,
            'message': check.get('message', self.message),
            'file': filename,
            'line': getattr(node, 'line', 0),
            'status': 'violation'
        }
        
    def _make_taint_finding(self, node: Any, filename: str, source: str, sink: str, check: Dict) -> Dict[str, Any]:
        """Create finding from taint flow check."""
        return {
            'rule_id': self.rule_id,
            'message': check.get('message', f"Tainted data flows from {source} to {sink}"),
            'file': filename,
            'line': getattr(node, 'line', 0),
            'status': 'violation',
            'taint_flow': f"{source} -> {sink}"
        }


# ===== MAIN ENTRY POINT =====

def run_rule(metadata: Dict[str, Any], ast_tree: Any, filename: str) -> List[Dict[str, Any]]:
    """
    Main entry point following Sonar architecture:
    1. Perform analysis (separate from rules)
    2. Create rule with analysis context
    3. Rule queries analysis results
    """
    
    # PHASE 1: Analysis (independent of rules)
    flow_analyzer = FlowAnalyzer()
    flow_analyzer.analyze(ast_tree)
    
    # PHASE 2: Rule execution (queries analysis)
    rule = RubyGenericRule(metadata)
    rule.set_analysis_context(flow_analyzer)
    
    if not rule.is_applicable(ast_tree):
        return []
        
    return rule.check(ast_tree, filename)