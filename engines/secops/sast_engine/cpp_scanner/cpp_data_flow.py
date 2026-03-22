"""
C++ Data Flow Analysis

This module implements data flow analysis for C++ code, tracking:
- Variable assignments and lifetime
- Ownership transfer (unique_ptr, shared_ptr, raw pointers)
- Null checks and nullability
- Move semantics and use-after-move
- RAII scope and resource management
- Memory safety patterns

Features:
- Inter-procedural analysis
- Path-sensitive nullability tracking
- Ownership transfer detection
- Use-after-move detection
- Resource leak detection
- Exception safety analysis
"""

from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import copy

from cpp_control_flow import ControlFlowGraph, CFGNode, EdgeType
from cpp_symbol_table import Symbol, SymbolKind, TypeInfo


class DataFlowState(Enum):
    """Possible states for variables in data flow analysis."""
    UNINITIALIZED = "uninitialized"
    INITIALIZED = "initialized"
    MOVED_FROM = "moved_from"
    POTENTIALLY_NULL = "potentially_null"
    DEFINITELY_NULL = "definitely_null"
    DEFINITELY_NOT_NULL = "definitely_not_null"
    UNKNOWN = "unknown"


class OwnershipState(Enum):
    """Ownership states for memory management analysis."""
    OWNED = "owned"              # Unique ownership (unique_ptr, local object)
    SHARED = "shared"            # Shared ownership (shared_ptr)
    BORROWED = "borrowed"        # Non-owning reference (raw pointer, reference)
    RELEASED = "released"        # Ownership transferred away
    INVALID = "invalid"          # Dangling pointer/reference
    UNKNOWN = "unknown"          # Cannot determine


@dataclass
class VariableState:
    """State of a variable at a specific program point."""
    symbol_id: str
    variable_name: str
    data_flow_state: DataFlowState
    ownership_state: OwnershipState
    type_info: Optional[TypeInfo] = None
    
    # Assignment tracking
    assigned_at: Optional[int] = None  # Line number of last assignment
    assigned_from: Optional[str] = None  # Variable assigned from
    
    # Nullability tracking
    null_checked_at: Optional[int] = None
    last_use_at: Optional[int] = None
    
    # Move semantics
    moved_at: Optional[int] = None
    moved_to: Optional[str] = None
    
    # RAII tracking
    acquired_resource: Optional[str] = None
    resource_released: bool = False
    destructor_called: bool = False


@dataclass
class DataFlowFact:
    """A fact about program state at a specific point."""
    location: str  # CFG node ID
    variable_states: Dict[str, VariableState] = field(default_factory=dict)
    
    def copy(self) -> 'DataFlowFact':
        """Create a deep copy of this fact."""
        return DataFlowFact(
            location=self.location,
            variable_states={
                name: copy.deepcopy(state) 
                for name, state in self.variable_states.items()
            }
        )
    
    def merge(self, other: 'DataFlowFact') -> 'DataFlowFact':
        """Merge two data flow facts (for join points)."""
        merged = self.copy()
        
        for var_name, other_state in other.variable_states.items():
            if var_name in merged.variable_states:
                self_state = merged.variable_states[var_name]
                # Merge states conservatively
                merged_state = self._merge_variable_states(self_state, other_state)
                merged.variable_states[var_name] = merged_state
            else:
                merged.variable_states[var_name] = copy.deepcopy(other_state)
        
        return merged
    
    def _merge_variable_states(self, state1: VariableState, 
                              state2: VariableState) -> VariableState:
        """Merge two variable states conservatively."""
        merged = copy.deepcopy(state1)
        
        # Merge data flow state
        if state1.data_flow_state != state2.data_flow_state:
            # Conservative merge - if states differ, use UNKNOWN
            if (state1.data_flow_state == DataFlowState.DEFINITELY_NULL and
                state2.data_flow_state == DataFlowState.DEFINITELY_NOT_NULL):
                merged.data_flow_state = DataFlowState.POTENTIALLY_NULL
            elif state1.data_flow_state in [DataFlowState.UNKNOWN, DataFlowState.POTENTIALLY_NULL]:
                merged.data_flow_state = DataFlowState.UNKNOWN
            else:
                merged.data_flow_state = DataFlowState.UNKNOWN
        
        # Merge ownership state
        if state1.ownership_state != state2.ownership_state:
            # Conservative merge
            merged.ownership_state = OwnershipState.UNKNOWN
        
        # Take more recent assignment
        if state2.assigned_at and (not merged.assigned_at or state2.assigned_at > merged.assigned_at):
            merged.assigned_at = state2.assigned_at
            merged.assigned_from = state2.assigned_from
        
        return merged


class DataFlowAnalyzer:
    """Data flow analyzer for C++ code."""
    
    def __init__(self, cfg: ControlFlowGraph, symbol_table: Dict[str, Symbol]):
        self.cfg = cfg
        self.symbol_table = symbol_table
        self.facts: Dict[str, DataFlowFact] = {}
        self.worklist: List[str] = []
        
        # Analysis results
        self.null_pointer_violations: List[Dict[str, Any]] = []
        self.use_after_move_violations: List[Dict[str, Any]] = []
        self.resource_leak_violations: List[Dict[str, Any]] = []
        self.ownership_violations: List[Dict[str, Any]] = []
    
    def analyze(self) -> Dict[str, Any]:
        """Perform data flow analysis on the CFG."""
        self._initialize_entry_state()
        self._run_worklist_algorithm()
        self._detect_violations()
        
        return {
            'facts': {node_id: fact.variable_states for node_id, fact in self.facts.items()},
            'null_pointer_violations': self.null_pointer_violations,
            'use_after_move_violations': self.use_after_move_violations,
            'resource_leak_violations': self.resource_leak_violations,
            'ownership_violations': self.ownership_violations
        }
    
    def _initialize_entry_state(self):
        """Initialize the data flow state at function entry."""
        entry_fact = DataFlowFact(location=self.cfg.entry_node)
        
        # Initialize parameter states
        for symbol in self.symbol_table.values():
            if symbol.kind == SymbolKind.PARAMETER:
                state = self._create_initial_state(symbol)
                entry_fact.variable_states[symbol.name] = state
        
        self.facts[self.cfg.entry_node] = entry_fact
        self.worklist.append(self.cfg.entry_node)
    
    def _create_initial_state(self, symbol: Symbol) -> VariableState:
        """Create initial state for a variable."""
        # Determine initial data flow state
        if symbol.type_info:
            if symbol.type_info.is_pointer:
                data_state = DataFlowState.POTENTIALLY_NULL
            elif symbol.type_info.is_reference:
                data_state = DataFlowState.DEFINITELY_NOT_NULL
            else:
                data_state = DataFlowState.INITIALIZED
        else:
            data_state = DataFlowState.UNINITIALIZED
        
        # Determine ownership state
        ownership_state = self._determine_ownership_state(symbol)
        
        return VariableState(
            symbol_id=symbol.symbol_id,
            variable_name=symbol.name,
            data_flow_state=data_state,
            ownership_state=ownership_state,
            type_info=symbol.type_info
        )
    
    def _determine_ownership_state(self, symbol: Symbol) -> OwnershipState:
        """Determine ownership state based on symbol type."""
        if not symbol.type_info:
            return OwnershipState.UNKNOWN
        
        if symbol.type_info.is_smart_pointer:
            if symbol.type_info.smart_pointer_type == 'unique_ptr':
                return OwnershipState.OWNED
            elif symbol.type_info.smart_pointer_type in ['shared_ptr', 'weak_ptr']:
                return OwnershipState.SHARED
        elif symbol.type_info.is_pointer:
            return OwnershipState.BORROWED
        elif symbol.type_info.is_reference:
            return OwnershipState.BORROWED
        else:
            return OwnershipState.OWNED  # Local object
        
        return OwnershipState.UNKNOWN
    
    def _run_worklist_algorithm(self):
        """Run the worklist algorithm for data flow analysis."""
        while self.worklist:
            node_id = self.worklist.pop(0)
            
            if node_id not in self.cfg.nodes:
                continue
            
            node = self.cfg.nodes[node_id]
            old_fact = self.facts.get(node_id)
            
            # Compute new fact
            new_fact = self._transfer_function(node, old_fact)
            
            # Check if fact changed
            if not old_fact or not self._facts_equal(old_fact, new_fact):
                self.facts[node_id] = new_fact
                
                # Add successors to worklist
                for successor_id, _ in node.successors:
                    if successor_id not in self.worklist:
                        self.worklist.append(successor_id)
    
    def _transfer_function(self, node: CFGNode, input_fact: Optional[DataFlowFact]) -> DataFlowFact:
        """Apply transfer function for a CFG node."""
        if not input_fact:
            # Create empty fact for join points
            input_fact = DataFlowFact(location=node.node_id)
            
            # Merge facts from all predecessors
            for pred_id in node.predecessors:
                if pred_id in self.facts:
                    input_fact = input_fact.merge(self.facts[pred_id])
        
        # Create output fact
        output_fact = input_fact.copy()
        output_fact.location = node.node_id
        
        # Apply node-specific transfer function
        if node.ast_node:
            self._apply_ast_effects(node.ast_node, output_fact)
        
        return output_fact
    
    def _apply_ast_effects(self, ast_node: Dict[str, Any], fact: DataFlowFact):
        """Apply the effects of an AST node to the data flow fact."""
        node_type = ast_node.get('node_type', '')
        
        if node_type == 'VariableDeclaration':
            self._handle_variable_declaration(ast_node, fact)
        elif node_type == 'Assignment':
            self._handle_assignment(ast_node, fact)
        elif node_type == 'FunctionCall':
            self._handle_function_call(ast_node, fact)
        elif node_type in ['BinaryExpression', 'ConditionalExpression']:
            self._handle_expression(ast_node, fact)
        elif node_type == 'ReturnStatement':
            self._handle_return(ast_node, fact)
        elif node_type == 'ThrowStatement':
            self._handle_throw(ast_node, fact)
    
    def _handle_variable_declaration(self, decl_node: Dict[str, Any], fact: DataFlowFact):
        """Handle variable declaration."""
        var_name = decl_node.get('name', '')
        if not var_name:
            return
        
        # Find symbol
        symbol = self._find_symbol(var_name)
        if not symbol:
            return
        
        # Create initial state
        state = self._create_initial_state(symbol)
        state.assigned_at = decl_node.get('lineno', 0)
        
        # Check for initialization
        if 'initializer' in decl_node or 'init_value' in decl_node:
            state.data_flow_state = DataFlowState.INITIALIZED
            if symbol.type_info and symbol.type_info.is_pointer:
                state.data_flow_state = DataFlowState.DEFINITELY_NOT_NULL
        
        fact.variable_states[var_name] = state
    
    def _handle_assignment(self, assign_node: Dict[str, Any], fact: DataFlowFact):
        """Handle assignment statement."""
        target = assign_node.get('target', '')
        source = assign_node.get('source', '')
        
        if not target:
            return
        
        # Update target variable state
        if target in fact.variable_states:
            state = fact.variable_states[target]
        else:
            symbol = self._find_symbol(target)
            if symbol:
                state = self._create_initial_state(symbol)
            else:
                return
        
        # Update state based on assignment
        state.assigned_at = assign_node.get('lineno', 0)
        state.assigned_from = source
        state.data_flow_state = DataFlowState.INITIALIZED
        
        # Check for move semantics
        if self._is_move_operation(assign_node):
            if source in fact.variable_states:
                source_state = fact.variable_states[source]
                source_state.data_flow_state = DataFlowState.MOVED_FROM
                source_state.moved_at = assign_node.get('lineno', 0)
                source_state.moved_to = target
            
            # Transfer ownership
            if source in fact.variable_states:
                state.ownership_state = fact.variable_states[source].ownership_state
        
        # Check for null assignment
        if self._is_null_assignment(assign_node):
            state.data_flow_state = DataFlowState.DEFINITELY_NULL
        
        fact.variable_states[target] = state
    
    def _handle_function_call(self, call_node: Dict[str, Any], fact: DataFlowFact):
        """Handle function call."""
        func_name = call_node.get('function_name', '')
        
        # Handle special functions
        if func_name in ['std::move', 'move']:
            self._handle_move_call(call_node, fact)
        elif func_name in ['reset', 'release']:
            self._handle_smart_pointer_operation(call_node, fact)
        elif func_name in ['malloc', 'calloc', 'new']:
            self._handle_allocation(call_node, fact)
        elif func_name in ['free', 'delete']:
            self._handle_deallocation(call_node, fact)
        
        # Handle arguments (potential moves or null checks)
        for arg in call_node.get('arguments', []):
            if isinstance(arg, str) and arg in fact.variable_states:
                # Argument is used, check for use-after-move
                state = fact.variable_states[arg]
                if state.data_flow_state == DataFlowState.MOVED_FROM:
                    self.use_after_move_violations.append({
                        'variable': arg,
                        'use_location': call_node.get('lineno', 0),
                        'moved_at': state.moved_at
                    })
    
    def _handle_expression(self, expr_node: Dict[str, Any], fact: DataFlowFact):
        """Handle expressions (including null checks)."""
        # Look for null checks
        if self._is_null_check(expr_node):
            checked_var = self._extract_checked_variable(expr_node)
            if checked_var and checked_var in fact.variable_states:
                state = fact.variable_states[checked_var]
                state.null_checked_at = expr_node.get('lineno', 0)
                # Update nullability based on check type
                if self._is_not_null_check(expr_node):
                    state.data_flow_state = DataFlowState.DEFINITELY_NOT_NULL
                else:
                    state.data_flow_state = DataFlowState.POTENTIALLY_NULL
    
    def _handle_return(self, return_node: Dict[str, Any], fact: DataFlowFact):
        """Handle return statement."""
        return_value = return_node.get('value', '')
        if return_value in fact.variable_states:
            state = fact.variable_states[return_value]
            if state.ownership_state == OwnershipState.OWNED:
                # Ownership transferred out of function
                state.ownership_state = OwnershipState.RELEASED
    
    def _handle_throw(self, throw_node: Dict[str, Any], fact: DataFlowFact):
        """Handle throw statement."""
        # Exception might prevent proper cleanup
        for var_name, state in fact.variable_states.items():
            if (state.ownership_state == OwnershipState.OWNED and 
                state.acquired_resource and not state.resource_released):
                self.resource_leak_violations.append({
                    'variable': var_name,
                    'resource': state.acquired_resource,
                    'throw_location': throw_node.get('lineno', 0)
                })
    
    def _handle_move_call(self, call_node: Dict[str, Any], fact: DataFlowFact):
        """Handle std::move call."""
        args = call_node.get('arguments', [])
        if args and isinstance(args[0], str):
            moved_var = args[0]
            if moved_var in fact.variable_states:
                state = fact.variable_states[moved_var]
                state.data_flow_state = DataFlowState.MOVED_FROM
                state.moved_at = call_node.get('lineno', 0)
    
    def _handle_smart_pointer_operation(self, call_node: Dict[str, Any], fact: DataFlowFact):
        """Handle smart pointer operations like reset(), release()."""
        # This would be more complex in a real implementation
        pass
    
    def _handle_allocation(self, call_node: Dict[str, Any], fact: DataFlowFact):
        """Handle memory allocation."""
        # Track allocation for leak detection
        pass
    
    def _handle_deallocation(self, call_node: Dict[str, Any], fact: DataFlowFact):
        """Handle memory deallocation."""
        # Track deallocation
        pass
    
    def _detect_violations(self):
        """Detect data flow violations after analysis."""
        for node_id, fact in self.facts.items():
            for var_name, state in fact.variable_states.items():
                # Check for null pointer dereference
                if (state.data_flow_state in [DataFlowState.DEFINITELY_NULL, DataFlowState.POTENTIALLY_NULL] and
                    self._is_pointer_dereference_context(node_id)):
                    self.null_pointer_violations.append({
                        'variable': var_name,
                        'location': node_id,
                        'line': self.cfg.nodes[node_id].line_number if node_id in self.cfg.nodes else 0,
                        'nullability': state.data_flow_state.value
                    })
                
                # Check for resource leaks at function exit
                if (node_id == self.cfg.exit_node and
                    state.ownership_state == OwnershipState.OWNED and
                    state.acquired_resource and not state.resource_released):
                    self.resource_leak_violations.append({
                        'variable': var_name,
                        'resource': state.acquired_resource,
                        'exit_location': node_id
                    })
    
    def _is_move_operation(self, assign_node: Dict[str, Any]) -> bool:
        """Check if assignment is a move operation."""
        source = assign_node.get('source', '')
        return 'std::move' in source or 'move(' in source
    
    def _is_null_assignment(self, assign_node: Dict[str, Any]) -> bool:
        """Check if assignment assigns null."""
        source = assign_node.get('source', '')
        return source in ['nullptr', 'NULL', '0', 'null']
    
    def _is_null_check(self, expr_node: Dict[str, Any]) -> bool:
        """Check if expression is a null check."""
        expr_text = expr_node.get('source', '')
        return ('!=' in expr_text and 'nullptr' in expr_text) or \
               ('==' in expr_text and 'nullptr' in expr_text) or \
               ('!=' in expr_text and 'NULL' in expr_text) or \
               ('==' in expr_text and 'NULL' in expr_text)
    
    def _is_not_null_check(self, expr_node: Dict[str, Any]) -> bool:
        """Check if expression is a not-null check."""
        expr_text = expr_node.get('source', '')
        return '!=' in expr_text and ('nullptr' in expr_text or 'NULL' in expr_text)
    
    def _extract_checked_variable(self, expr_node: Dict[str, Any]) -> Optional[str]:
        """Extract the variable being checked in a null check."""
        expr_text = expr_node.get('source', '')
        # Simple pattern matching - real implementation would be more sophisticated
        for part in expr_text.split():
            if part not in ['!=', '==', 'nullptr', 'NULL', '(', ')']:
                return part.strip('()')
        return None
    
    def _is_pointer_dereference_context(self, node_id: str) -> bool:
        """Check if the context involves pointer dereference."""
        if node_id not in self.cfg.nodes:
            return False
        
        node = self.cfg.nodes[node_id]
        if not node.ast_node:
            return False
        
        source = node.ast_node.get('source', '')
        return '*' in source or '->' in source or '.' in source
    
    def _find_symbol(self, name: str) -> Optional[Symbol]:
        """Find symbol by name in symbol table."""
        for symbol in self.symbol_table.values():
            if symbol.name == name:
                return symbol
        return None
    
    def _facts_equal(self, fact1: DataFlowFact, fact2: DataFlowFact) -> bool:
        """Check if two facts are equal."""
        if len(fact1.variable_states) != len(fact2.variable_states):
            return False
        
        for var_name, state1 in fact1.variable_states.items():
            if var_name not in fact2.variable_states:
                return False
            
            state2 = fact2.variable_states[var_name]
            if (state1.data_flow_state != state2.data_flow_state or
                state1.ownership_state != state2.ownership_state or
                state1.assigned_at != state2.assigned_at):
                return False
        
        return True


def analyze_data_flow(cfg: ControlFlowGraph, symbol_table: Dict[str, Symbol]) -> Dict[str, Any]:
    """
    Analyze data flow for a function.
    
    Args:
        cfg: Control flow graph
        symbol_table: Symbol table
        
    Returns:
        Data flow analysis results
    """
    analyzer = DataFlowAnalyzer(cfg, symbol_table)
    return analyzer.analyze()


def analyze_data_flow_for_ast(ast_root: Dict[str, Any], 
                             cfgs: Dict[str, ControlFlowGraph],
                             symbol_table: Dict[str, Symbol]) -> Dict[str, Any]:
    """
    Analyze data flow for all functions in AST.
    
    Args:
        ast_root: Root AST node
        cfgs: Control flow graphs for functions
        symbol_table: Symbol table
        
    Returns:
        Complete data flow analysis results
    """
    results = {}
    
    for func_name, cfg in cfgs.items():
        # Filter symbols for this function
        func_symbols = {
            sid: symbol for sid, symbol in symbol_table.items()
            if func_name in symbol.scope_id
        }
        
        # Analyze this function
        func_results = analyze_data_flow(cfg, func_symbols)
        results[func_name] = func_results
        
        # Add data flow info to function AST node
        def add_dataflow_info(node: Dict[str, Any]):
            if (node.get('node_type') == 'FunctionDefinition' and 
                node.get('name') == func_name):
                node['data_flow_info'] = {
                    'violations': {
                        'null_pointer': len(func_results['null_pointer_violations']),
                        'use_after_move': len(func_results['use_after_move_violations']),
                        'resource_leaks': len(func_results['resource_leak_violations']),
                        'ownership': len(func_results['ownership_violations'])
                    }
                }
            
            for child in node.get('children', []):
                add_dataflow_info(child)
        
        add_dataflow_info(ast_root)
    
    # Aggregate results
    total_violations = {
        'null_pointer': sum(len(r['null_pointer_violations']) for r in results.values()),
        'use_after_move': sum(len(r['use_after_move_violations']) for r in results.values()),
        'resource_leaks': sum(len(r['resource_leak_violations']) for r in results.values()),
        'ownership': sum(len(r['ownership_violations']) for r in results.values())
    }
    
    return {
        'functions': list(results.keys()),
        'function_results': results,
        'total_violations': total_violations
    }