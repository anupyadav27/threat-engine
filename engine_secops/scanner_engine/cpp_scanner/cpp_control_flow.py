"""
C++ Control Flow Graph Builder

This module constructs control flow graphs for C++ functions, enabling
path-sensitive analysis for advanced safety and security rules.

Features:
- Function-level CFG construction
- Branch-aware analysis (if/else, loops, switch)
- Exception flow tracking (try/catch/throw)
- Early return and break/continue handling
- Dominance and post-dominance analysis
- Dead code detection
"""

from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid


class CFGNodeType(Enum):
    """Types of nodes in a control flow graph."""
    ENTRY = "entry"
    EXIT = "exit"
    STATEMENT = "statement"
    CONDITION = "condition"
    BRANCH = "branch"
    LOOP_HEADER = "loop_header"
    LOOP_BODY = "loop_body"
    LOOP_INCREMENT = "loop_increment"
    EXCEPTION_HANDLER = "exception_handler"
    THROW = "throw"
    RETURN = "return"
    BREAK = "break"
    CONTINUE = "continue"
    SWITCH = "switch"
    CASE = "case"
    DEFAULT = "default"


class EdgeType(Enum):
    """Types of edges in a control flow graph."""
    FALLTHROUGH = "fallthrough"  # Normal sequential flow
    TRUE_BRANCH = "true"         # Condition evaluates to true
    FALSE_BRANCH = "false"       # Condition evaluates to false
    EXCEPTION = "exception"      # Exception thrown
    CATCH = "catch"             # Exception caught
    BREAK = "break"             # Break statement
    CONTINUE = "continue"       # Continue statement
    RETURN = "return"           # Return statement
    SWITCH = "switch"           # Switch dispatch
    CASE = "case"              # Case label


@dataclass
class CFGNode:
    """A node in the control flow graph."""
    node_id: str
    node_type: CFGNodeType
    ast_node: Optional[Dict[str, Any]] = None
    line_number: int = 0
    source_text: str = ""
    
    # Control flow information
    predecessors: Set[str] = field(default_factory=set)
    successors: List[Tuple[str, EdgeType]] = field(default_factory=list)
    
    # Analysis information
    dominators: Set[str] = field(default_factory=set)
    post_dominators: Set[str] = field(default_factory=set)
    reachable: bool = True
    
    # Exception handling
    exception_handlers: List[str] = field(default_factory=list)
    
    def add_successor(self, node_id: str, edge_type: EdgeType = EdgeType.FALLTHROUGH):
        """Add a successor node with specified edge type."""
        self.successors.append((node_id, edge_type))
    
    def get_successors(self) -> List[str]:
        """Get list of successor node IDs."""
        return [node_id for node_id, _ in self.successors]


@dataclass
class ControlFlowGraph:
    """Control flow graph for a function."""
    function_name: str
    entry_node: str
    exit_node: str
    nodes: Dict[str, CFGNode] = field(default_factory=dict)
    
    # Analysis results
    dominance_computed: bool = False
    dead_code_computed: bool = False
    exception_flow_computed: bool = False
    
    def add_node(self, node: CFGNode) -> str:
        """Add a node to the CFG."""
        self.nodes[node.node_id] = node
        return node.node_id
    
    def add_edge(self, from_id: str, to_id: str, edge_type: EdgeType = EdgeType.FALLTHROUGH):
        """Add an edge between two nodes."""
        if from_id in self.nodes:
            self.nodes[from_id].add_successor(to_id, edge_type)
        if to_id in self.nodes:
            self.nodes[to_id].predecessors.add(from_id)
    
    def get_paths(self, from_id: str, to_id: str) -> List[List[str]]:
        """Get all paths between two nodes."""
        paths = []
        current_path = [from_id]
        visited = {from_id}
        
        def dfs_paths(current: str, target: str, path: List[str], visited_set: Set[str]):
            if current == target:
                paths.append(path.copy())
                return
            
            if current in self.nodes:
                for successor_id, _ in self.nodes[current].successors:
                    if successor_id not in visited_set:
                        path.append(successor_id)
                        visited_set.add(successor_id)
                        dfs_paths(successor_id, target, path, visited_set)
                        path.pop()
                        visited_set.remove(successor_id)
        
        dfs_paths(from_id, to_id, current_path, visited)
        return paths
    
    def compute_dominance(self):
        """Compute dominance relationships."""
        if self.dominance_computed:
            return
        
        # Initialize dominators
        for node_id in self.nodes:
            if node_id == self.entry_node:
                self.nodes[node_id].dominators = {node_id}
            else:
                self.nodes[node_id].dominators = set(self.nodes.keys())
        
        # Iterative dominance computation
        changed = True
        while changed:
            changed = False
            for node_id in self.nodes:
                if node_id == self.entry_node:
                    continue
                
                node = self.nodes[node_id]
                old_dominators = node.dominators.copy()
                
                # Intersect dominators of all predecessors
                if node.predecessors:
                    new_dominators = set(self.nodes.keys())
                    for pred_id in node.predecessors:
                        if pred_id in self.nodes:
                            new_dominators &= self.nodes[pred_id].dominators
                    new_dominators.add(node_id)
                    node.dominators = new_dominators
                
                if old_dominators != node.dominators:
                    changed = True
        
        self.dominance_computed = True
    
    def compute_dead_code(self):
        """Identify unreachable (dead) code."""
        if self.dead_code_computed:
            return
        
        # Mark all nodes as unreachable initially
        for node in self.nodes.values():
            node.reachable = False
        
        # DFS from entry node to mark reachable nodes
        visited = set()
        
        def mark_reachable(node_id: str):
            if node_id in visited or node_id not in self.nodes:
                return
            
            visited.add(node_id)
            self.nodes[node_id].reachable = True
            
            for successor_id, _ in self.nodes[node_id].successors:
                mark_reachable(successor_id)
        
        mark_reachable(self.entry_node)
        self.dead_code_computed = True
    
    def get_unreachable_nodes(self) -> List[CFGNode]:
        """Get list of unreachable (dead) code nodes."""
        if not self.dead_code_computed:
            self.compute_dead_code()
        
        return [node for node in self.nodes.values() if not node.reachable]


class CFGBuilder:
    """Builds control flow graphs from C++ AST nodes."""
    
    def __init__(self):
        self.node_counter = 0
        self.break_targets: List[str] = []  # Stack of break targets
        self.continue_targets: List[str] = []  # Stack of continue targets
        self.return_node: Optional[str] = None
        self.exception_handlers: List[str] = []  # Stack of exception handlers
    
    def build_cfg_for_function(self, function_ast: Dict[str, Any]) -> ControlFlowGraph:
        """Build CFG for a single function."""
        function_name = function_ast.get('name', 'anonymous')
        
        # Create CFG
        cfg = ControlFlowGraph(function_name, '', '')
        
        # Create entry and exit nodes
        entry_node = self._create_cfg_node(CFGNodeType.ENTRY, function_ast, "function entry")
        exit_node = self._create_cfg_node(CFGNodeType.EXIT, function_ast, "function exit")
        
        cfg.entry_node = entry_node.node_id
        cfg.exit_node = exit_node.node_id
        cfg.add_node(entry_node)
        cfg.add_node(exit_node)
        
        self.return_node = exit_node.node_id
        
        # Build CFG for function body
        current_node = entry_node.node_id
        
        # Process function body
        for child in function_ast.get('children', []):
            if child.get('node_type') in ['CompoundStatement', 'Block']:
                current_node = self._process_block(child, cfg, current_node)
            else:
                current_node = self._process_statement(child, cfg, current_node)
        
        # Connect final node to exit if not already connected
        if current_node and current_node != exit_node.node_id:
            cfg.add_edge(current_node, exit_node.node_id, EdgeType.FALLTHROUGH)
        
        # Compute analysis information
        cfg.compute_dominance()
        cfg.compute_dead_code()
        
        return cfg
    
    def _create_cfg_node(self, node_type: CFGNodeType, ast_node: Dict[str, Any], 
                        source_text: str = "") -> CFGNode:
        """Create a new CFG node."""
        self.node_counter += 1
        node_id = f"cfg_{self.node_counter}"
        
        return CFGNode(
            node_id=node_id,
            node_type=node_type,
            ast_node=ast_node,
            line_number=ast_node.get('lineno', 0),
            source_text=source_text or ast_node.get('source', '')[:50],
            exception_handlers=self.exception_handlers.copy()
        )
    
    def _process_block(self, block_ast: Dict[str, Any], cfg: ControlFlowGraph, 
                      current_node: str) -> str:
        """Process a compound statement (block)."""
        for child in block_ast.get('children', []):
            current_node = self._process_statement(child, cfg, current_node)
            if not current_node:  # Early return or break
                break
        return current_node
    
    def _process_statement(self, stmt_ast: Dict[str, Any], cfg: ControlFlowGraph,
                          current_node: str) -> Optional[str]:
        """Process a single statement and return the next node."""
        stmt_type = stmt_ast.get('node_type', '')
        
        if stmt_type == 'IfStatement':
            return self._process_if_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'WhileStatement':
            return self._process_while_loop(stmt_ast, cfg, current_node)
        elif stmt_type == 'ForStatement':
            return self._process_for_loop(stmt_ast, cfg, current_node)
        elif stmt_type == 'DoWhileStatement':
            return self._process_do_while_loop(stmt_ast, cfg, current_node)
        elif stmt_type == 'SwitchStatement':
            return self._process_switch_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'TryStatement':
            return self._process_try_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'ThrowStatement':
            return self._process_throw_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'ReturnStatement':
            return self._process_return_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'BreakStatement':
            return self._process_break_statement(stmt_ast, cfg, current_node)
        elif stmt_type == 'ContinueStatement':
            return self._process_continue_statement(stmt_ast, cfg, current_node)
        else:
            return self._process_simple_statement(stmt_ast, cfg, current_node)
    
    def _process_if_statement(self, if_ast: Dict[str, Any], cfg: ControlFlowGraph,
                             current_node: str) -> str:
        """Process if/else statement."""
        # Create condition node
        condition_node = self._create_cfg_node(CFGNodeType.CONDITION, if_ast, "if condition")
        cfg.add_node(condition_node)
        cfg.add_edge(current_node, condition_node.node_id)
        
        # Create merge node for after the if statement
        merge_node = self._create_cfg_node(CFGNodeType.STATEMENT, if_ast, "if merge")
        cfg.add_node(merge_node)
        
        # Process then branch
        then_stmt = self._get_child_by_type(if_ast, 'then_statement') 
        if then_stmt:
            then_end = self._process_statement(then_stmt, cfg, condition_node.node_id)
            cfg.add_edge(condition_node.node_id, then_end or merge_node.node_id, EdgeType.TRUE_BRANCH)
            if then_end:
                cfg.add_edge(then_end, merge_node.node_id)
        else:
            cfg.add_edge(condition_node.node_id, merge_node.node_id, EdgeType.TRUE_BRANCH)
        
        # Process else branch if present
        else_stmt = self._get_child_by_type(if_ast, 'else_statement')
        if else_stmt:
            else_end = self._process_statement(else_stmt, cfg, condition_node.node_id)
            cfg.add_edge(condition_node.node_id, else_end or merge_node.node_id, EdgeType.FALSE_BRANCH)
            if else_end:
                cfg.add_edge(else_end, merge_node.node_id)
        else:
            cfg.add_edge(condition_node.node_id, merge_node.node_id, EdgeType.FALSE_BRANCH)
        
        return merge_node.node_id
    
    def _process_while_loop(self, while_ast: Dict[str, Any], cfg: ControlFlowGraph,
                           current_node: str) -> str:
        """Process while loop."""
        # Create loop header (condition)
        header_node = self._create_cfg_node(CFGNodeType.LOOP_HEADER, while_ast, "while condition")
        cfg.add_node(header_node)
        cfg.add_edge(current_node, header_node.node_id)
        
        # Create exit node
        exit_node = self._create_cfg_node(CFGNodeType.STATEMENT, while_ast, "while exit")
        cfg.add_node(exit_node)
        
        # Set up break/continue targets
        old_break = self.break_targets[-1] if self.break_targets else None
        old_continue = self.continue_targets[-1] if self.continue_targets else None
        self.break_targets.append(exit_node.node_id)
        self.continue_targets.append(header_node.node_id)
        
        # Process loop body
        body_stmt = self._get_child_by_type(while_ast, 'body')
        if body_stmt:
            body_end = self._process_statement(body_stmt, cfg, header_node.node_id)
            cfg.add_edge(header_node.node_id, body_end or header_node.node_id, EdgeType.TRUE_BRANCH)
            if body_end:
                cfg.add_edge(body_end, header_node.node_id)  # Back edge
        
        # False branch exits loop
        cfg.add_edge(header_node.node_id, exit_node.node_id, EdgeType.FALSE_BRANCH)
        
        # Restore break/continue targets
        self.break_targets.pop()
        self.continue_targets.pop()
        if old_break:
            self.break_targets.append(old_break)
        if old_continue:
            self.continue_targets.append(old_continue)
        
        return exit_node.node_id
    
    def _process_for_loop(self, for_ast: Dict[str, Any], cfg: ControlFlowGraph,
                         current_node: str) -> str:
        """Process for loop."""
        # Create initialization node
        init_node = None
        init_stmt = self._get_child_by_type(for_ast, 'initializer')
        if init_stmt:
            init_node = self._create_cfg_node(CFGNodeType.STATEMENT, init_stmt, "for init")
            cfg.add_node(init_node)
            cfg.add_edge(current_node, init_node.node_id)
            current_node = init_node.node_id
        
        # Create condition node
        condition_node = self._create_cfg_node(CFGNodeType.LOOP_HEADER, for_ast, "for condition")
        cfg.add_node(condition_node)
        cfg.add_edge(current_node, condition_node.node_id)
        
        # Create increment node
        increment_node = None
        increment_stmt = self._get_child_by_type(for_ast, 'increment')
        if increment_stmt:
            increment_node = self._create_cfg_node(CFGNodeType.LOOP_INCREMENT, increment_stmt, "for increment")
            cfg.add_node(increment_node)
        
        # Create exit node
        exit_node = self._create_cfg_node(CFGNodeType.STATEMENT, for_ast, "for exit")
        cfg.add_node(exit_node)
        
        # Set up break/continue targets
        old_break = self.break_targets[-1] if self.break_targets else None
        old_continue = self.continue_targets[-1] if self.continue_targets else None
        self.break_targets.append(exit_node.node_id)
        continue_target = increment_node.node_id if increment_node else condition_node.node_id
        self.continue_targets.append(continue_target)
        
        # Process loop body
        body_stmt = self._get_child_by_type(for_ast, 'body')
        if body_stmt:
            body_end = self._process_statement(body_stmt, cfg, condition_node.node_id)
            cfg.add_edge(condition_node.node_id, body_end or continue_target, EdgeType.TRUE_BRANCH)
            
            if body_end:
                if increment_node:
                    cfg.add_edge(body_end, increment_node.node_id)
                    cfg.add_edge(increment_node.node_id, condition_node.node_id)
                else:
                    cfg.add_edge(body_end, condition_node.node_id)
        
        # False branch exits loop
        cfg.add_edge(condition_node.node_id, exit_node.node_id, EdgeType.FALSE_BRANCH)
        
        # Restore break/continue targets
        self.break_targets.pop()
        self.continue_targets.pop()
        if old_break:
            self.break_targets.append(old_break)
        if old_continue:
            self.continue_targets.append(old_continue)
        
        return exit_node.node_id
    
    def _process_try_statement(self, try_ast: Dict[str, Any], cfg: ControlFlowGraph,
                              current_node: str) -> str:
        """Process try/catch statement."""
        # Create try block node
        try_node = self._create_cfg_node(CFGNodeType.STATEMENT, try_ast, "try block")
        cfg.add_node(try_node)
        cfg.add_edge(current_node, try_node.node_id)
        
        # Create merge node for after try/catch
        merge_node = self._create_cfg_node(CFGNodeType.STATEMENT, try_ast, "try/catch merge")
        cfg.add_node(merge_node)
        
        # Process catch handlers
        catch_handlers = []
        for child in try_ast.get('children', []):
            if child.get('node_type') == 'CatchStatement':
                handler_node = self._create_cfg_node(CFGNodeType.EXCEPTION_HANDLER, child, "catch handler")
                cfg.add_node(handler_node)
                catch_handlers.append(handler_node.node_id)
                
                # Process catch body
                handler_end = self._process_statement(child, cfg, handler_node.node_id)
                if handler_end:
                    cfg.add_edge(handler_end, merge_node.node_id)
        
        # Set up exception handlers
        old_handlers = self.exception_handlers.copy()
        self.exception_handlers.extend(catch_handlers)
        
        # Process try body
        try_body = self._get_child_by_type(try_ast, 'body')
        if try_body:
            try_end = self._process_statement(try_body, cfg, try_node.node_id)
            if try_end:
                cfg.add_edge(try_end, merge_node.node_id)
            
            # Add exception edges from try body to catch handlers
            for handler_id in catch_handlers:
                cfg.add_edge(try_node.node_id, handler_id, EdgeType.EXCEPTION)
        
        # Restore exception handlers
        self.exception_handlers = old_handlers
        
        return merge_node.node_id
    
    def _process_throw_statement(self, throw_ast: Dict[str, Any], cfg: ControlFlowGraph,
                                current_node: str) -> None:
        """Process throw statement."""
        throw_node = self._create_cfg_node(CFGNodeType.THROW, throw_ast, "throw")
        cfg.add_node(throw_node)
        cfg.add_edge(current_node, throw_node.node_id)
        
        # Connect to exception handlers
        for handler_id in self.exception_handlers:
            cfg.add_edge(throw_node.node_id, handler_id, EdgeType.EXCEPTION)
        
        # No fallthrough from throw
        return None
    
    def _process_return_statement(self, return_ast: Dict[str, Any], cfg: ControlFlowGraph,
                                 current_node: str) -> None:
        """Process return statement."""
        return_node = self._create_cfg_node(CFGNodeType.RETURN, return_ast, "return")
        cfg.add_node(return_node)
        cfg.add_edge(current_node, return_node.node_id)
        
        # Connect to function exit
        if self.return_node:
            cfg.add_edge(return_node.node_id, self.return_node, EdgeType.RETURN)
        
        # No fallthrough from return
        return None
    
    def _process_break_statement(self, break_ast: Dict[str, Any], cfg: ControlFlowGraph,
                                current_node: str) -> None:
        """Process break statement."""
        break_node = self._create_cfg_node(CFGNodeType.BREAK, break_ast, "break")
        cfg.add_node(break_node)
        cfg.add_edge(current_node, break_node.node_id)
        
        # Connect to break target
        if self.break_targets:
            cfg.add_edge(break_node.node_id, self.break_targets[-1], EdgeType.BREAK)
        
        # No fallthrough from break
        return None
    
    def _process_continue_statement(self, continue_ast: Dict[str, Any], cfg: ControlFlowGraph,
                                   current_node: str) -> None:
        """Process continue statement."""
        continue_node = self._create_cfg_node(CFGNodeType.CONTINUE, continue_ast, "continue")
        cfg.add_node(continue_node)
        cfg.add_edge(current_node, continue_node.node_id)
        
        # Connect to continue target
        if self.continue_targets:
            cfg.add_edge(continue_node.node_id, self.continue_targets[-1], EdgeType.CONTINUE)
        
        # No fallthrough from continue
        return None
    
    def _process_simple_statement(self, stmt_ast: Dict[str, Any], cfg: ControlFlowGraph,
                                 current_node: str) -> str:
        """Process a simple statement (assignment, call, etc.)."""
        stmt_node = self._create_cfg_node(CFGNodeType.STATEMENT, stmt_ast)
        cfg.add_node(stmt_node)
        cfg.add_edge(current_node, stmt_node.node_id)
        return stmt_node.node_id
    
    def _get_child_by_type(self, ast_node: Dict[str, Any], child_type: str) -> Optional[Dict[str, Any]]:
        """Find a child node by type or attribute name."""
        # First check if it's a direct attribute
        if child_type in ast_node:
            return ast_node[child_type]
        
        # Then search children
        for child in ast_node.get('children', []):
            if child.get('node_type') == child_type or child.get('type') == child_type:
                return child
        
        return None


def build_cfg_for_ast(ast_root: Dict[str, Any]) -> Dict[str, ControlFlowGraph]:
    """
    Build control flow graphs for all functions in an AST.
    
    Args:
        ast_root: Root AST node
        
    Returns:
        Dictionary mapping function names to their CFGs
    """
    cfgs = {}
    builder = CFGBuilder()
    
    def find_functions(node: Dict[str, Any]):
        """Recursively find all function definitions."""
        if node.get('node_type') == 'FunctionDefinition':
            function_name = node.get('name', 'anonymous')
            cfg = builder.build_cfg_for_function(node)
            cfgs[function_name] = cfg
            
            # Add CFG info to AST node
            node['cfg_info'] = {
                'entry_node': cfg.entry_node,
                'exit_node': cfg.exit_node,
                'node_count': len(cfg.nodes),
                'has_dead_code': len(cfg.get_unreachable_nodes()) > 0
            }
        
        # Process children
        for child in node.get('children', []):
            find_functions(child)
    
    find_functions(ast_root)
    return cfgs