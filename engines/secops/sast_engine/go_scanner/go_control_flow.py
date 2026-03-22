"""
Go Control Flow Analysis Module

Builds control flow graphs (CFGs) for Go functions to enable 
flow-sensitive static analysis.
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

@dataclass
class CFGNode:
    """Control flow graph node."""
    id: str
    node_type: str  # 'entry', 'exit', 'statement', 'condition', 'goroutine'
    line: int
    statements: List[Dict[str, Any]] = field(default_factory=list)
    successors: Set['CFGNode'] = field(default_factory=set)
    predecessors: Set['CFGNode'] = field(default_factory=set)
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, CFGNode):
            return self.id == other.id
        return False
    
    def add_successor(self, node: 'CFGNode'):
        """Add successor node."""
        self.successors.add(node)
        node.predecessors.add(self)
    
    def remove_successor(self, node: 'CFGNode'):
        """Remove successor node."""
        if node in self.successors:
            self.successors.remove(node)
        if self in node.predecessors:
            node.predecessors.remove(self)

@dataclass
class ControlFlowGraph:
    """Control flow graph for a function."""
    function_name: str
    entry_node: CFGNode
    exit_node: CFGNode
    nodes: Dict[str, CFGNode] = field(default_factory=dict)
    goroutine_nodes: List[CFGNode] = field(default_factory=list)
    
    def add_node(self, node: CFGNode):
        """Add node to CFG."""
        self.nodes[node.id] = node
        if node.node_type == 'goroutine':
            self.goroutine_nodes.append(node)
    
    def get_reachable_nodes(self, from_node: CFGNode) -> Set[CFGNode]:
        """Get all nodes reachable from given node."""
        visited = set()
        stack = [from_node]
        
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            
            visited.add(current)
            stack.extend(current.successors)
        
        return visited
    
    def get_unreachable_nodes(self) -> Set[CFGNode]:
        """Get nodes unreachable from entry."""
        reachable = self.get_reachable_nodes(self.entry_node)
        all_nodes = set(self.nodes.values())
        return all_nodes - reachable
    
    def has_goroutines(self) -> bool:
        """Check if function creates goroutines."""
        return len(self.goroutine_nodes) > 0
    
    def get_paths_to_exit(self, from_node: CFGNode) -> List[List[CFGNode]]:
        """Get all paths from node to exit."""
        paths = []
        self._find_paths_to_exit(from_node, self.exit_node, [], paths, set())
        return paths
    
    def _find_paths_to_exit(self, current: CFGNode, target: CFGNode, 
                           path: List[CFGNode], all_paths: List[List[CFGNode]],
                           visited: Set[CFGNode]):
        """Recursively find paths to exit node."""
        if current in visited:
            return
        
        visited.add(current)
        path.append(current)
        
        if current == target:
            all_paths.append(path.copy())
        else:
            for successor in current.successors:
                self._find_paths_to_exit(successor, target, path, all_paths, visited.copy())
        
        path.pop()

def build_cfg_for_ast(ast: Dict[str, Any]) -> Dict[str, ControlFlowGraph]:
    """Build control flow graphs for all functions in AST."""
    cfgs = {}
    
    # Extract functions from AST
    functions = _extract_functions_from_ast(ast)
    
    for func_name, func_ast in functions.items():
        try:
            cfg = _build_function_cfg(func_name, func_ast)
            cfgs[func_name] = cfg
        except Exception as e:
            print(f"Failed to build CFG for function {func_name}: {e}")
            # Create minimal CFG as fallback
            cfgs[func_name] = _create_minimal_cfg(func_name)
    
    return cfgs

def _extract_functions_from_ast(ast: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract function declarations from AST."""
    functions = {}
    
    def extract_from_nodes(nodes: List[Dict[str, Any]]):
        for node in nodes:
            if node.get('node_type') == 'function_declaration':
                func_name = node.get('properties', {}).get('name', 'anonymous')
                functions[func_name] = node
            
            # Recursively check children
            children = node.get('children', [])
            if children:
                extract_from_nodes(children)
    
    children = ast.get('children', [])
    extract_from_nodes(children)
    
    return functions

def _build_function_cfg(func_name: str, func_ast: Dict[str, Any]) -> ControlFlowGraph:
    """Build CFG for a single function."""
    
    # Create entry and exit nodes
    entry_node = CFGNode(
        id=f"{func_name}_entry",
        node_type='entry',
        line=func_ast.get('line', 0),
        properties={'function': func_name}
    )
    
    exit_node = CFGNode(
        id=f"{func_name}_exit", 
        node_type='exit',
        line=func_ast.get('end_line', func_ast.get('line', 0)),
        properties={'function': func_name}
    )
    
    # Create CFG
    cfg = ControlFlowGraph(
        function_name=func_name,
        entry_node=entry_node,
        exit_node=exit_node
    )
    
    cfg.add_node(entry_node)
    cfg.add_node(exit_node)
    
    # Build CFG from function body
    children = func_ast.get('children', [])
    if children:
        current_node = entry_node
        current_node = _process_statements(children, cfg, current_node, exit_node)
        
        # Connect final node to exit if not already connected
        if current_node and current_node != exit_node:
            current_node.add_successor(exit_node)
    else:
        # Empty function - connect entry directly to exit
        entry_node.add_successor(exit_node)
    
    return cfg

def _process_statements(statements: List[Dict[str, Any]], 
                       cfg: ControlFlowGraph,
                       current_node: CFGNode,
                       exit_node: CFGNode) -> CFGNode:
    """Process a list of statements and build CFG."""
    
    for i, stmt in enumerate(statements):
        stmt_type = stmt.get('node_type', '')
        line = stmt.get('line', 0)
        
        if stmt_type == 'if_statement':
            current_node = _process_if_statement(stmt, cfg, current_node, exit_node)
        
        elif stmt_type == 'for_statement' or stmt_type == 'while_statement':
            current_node = _process_loop_statement(stmt, cfg, current_node, exit_node)
        
        elif stmt_type == 'switch_statement':
            current_node = _process_switch_statement(stmt, cfg, current_node, exit_node)
        
        elif stmt_type == 'return_statement':
            current_node = _process_return_statement(stmt, cfg, current_node, exit_node)
        
        elif stmt_type == 'go_statement':
            current_node = _process_goroutine_statement(stmt, cfg, current_node, exit_node)
        
        else:
            # Regular statement
            stmt_node = CFGNode(
                id=f"{cfg.function_name}_stmt_{line}_{i}",
                node_type='statement',
                line=line,
                statements=[stmt],
                properties={'statement_type': stmt_type}
            )
            
            cfg.add_node(stmt_node)
            current_node.add_successor(stmt_node)
            current_node = stmt_node
    
    return current_node

def _process_if_statement(stmt: Dict[str, Any], cfg: ControlFlowGraph, 
                         current_node: CFGNode, exit_node: CFGNode) -> CFGNode:
    """Process if statement and build CFG branches."""
    line = stmt.get('line', 0)
    
    # Create condition node
    condition_node = CFGNode(
        id=f"{cfg.function_name}_if_{line}",
        node_type='condition',
        line=line,
        statements=[stmt],
        properties={'condition_type': 'if'}
    )
    
    cfg.add_node(condition_node)
    current_node.add_successor(condition_node)
    
    # Create merge node for after if
    merge_node = CFGNode(
        id=f"{cfg.function_name}_merge_{line}",
        node_type='statement',
        line=line + 1,
        properties={'merge_point': True}
    )
    cfg.add_node(merge_node)
    
    # Process then branch
    then_body = stmt.get('then_body', [])
    if then_body:
        then_end = _process_statements(then_body, cfg, condition_node, exit_node)
        then_end.add_successor(merge_node)
    else:
        condition_node.add_successor(merge_node)
    
    # Process else branch if exists
    else_body = stmt.get('else_body', [])
    if else_body:
        else_end = _process_statements(else_body, cfg, condition_node, exit_node)
        else_end.add_successor(merge_node)
    else:
        condition_node.add_successor(merge_node)
    
    return merge_node

def _process_loop_statement(stmt: Dict[str, Any], cfg: ControlFlowGraph,
                           current_node: CFGNode, exit_node: CFGNode) -> CFGNode:
    """Process loop statement and build CFG with back edges."""
    line = stmt.get('line', 0)
    
    # Create loop header node
    loop_header = CFGNode(
        id=f"{cfg.function_name}_loop_{line}",
        node_type='condition',
        line=line,
        statements=[stmt],
        properties={'condition_type': 'loop'}
    )
    
    cfg.add_node(loop_header)
    current_node.add_successor(loop_header)
    
    # Create loop exit node
    loop_exit = CFGNode(
        id=f"{cfg.function_name}_loop_exit_{line}",
        node_type='statement',
        line=line + 1,
        properties={'loop_exit': True}
    )
    cfg.add_node(loop_exit)
    
    # Process loop body
    body = stmt.get('body', [])
    if body:
        body_end = _process_statements(body, cfg, loop_header, exit_node)
        # Back edge to loop header
        body_end.add_successor(loop_header)
    
    # Loop exit edge
    loop_header.add_successor(loop_exit)
    
    return loop_exit

def _process_switch_statement(stmt: Dict[str, Any], cfg: ControlFlowGraph,
                             current_node: CFGNode, exit_node: CFGNode) -> CFGNode:
    """Process switch statement with multiple branches."""
    line = stmt.get('line', 0)
    
    # Create switch node
    switch_node = CFGNode(
        id=f"{cfg.function_name}_switch_{line}",
        node_type='condition',
        line=line,
        statements=[stmt],
        properties={'condition_type': 'switch'}
    )
    
    cfg.add_node(switch_node)
    current_node.add_successor(switch_node)
    
    # Create merge node
    merge_node = CFGNode(
        id=f"{cfg.function_name}_switch_merge_{line}",
        node_type='statement',
        line=line + 1,
        properties={'switch_merge': True}
    )
    cfg.add_node(merge_node)
    
    # Process cases
    cases = stmt.get('cases', [])
    for case in cases:
        case_body = case.get('body', [])
        if case_body:
            case_end = _process_statements(case_body, cfg, switch_node, exit_node)
            case_end.add_successor(merge_node)
        else:
            switch_node.add_successor(merge_node)
    
    # Default case
    switch_node.add_successor(merge_node)
    
    return merge_node

def _process_return_statement(stmt: Dict[str, Any], cfg: ControlFlowGraph,
                             current_node: CFGNode, exit_node: CFGNode) -> CFGNode:
    """Process return statement - connects directly to exit."""
    line = stmt.get('line', 0)
    
    return_node = CFGNode(
        id=f"{cfg.function_name}_return_{line}",
        node_type='statement',
        line=line,
        statements=[stmt],
        properties={'statement_type': 'return'}
    )
    
    cfg.add_node(return_node)
    current_node.add_successor(return_node)
    return_node.add_successor(exit_node)
    
    # Return statement doesn't continue to next statement
    return None

def _process_goroutine_statement(stmt: Dict[str, Any], cfg: ControlFlowGraph,
                                current_node: CFGNode, exit_node: CFGNode) -> CFGNode:
    """Process goroutine statement."""
    line = stmt.get('line', 0)
    
    goroutine_node = CFGNode(
        id=f"{cfg.function_name}_goroutine_{line}",
        node_type='goroutine',
        line=line,
        statements=[stmt],
        properties={
            'statement_type': 'goroutine',
            'called_function': stmt.get('properties', {}).get('called_function', 'unknown')
        }
    )
    
    cfg.add_node(goroutine_node)
    current_node.add_successor(goroutine_node)
    
    return goroutine_node

def _create_minimal_cfg(func_name: str) -> ControlFlowGraph:
    """Create minimal CFG when full analysis fails."""
    entry_node = CFGNode(
        id=f"{func_name}_entry",
        node_type='entry',
        line=0,
        properties={'function': func_name}
    )
    
    exit_node = CFGNode(
        id=f"{func_name}_exit",
        node_type='exit',
        line=0,
        properties={'function': func_name}
    )
    
    cfg = ControlFlowGraph(
        function_name=func_name,
        entry_node=entry_node,
        exit_node=exit_node
    )
    
    cfg.add_node(entry_node)
    cfg.add_node(exit_node)
    entry_node.add_successor(exit_node)
    
    return cfg