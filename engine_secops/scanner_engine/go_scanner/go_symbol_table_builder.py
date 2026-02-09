"""
Go Symbol Table Builder Module

Builds symbol tables from Go AST for enhanced semantic analysis.
Tracks symbols, scopes, and their relationships.
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

@dataclass
class Symbol:
    """Symbol table entry."""
    name: str
    symbol_type: str  # 'function', 'variable', 'type', 'constant'
    scope: str
    line: int
    file: str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class Scope:
    """Scope information."""
    name: str
    parent: Optional['Scope'] = None
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    children: List['Scope'] = field(default_factory=list)

class GoSymbolTable:
    """Go-specific symbol table."""
    
    def __init__(self):
        self.global_scope = Scope("global")
        self.current_scope = self.global_scope
        self.all_symbols: Dict[str, Symbol] = {}
    
    def enter_scope(self, scope_name: str) -> Scope:
        """Enter a new scope."""
        new_scope = Scope(scope_name, parent=self.current_scope)
        self.current_scope.children.append(new_scope)
        self.current_scope = new_scope
        return new_scope
    
    def exit_scope(self) -> Optional[Scope]:
        """Exit current scope."""
        if self.current_scope.parent:
            self.current_scope = self.current_scope.parent
            return self.current_scope
        return None
    
    def add_symbol(self, symbol: Symbol) -> bool:
        """Add symbol to current scope."""
        # Check for conflicts in current scope
        if symbol.name in self.current_scope.symbols:
            return False  # Symbol already exists
        
        self.current_scope.symbols[symbol.name] = symbol
        self.all_symbols[f"{self.current_scope.name}::{symbol.name}"] = symbol
        return True
    
    def lookup_symbol(self, name: str) -> Optional[Symbol]:
        """Lookup symbol in current scope chain."""
        scope = self.current_scope
        while scope:
            if name in scope.symbols:
                return scope.symbols[name]
            scope = scope.parent
        return None
    
    def get_symbols_in_scope(self, scope_name: str) -> List[Symbol]:
        """Get all symbols in a specific scope."""
        return [symbol for key, symbol in self.all_symbols.items() 
                if symbol.scope == scope_name]
    
    def dump_symbol_table(self) -> Dict[str, Any]:
        """Dump symbol table for analysis."""
        return {
            'symbols': {key: {
                'name': symbol.name,
                'type': symbol.symbol_type,
                'scope': symbol.scope,
                'line': symbol.line,
                'file': symbol.file,
                'properties': symbol.properties
            } for key, symbol in self.all_symbols.items()},
            'scopes': self._dump_scope(self.global_scope)
        }
    
    def _dump_scope(self, scope: Scope) -> Dict[str, Any]:
        """Recursively dump scope structure."""
        return {
            'name': scope.name,
            'symbols': list(scope.symbols.keys()),
            'children': [self._dump_scope(child) for child in scope.children]
        }

def build_symbol_table_from_ast(ast: Dict[str, Any]) -> GoSymbolTable:
    """Build symbol table from Go AST."""
    symbol_table = GoSymbolTable()
    
    # Get file info
    filename = ast.get('filename', 'unknown')
    
    # Add package symbol
    package_name = ast.get('package_name', 'main')
    package_symbol = Symbol(
        name=package_name,
        symbol_type='package',
        scope='global',
        line=1,
        file=filename,
        properties={'is_main': package_name == 'main'}
    )
    symbol_table.add_symbol(package_symbol)
    
    # Add import symbols
    imports = ast.get('imports', [])
    for import_path in imports:
        import_name = import_path.split('/')[-1] if '/' in import_path else import_path
        import_symbol = Symbol(
            name=import_name,
            symbol_type='import',
            scope='global',
            line=1,
            file=filename,
            properties={'import_path': import_path}
        )
        symbol_table.add_symbol(import_symbol)
    
    # Process AST children
    children = ast.get('children', [])
    _process_ast_nodes(children, symbol_table, filename)
    
    return symbol_table

def _process_ast_nodes(nodes: List[Dict[str, Any]], symbol_table: GoSymbolTable, filename: str):
    """Process AST nodes to extract symbols."""
    for node in nodes:
        node_type = node.get('node_type', '')
        line = node.get('line', 0)
        properties = node.get('properties', {})
        
        if node_type == 'function_declaration':
            # Enter function scope
            func_name = properties.get('name', 'anonymous')
            func_scope = symbol_table.enter_scope(func_name)
            
            # Add function symbol
            func_symbol = Symbol(
                name=func_name,
                symbol_type='function',
                scope=symbol_table.current_scope.parent.name if symbol_table.current_scope.parent else 'global',
                line=line,
                file=filename,
                properties={
                    'parameters': properties.get('parameters', ''),
                    'is_exported': properties.get('is_exported', False),
                    'is_method': properties.get('is_method', False)
                }
            )
            
            # Add to parent scope
            if symbol_table.current_scope.parent:
                original_scope = symbol_table.current_scope
                symbol_table.current_scope = symbol_table.current_scope.parent
                symbol_table.add_symbol(func_symbol)
                symbol_table.current_scope = original_scope
            
            # Process function parameters as symbols
            params = properties.get('parameters', '')
            if params:
                _process_parameters(params, symbol_table, filename, line)
            
            # Process function body
            children = node.get('children', [])
            _process_ast_nodes(children, symbol_table, filename)
            
            # Exit function scope
            symbol_table.exit_scope()
        
        elif node_type == 'variable_declaration':
            var_name = properties.get('name', 'unknown')
            var_symbol = Symbol(
                name=var_name,
                symbol_type='variable',
                scope=symbol_table.current_scope.name,
                line=line,
                file=filename,
                properties={
                    'var_type': properties.get('type', 'unknown'),
                    'is_global': symbol_table.current_scope.name == 'global'
                }
            )
            symbol_table.add_symbol(var_symbol)
        
        elif node_type == 'type_declaration':
            type_name = properties.get('name', 'unknown')
            type_symbol = Symbol(
                name=type_name,
                symbol_type='type',
                scope=symbol_table.current_scope.name,
                line=line,
                file=filename,
                properties={
                    'type_kind': properties.get('kind', 'unknown'),
                    'is_exported': type_name[0].isupper() if type_name != 'unknown' else False
                }
            )
            symbol_table.add_symbol(type_symbol)
        
        elif node_type == 'const_declaration':
            const_name = properties.get('name', 'unknown')
            const_symbol = Symbol(
                name=const_name,
                symbol_type='constant',
                scope=symbol_table.current_scope.name,
                line=line,
                file=filename,
                properties={
                    'value': properties.get('value', ''),
                    'const_type': properties.get('type', 'unknown')
                }
            )
            symbol_table.add_symbol(const_symbol)
        
        # Process children recursively
        children = node.get('children', [])
        if children:
            _process_ast_nodes(children, symbol_table, filename)

def _process_parameters(params_str: str, symbol_table: GoSymbolTable, filename: str, line: int):
    """Process function parameters and add as symbols."""
    if not params_str.strip():
        return
    
    # Simple parameter parsing
    # This is a basic implementation - real parser would be more sophisticated
    param_parts = params_str.split(',')
    
    for param in param_parts:
        param = param.strip()
        if param:
            # Extract parameter name and type
            if ' ' in param:
                parts = param.split()
                param_name = parts[0].strip()
                param_type = ' '.join(parts[1:]).strip()
            else:
                param_name = param
                param_type = 'unknown'
            
            param_symbol = Symbol(
                name=param_name,
                symbol_type='parameter',
                scope=symbol_table.current_scope.name,
                line=line,
                file=filename,
                properties={
                    'param_type': param_type,
                    'is_parameter': True
                }
            )
            symbol_table.add_symbol(param_symbol)