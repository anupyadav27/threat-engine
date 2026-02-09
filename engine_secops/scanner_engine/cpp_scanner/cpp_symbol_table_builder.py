"""
C++ Symbol Table Builder

This module builds symbol tables from C++ ASTs, providing semantic analysis
capabilities while maintaining compatibility with the existing rule engine.

Features:
- Builds symbol table from tree-sitter or regex AST
- Tracks all symbols across scopes
- Resolves types and references
- Enables overload resolution
- Maintains AST compatibility by adding symbol_id fields
"""

from typing import Dict, List, Optional, Any, Set
import re
from cpp_symbol_table import (
    SymbolTable, Symbol, SymbolKind, AccessSpecifier, TypeInfo, Scope
)


class CppSymbolTableBuilder:
    """
    Builds symbol tables from C++ AST nodes while preserving AST structure.
    
    This class analyzes AST nodes and populates a symbol table, then enhances
    the AST nodes with symbol_id references for semantic analysis.
    """
    
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.current_access = AccessSpecifier.PUBLIC
        self.current_class = None
        self.processing_template = False
        self.template_params = []
    
    def build_symbol_table(self, ast_root: Dict[str, Any]) -> SymbolTable:
        """
        Build symbol table from AST root and enhance AST nodes with symbol IDs.
        
        Args:
            ast_root: The root AST node from parser
            
        Returns:
            Populated symbol table
        """
        # Process the AST tree
        self._process_node(ast_root)
        
        # Add symbol_id fields to AST nodes
        self._add_symbol_ids_to_ast(ast_root)
        
        return self.symbol_table
    
    def _process_node(self, node: Dict[str, Any]):
        """Process a single AST node and its children."""
        node_type = node.get('node_type', '')
        
        if node_type == 'TranslationUnit':
            self._process_translation_unit(node)
        elif node_type in ['NamespaceDeclaration']:
            self._process_namespace(node)
        elif node_type in ['ClassDeclaration', 'StructDeclaration']:
            self._process_class(node)
        elif node_type == 'FunctionDefinition':
            self._process_function(node)
        elif node_type == 'TemplateDeclaration':
            self._process_template(node)
        elif node_type == 'VariableDeclaration':
            self._process_variable(node)
        elif node_type in ['FunctionCall']:
            self._process_function_call(node)
        elif node_type == 'UsingDeclaration':
            self._process_using_declaration(node)
        
        # Process children
        for child in node.get('children', []):
            self._process_node(child)
    
    def _process_translation_unit(self, node: Dict[str, Any]):
        """Process translation unit (file root)."""
        # Already in global scope, just set metadata
        node['symbol_table_info'] = {
            'scope_id': self.symbol_table.current_scope_id,
            'symbols_count': 0
        }
    
    def _process_namespace(self, node: Dict[str, Any]):
        """Process namespace declaration."""
        namespace_name = node.get('name', 'anonymous')
        start_line = node.get('lineno', 0)
        
        # Enter namespace scope
        scope_id = self.symbol_table.enter_scope('namespace', namespace_name, start_line)
        
        # Create namespace symbol
        namespace_symbol = Symbol(
            name=namespace_name,
            kind=SymbolKind.NAMESPACE,
            type_info=None,
            scope_id=scope_id,
            definition_line=start_line,
            definition_file=node.get('filename', '<unknown>')
        )
        
        symbol_id = self.symbol_table.add_symbol(namespace_symbol)
        
        # Add symbol info to node
        node['symbol_id'] = symbol_id
        node['scope_id'] = scope_id
        
        # Process namespace body
        for child in node.get('children', []):
            self._process_node(child)
        
        # Exit namespace scope
        end_line = node.get('end_line', start_line)
        self.symbol_table.exit_scope(end_line)
    
    def _process_class(self, node: Dict[str, Any]):
        """Process class or struct declaration."""
        class_name = node.get('name', 'anonymous')
        start_line = node.get('lineno', 0)
        is_struct = node.get('node_type') == 'StructDeclaration'
        
        # Enter class scope
        scope_id = self.symbol_table.enter_scope('class', class_name, start_line)
        
        # Parse type information
        type_info = TypeInfo(name=class_name)
        
        # Create class symbol
        class_kind = SymbolKind.STRUCT if is_struct else SymbolKind.CLASS
        class_symbol = Symbol(
            name=class_name,
            kind=class_kind,
            type_info=type_info,
            scope_id=scope_id,
            definition_line=start_line,
            definition_file=node.get('filename', '<unknown>'),
            base_classes=node.get('base_classes', [])
        )
        
        symbol_id = self.symbol_table.add_symbol(class_symbol)
        
        # Add inheritance relationships
        base_classes = node.get('base_classes', [])
        if base_classes:
            self.symbol_table.add_inheritance(class_name, base_classes)
        
        # Set current class context
        old_class = self.current_class
        self.current_class = class_name
        old_access = self.current_access
        self.current_access = AccessSpecifier.PUBLIC if is_struct else AccessSpecifier.PRIVATE
        
        # Add symbol info to node
        node['symbol_id'] = symbol_id
        node['scope_id'] = scope_id
        
        # Process class members
        self._process_class_members(node)
        
        # Process children
        for child in node.get('children', []):
            self._process_node(child)
        
        # Restore context
        self.current_class = old_class
        self.current_access = old_access
        
        # Exit class scope
        end_line = node.get('end_line', start_line)
        self.symbol_table.exit_scope(end_line)
    
    def _process_class_members(self, class_node: Dict[str, Any]):
        """Process class members from the members list."""
        members = class_node.get('members', [])
        for member in members:
            if isinstance(member, dict):
                member_type = member.get('member_type', '')
                if member_type == 'access_specifier':
                    self._update_access_specifier(member.get('access', 'public'))
                elif member_type in ['method', 'function']:
                    self._process_member_function(member, class_node)
                elif member_type in ['variable', 'field']:
                    self._process_member_variable(member, class_node)
    
    def _update_access_specifier(self, access: str):
        """Update current access specifier."""
        access_map = {
            'public': AccessSpecifier.PUBLIC,
            'private': AccessSpecifier.PRIVATE,
            'protected': AccessSpecifier.PROTECTED
        }
        self.current_access = access_map.get(access, AccessSpecifier.PUBLIC)
    
    def _process_member_function(self, member: Dict[str, Any], class_node: Dict[str, Any]):
        """Process a member function."""
        func_name = member.get('name', 'anonymous')
        start_line = member.get('lineno', 0)
        
        # Determine function kind
        class_name = class_node.get('name', '')
        if func_name == class_name:
            kind = SymbolKind.CONSTRUCTOR
            is_constructor = True
        elif func_name == f"~{class_name}":
            kind = SymbolKind.DESTRUCTOR
            is_destructor = True
        elif func_name.startswith('operator'):
            kind = SymbolKind.OPERATOR
            is_operator_overload = True
        else:
            kind = SymbolKind.MEMBER_FUNCTION
            is_constructor = is_destructor = is_operator_overload = False
        
        # Parse return type
        return_type = None
        if not is_constructor and not is_destructor:
            return_type_str = member.get('return_type', 'void')
            return_type = self._parse_type(return_type_str)
        
        # Parse parameters
        parameters = []
        for param in member.get('parameters', []):
            param_type = self._parse_type(param.get('type', ''))
            param_symbol = Symbol(
                name=param.get('name', ''),
                kind=SymbolKind.PARAMETER,
                type_info=param_type,
                scope_id='',  # Will be set when function scope is created
                definition_line=start_line,
                definition_file=class_node.get('filename', '<unknown>')
            )
            parameters.append(param_symbol)
        
        # Create function symbol
        func_symbol = Symbol(
            name=func_name,
            kind=kind,
            type_info=None,  # Functions don't have type_info, they have return_type
            scope_id=self.symbol_table.current_scope_id,
            definition_line=start_line,
            definition_file=class_node.get('filename', '<unknown>'),
            is_static=member.get('is_static', False),
            is_virtual=member.get('is_virtual', False),
            is_const=member.get('is_const', False),
            access=self.current_access,
            parameters=parameters,
            return_type=return_type,
            is_constructor=is_constructor,
            is_destructor=is_destructor,
            is_operator_overload=is_operator_overload
        )
        
        symbol_id = self.symbol_table.add_symbol(func_symbol)
        member['symbol_id'] = symbol_id
    
    def _process_member_variable(self, member: Dict[str, Any], class_node: Dict[str, Any]):
        """Process a member variable."""
        var_name = member.get('name', 'anonymous')
        start_line = member.get('lineno', 0)
        
        # Parse type
        type_info = self._parse_type(member.get('type', ''))
        
        # Create variable symbol
        var_symbol = Symbol(
            name=var_name,
            kind=SymbolKind.MEMBER_VARIABLE,
            type_info=type_info,
            scope_id=self.symbol_table.current_scope_id,
            definition_line=start_line,
            definition_file=class_node.get('filename', '<unknown>'),
            is_static=member.get('is_static', False),
            is_const=member.get('is_const', False),
            access=self.current_access
        )
        
        symbol_id = self.symbol_table.add_symbol(var_symbol)
        member['symbol_id'] = symbol_id
    
    def _process_function(self, node: Dict[str, Any]):
        """Process function definition."""
        func_name = node.get('name', 'anonymous')
        start_line = node.get('lineno', 0)
        
        # Enter function scope
        scope_id = self.symbol_table.enter_scope('function', func_name, start_line)
        
        # Parse return type
        return_type_str = node.get('return_type', 'void')
        return_type = self._parse_type(return_type_str)
        
        # Parse parameters
        parameters = []
        for param in node.get('parameters', []):
            param_type = self._parse_type(param.get('type', ''))
            param_symbol = Symbol(
                name=param.get('name', ''),
                kind=SymbolKind.PARAMETER,
                type_info=param_type,
                scope_id=scope_id,
                definition_line=start_line,
                definition_file=node.get('filename', '<unknown>')
            )
            parameters.append(param_symbol)
            # Add parameter to function scope
            self.symbol_table.add_symbol(param_symbol)
        
        # Create function symbol
        func_symbol = Symbol(
            name=func_name,
            kind=SymbolKind.FUNCTION,
            type_info=None,
            scope_id=self.symbol_table.current_scope_id,
            definition_line=start_line,
            definition_file=node.get('filename', '<unknown>'),
            is_static=node.get('is_static', False),
            is_virtual=node.get('is_virtual', False),
            is_const=node.get('is_const', False),
            is_template=self.processing_template,
            template_parameters=self.template_params.copy() if self.processing_template else [],
            parameters=parameters,
            return_type=return_type
        )
        
        symbol_id = self.symbol_table.add_symbol(func_symbol)
        
        # Add symbol info to node
        node['symbol_id'] = symbol_id
        node['scope_id'] = scope_id
        
        # Process function body
        for child in node.get('children', []):
            self._process_node(child)
        
        # Exit function scope
        end_line = node.get('end_line', start_line)
        self.symbol_table.exit_scope(end_line)
    
    def _process_template(self, node: Dict[str, Any]):
        """Process template declaration."""
        template_params = node.get('template_params', '')
        start_line = node.get('lineno', 0)
        
        # Parse template parameters
        old_template_state = self.processing_template
        old_template_params = self.template_params
        
        self.processing_template = True
        self.template_params = self._parse_template_parameters(template_params)
        
        # Add symbol info to node
        node['template_info'] = {
            'parameters': self.template_params,
            'is_template': True
        }
        
        # Process the templated declaration
        for child in node.get('children', []):
            self._process_node(child)
        
        # Restore template state
        self.processing_template = old_template_state
        self.template_params = old_template_params
    
    def _process_variable(self, node: Dict[str, Any]):
        """Process variable declaration."""
        var_name = node.get('name', 'anonymous')
        start_line = node.get('lineno', 0)
        
        # Parse type
        type_info = self._parse_type(node.get('type', ''))
        
        # Create variable symbol
        var_symbol = Symbol(
            name=var_name,
            kind=SymbolKind.VARIABLE,
            type_info=type_info,
            scope_id=self.symbol_table.current_scope_id,
            definition_line=start_line,
            definition_file=node.get('filename', '<unknown>'),
            is_static=node.get('is_static', False),
            is_const=node.get('is_const', False)
        )
        
        symbol_id = self.symbol_table.add_symbol(var_symbol)
        
        # Add symbol info to node
        node['symbol_id'] = symbol_id
    
    def _process_function_call(self, node: Dict[str, Any]):
        """Process function call to add references."""
        func_name = node.get('function_name', '')
        if func_name:
            line = node.get('lineno', 0)
            file = node.get('filename', '<unknown>')
            self.symbol_table.add_reference(func_name, line, file)
            
            # Try to resolve the call
            symbol = self.symbol_table.lookup_symbol(func_name)
            if symbol:
                node['resolved_symbol_id'] = symbol.symbol_id
    
    def _process_using_declaration(self, node: Dict[str, Any]):
        """Process using declarations and directives."""
        # For using namespace directives, we could add namespace imports
        # For using declarations, we could add type aliases
        pass
    
    def _parse_type(self, type_str: str) -> TypeInfo:
        """Parse a type string into TypeInfo."""
        if not type_str:
            return TypeInfo(name='void')
        
        # Clean up type string
        type_str = type_str.strip()
        
        # Initialize type info
        type_info = TypeInfo(name='')
        
        # Parse const/volatile qualifiers
        if 'const' in type_str:
            type_info.is_const = True
            type_str = re.sub(r'\bconst\b', '', type_str).strip()
        
        if 'volatile' in type_str:
            type_info.is_volatile = True
            type_str = re.sub(r'\bvolatile\b', '', type_str).strip()
        
        # Parse pointers
        type_info.pointer_depth = type_str.count('*')
        type_str = type_str.replace('*', '').strip()
        type_info.is_pointer = type_info.pointer_depth > 0
        
        # Parse references
        if '&&' in type_str:
            type_info.is_rvalue_reference = True
            type_str = type_str.replace('&&', '').strip()
        elif '&' in type_str:
            type_info.is_reference = True
            type_str = type_str.replace('&', '').strip()
        
        # Parse arrays
        array_match = re.search(r'(.+?)\[([^\]]*)\]', type_str)
        if array_match:
            type_str = array_match.group(1).strip()
            type_info.is_array = True
            # Parse array dimensions
            dimension_str = array_match.group(2)
            if dimension_str.isdigit():
                type_info.array_dimensions.append(int(dimension_str))
            else:
                type_info.array_dimensions.append(None)
        
        # Parse template arguments
        template_match = re.match(r'(.+?)<(.+)>', type_str)
        if template_match:
            base_type = template_match.group(1).strip()
            template_args_str = template_match.group(2)
            type_info.name = base_type
            type_info.is_template = True
            
            # Parse template arguments (simplified)
            for arg in template_args_str.split(','):
                arg_type = self._parse_type(arg.strip())
                type_info.template_args.append(arg_type)
        else:
            type_info.name = type_str
        
        # Check for smart pointers
        smart_pointer_types = {
            'unique_ptr': 'unique_ptr',
            'shared_ptr': 'shared_ptr',
            'weak_ptr': 'weak_ptr',
            'std::unique_ptr': 'unique_ptr',
            'std::shared_ptr': 'shared_ptr',
            'std::weak_ptr': 'weak_ptr'
        }
        
        if type_info.name in smart_pointer_types:
            type_info.is_smart_pointer = True
            type_info.smart_pointer_type = smart_pointer_types[type_info.name]
        
        return type_info
    
    def _parse_template_parameters(self, params_str: str) -> List[str]:
        """Parse template parameter list."""
        if not params_str or not isinstance(params_str, str):
            return []
        
        # Simple parsing - split by comma and extract parameter names
        params = []
        for param in params_str.split(','):
            param = param.strip()
            # Extract parameter name (after 'typename' or 'class')
            if 'typename' in param or 'class' in param:
                parts = param.split()
                if len(parts) >= 2:
                    params.append(parts[-1])
            else:
                params.append(param)
        
        return params
    
    def _add_symbol_ids_to_ast(self, node: Dict[str, Any]):
        """Recursively add symbol_id fields to all AST nodes that don't have them."""
        # Try to resolve symbol for this node if it doesn't have symbol_id
        if 'symbol_id' not in node and 'name' in node:
            name = node.get('name')
            if name:
                symbol = self.symbol_table.lookup_symbol(name)
                if symbol:
                    node['symbol_id'] = symbol.symbol_id
        
        # Process children
        for child in node.get('children', []):
            self._add_symbol_ids_to_ast(child)


def build_symbol_table_from_ast(ast_root: Dict[str, Any]) -> SymbolTable:
    """
    Convenience function to build symbol table from AST.
    
    Args:
        ast_root: Root AST node
        
    Returns:
        Populated symbol table
    """
    builder = CppSymbolTableBuilder()
    return builder.build_symbol_table(ast_root)