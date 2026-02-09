"""
C++ Symbol Table System

This module implements comprehensive symbol resolution for C++ code,
tracking all symbols across scopes, enabling overload resolution,
type checking, and semantic analysis.

Features:
- Scope-aware symbol tracking (global, namespace, class, function, block)
- Template specialization tracking
- Inheritance hierarchy resolution
- Overload resolution
- Type inference and checking
- Cross-reference analysis
"""

from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import re


class SymbolKind(Enum):
    """Types of symbols in C++ code."""
    VARIABLE = "variable"
    FUNCTION = "function"
    CLASS = "class"
    STRUCT = "struct"
    NAMESPACE = "namespace"
    TEMPLATE_CLASS = "template_class"
    TEMPLATE_FUNCTION = "template_function"
    TYPEDEF = "typedef"
    ENUM = "enum"
    ENUM_VALUE = "enum_value"
    CONSTRUCTOR = "constructor"
    DESTRUCTOR = "destructor"
    OPERATOR = "operator"
    PARAMETER = "parameter"
    MEMBER_VARIABLE = "member_variable"
    MEMBER_FUNCTION = "member_function"


class AccessSpecifier(Enum):
    """C++ access specifiers."""
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"


@dataclass
class TypeInfo:
    """Enhanced type information for C++ semantic analysis."""
    name: str
    is_const: bool = False
    is_volatile: bool = False
    is_reference: bool = False
    is_rvalue_reference: bool = False
    is_pointer: bool = False
    pointer_depth: int = 0
    is_array: bool = False
    array_dimensions: List[Optional[int]] = field(default_factory=list)
    is_template: bool = False
    template_args: List['TypeInfo'] = field(default_factory=list)
    namespace_qualifiers: List[str] = field(default_factory=list)
    
    # Smart pointer information
    is_smart_pointer: bool = False
    smart_pointer_type: Optional[str] = None  # unique_ptr, shared_ptr, weak_ptr
    
    def __str__(self) -> str:
        """String representation of the type."""
        result = ""
        
        # Add qualifiers
        if self.namespace_qualifiers:
            result += "::".join(self.namespace_qualifiers) + "::"
        
        # Add const/volatile
        if self.is_const:
            result += "const "
        if self.is_volatile:
            result += "volatile "
        
        # Add base type
        result += self.name
        
        # Add template arguments
        if self.is_template and self.template_args:
            result += "<" + ", ".join(str(arg) for arg in self.template_args) + ">"
        
        # Add pointers
        result += "*" * self.pointer_depth
        
        # Add reference
        if self.is_rvalue_reference:
            result += "&&"
        elif self.is_reference:
            result += "&"
        
        # Add array dimensions
        if self.is_array:
            for dim in self.array_dimensions:
                if dim is not None:
                    result += f"[{dim}]"
                else:
                    result += "[]"
        
        return result


@dataclass
class Symbol:
    """Represents a symbol in the symbol table."""
    name: str
    kind: SymbolKind
    type_info: Optional[TypeInfo]
    scope_id: str
    definition_line: int
    definition_file: str
    
    # Symbol-specific attributes
    is_static: bool = False
    is_virtual: bool = False
    is_abstract: bool = False
    is_final: bool = False
    is_override: bool = False
    is_constexpr: bool = False
    is_inline: bool = False
    is_const: bool = False  # For const member functions and const variables
    access: AccessSpecifier = AccessSpecifier.PUBLIC
    
    # Function-specific
    parameters: List['Symbol'] = field(default_factory=list)
    return_type: Optional[TypeInfo] = None
    is_constructor: bool = False
    is_destructor: bool = False
    is_operator_overload: bool = False
    
    # Class-specific
    base_classes: List[str] = field(default_factory=list)
    members: List['Symbol'] = field(default_factory=list)
    
    # Template-specific
    is_template: bool = False
    template_parameters: List[str] = field(default_factory=list)
    template_specializations: List['Symbol'] = field(default_factory=list)
    
    # Cross-references
    references: List[Tuple[int, str]] = field(default_factory=list)  # (line, file)
    symbol_id: str = field(default="", init=False)
    
    def __post_init__(self):
        """Generate unique symbol ID."""
        if not self.symbol_id:
            self.symbol_id = f"{self.scope_id}::{self.name}#{self.kind.value}"


@dataclass 
class Scope:
    """Represents a scope in C++ code."""
    scope_id: str
    scope_type: str  # global, namespace, class, function, block
    parent_scope: Optional[str]
    name: str
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    child_scopes: List[str] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0


class SymbolTable:
    """
    Comprehensive symbol table for C++ code analysis.
    
    Provides scope-aware symbol tracking, type resolution, and semantic analysis.
    """
    
    def __init__(self):
        self.scopes: Dict[str, Scope] = {}
        self.symbols: Dict[str, Symbol] = {}
        self.current_scope_id = "global"
        self.scope_counter = 0
        
        # Type system
        self.builtin_types = {
            'void', 'bool', 'char', 'wchar_t', 'char8_t', 'char16_t', 'char32_t',
            'signed char', 'unsigned char', 'short', 'unsigned short',
            'int', 'unsigned int', 'long', 'unsigned long', 'long long', 'unsigned long long',
            'float', 'double', 'long double', 'auto', 'decltype'
        }
        self.type_aliases: Dict[str, TypeInfo] = {}
        
        # Template system
        self.template_instantiations: Dict[str, List[Symbol]] = {}
        
        # Inheritance hierarchy
        self.inheritance_graph: Dict[str, List[str]] = {}
        
        # Initialize global scope
        self._init_global_scope()
    
    def _init_global_scope(self):
        """Initialize the global scope with built-in symbols."""
        global_scope = Scope(
            scope_id="global",
            scope_type="global",
            parent_scope=None,
            name="::global"
        )
        self.scopes["global"] = global_scope
        
        # Add built-in types
        for builtin in self.builtin_types:
            symbol = Symbol(
                name=builtin,
                kind=SymbolKind.CLASS,  # Treat built-in types as classes for simplicity
                type_info=TypeInfo(name=builtin),
                scope_id="global",
                definition_line=0,
                definition_file="<built-in>"
            )
            self.add_symbol(symbol)
    
    def enter_scope(self, scope_type: str, name: str, start_line: int = 0) -> str:
        """Enter a new scope and return its ID."""
        self.scope_counter += 1
        scope_id = f"{self.current_scope_id}#{scope_type}#{self.scope_counter}"
        
        new_scope = Scope(
            scope_id=scope_id,
            scope_type=scope_type,
            parent_scope=self.current_scope_id,
            name=name,
            start_line=start_line
        )
        
        self.scopes[scope_id] = new_scope
        
        # Add to parent's children
        if self.current_scope_id in self.scopes:
            self.scopes[self.current_scope_id].child_scopes.append(scope_id)
        
        self.current_scope_id = scope_id
        return scope_id
    
    def exit_scope(self, end_line: int = 0):
        """Exit the current scope."""
        if self.current_scope_id in self.scopes:
            current_scope = self.scopes[self.current_scope_id]
            current_scope.end_line = end_line
            
            if current_scope.parent_scope:
                self.current_scope_id = current_scope.parent_scope
    
    def add_symbol(self, symbol: Symbol) -> str:
        """Add a symbol to the current scope."""
        symbol.scope_id = self.current_scope_id
        symbol_id = symbol.symbol_id
        
        # Add to global symbol table
        self.symbols[symbol_id] = symbol
        
        # Add to current scope
        if self.current_scope_id in self.scopes:
            self.scopes[self.current_scope_id].symbols[symbol.name] = symbol
        
        return symbol_id
    
    def lookup_symbol(self, name: str, scope_id: Optional[str] = None) -> Optional[Symbol]:
        """
        Look up a symbol by name, searching up the scope hierarchy.
        """
        if scope_id is None:
            scope_id = self.current_scope_id
        
        # Search current scope first
        if scope_id in self.scopes:
            scope = self.scopes[scope_id]
            if name in scope.symbols:
                return scope.symbols[name]
        
        # Search parent scopes
        if scope_id in self.scopes and self.scopes[scope_id].parent_scope:
            return self.lookup_symbol(name, self.scopes[scope_id].parent_scope)
        
        return None
    
    def lookup_qualified_symbol(self, qualified_name: str) -> Optional[Symbol]:
        """Look up a symbol by qualified name (e.g., std::vector)."""
        parts = qualified_name.split("::")
        if not parts:
            return None
        
        # Start from global scope for absolute paths
        if qualified_name.startswith("::"):
            scope_id = "global"
            parts = parts[1:]  # Remove empty first part
        else:
            scope_id = self.current_scope_id
        
        # Navigate through namespaces
        for i, part in enumerate(parts[:-1]):
            symbol = self.lookup_symbol(part, scope_id)
            if symbol and symbol.kind == SymbolKind.NAMESPACE:
                # Find the scope for this namespace
                for scope in self.scopes.values():
                    if scope.scope_type == "namespace" and scope.name == part:
                        scope_id = scope.scope_id
                        break
            else:
                return None
        
        # Look up the final symbol
        return self.lookup_symbol(parts[-1], scope_id)
    
    def resolve_overloads(self, function_name: str, 
                         argument_types: List[TypeInfo]) -> List[Symbol]:
        """
        Resolve function overloads based on argument types.
        
        Returns list of candidate functions ranked by match quality.
        """
        candidates = []
        
        # Find all functions with matching name
        for symbol in self.symbols.values():
            if (symbol.name == function_name and 
                symbol.kind in [SymbolKind.FUNCTION, SymbolKind.MEMBER_FUNCTION, 
                              SymbolKind.CONSTRUCTOR]):
                candidates.append(symbol)
        
        # Rank candidates by argument matching
        ranked_candidates = []
        for candidate in candidates:
            score = self._calculate_overload_score(candidate, argument_types)
            if score >= 0:  # Valid candidate
                ranked_candidates.append((score, candidate))
        
        # Sort by score (higher is better)
        ranked_candidates.sort(key=lambda x: x[0], reverse=True)
        return [candidate for score, candidate in ranked_candidates]
    
    def _calculate_overload_score(self, function: Symbol, 
                                 argument_types: List[TypeInfo]) -> int:
        """Calculate overload resolution score for a function."""
        if len(function.parameters) != len(argument_types):
            return -1  # Parameter count mismatch
        
        score = 100  # Start with perfect score
        
        for param, arg_type in zip(function.parameters, argument_types):
            if param.type_info and param.type_info.name == arg_type.name:
                # Exact match
                continue
            elif self._is_convertible(arg_type, param.type_info):
                # Convertible - reduce score
                score -= 10
            else:
                # No conversion available
                return -1
        
        return score
    
    def _is_convertible(self, from_type: Optional[TypeInfo], 
                       to_type: Optional[TypeInfo]) -> bool:
        """Check if one type can be converted to another."""
        if not from_type or not to_type:
            return False
        
        # Same type
        if from_type.name == to_type.name:
            return True
        
        # Built-in type conversions
        numeric_types = {'int', 'float', 'double', 'long', 'short', 'char'}
        if from_type.name in numeric_types and to_type.name in numeric_types:
            return True
        
        # Pointer/reference conversions
        if from_type.is_pointer and to_type.is_pointer:
            return self._is_convertible(
                TypeInfo(from_type.name), 
                TypeInfo(to_type.name)
            )
        
        # Inheritance-based conversions
        if self._is_base_class(to_type.name, from_type.name):
            return True
        
        return False
    
    def _is_base_class(self, base_name: str, derived_name: str) -> bool:
        """Check if base_name is a base class of derived_name."""
        if derived_name in self.inheritance_graph:
            bases = self.inheritance_graph[derived_name]
            if base_name in bases:
                return True
            # Check recursively
            for base in bases:
                if self._is_base_class(base_name, base):
                    return True
        return False
    
    def add_inheritance(self, derived_class: str, base_classes: List[str]):
        """Add inheritance relationship to the graph."""
        self.inheritance_graph[derived_class] = base_classes
    
    def get_virtual_functions(self, class_name: str) -> List[Symbol]:
        """Get all virtual functions for a class including inherited ones."""
        virtual_functions = []
        
        # Get virtual functions from this class
        for symbol in self.symbols.values():
            if (symbol.kind == SymbolKind.MEMBER_FUNCTION and 
                symbol.is_virtual and 
                symbol.scope_id.endswith(class_name)):
                virtual_functions.append(symbol)
        
        # Get virtual functions from base classes
        if class_name in self.inheritance_graph:
            for base_class in self.inheritance_graph[class_name]:
                virtual_functions.extend(self.get_virtual_functions(base_class))
        
        return virtual_functions
    
    def resolve_template_instantiation(self, template_name: str, 
                                     template_args: List[TypeInfo]) -> Optional[Symbol]:
        """Resolve a template instantiation to a specific symbol."""
        # Find template symbol
        template_symbol = self.lookup_symbol(template_name)
        if not template_symbol or not template_symbol.is_template:
            return None
        
        # Create instantiation key
        args_str = ", ".join(str(arg) for arg in template_args)
        instantiation_key = f"{template_name}<{args_str}>"
        
        # Check if already instantiated
        if instantiation_key in self.template_instantiations:
            return self.template_instantiations[instantiation_key][0]
        
        # Create new instantiation
        instantiated_symbol = Symbol(
            name=instantiation_key,
            kind=template_symbol.kind,
            type_info=TypeInfo(name=instantiation_key, is_template=True, 
                             template_args=template_args),
            scope_id=template_symbol.scope_id,
            definition_line=template_symbol.definition_line,
            definition_file=template_symbol.definition_file,
            is_template=False  # This is an instantiation, not a template
        )
        
        self.template_instantiations[instantiation_key] = [instantiated_symbol]
        self.symbols[instantiated_symbol.symbol_id] = instantiated_symbol
        
        return instantiated_symbol
    
    def add_reference(self, symbol_name: str, line: int, file: str):
        """Add a reference to a symbol."""
        symbol = self.lookup_symbol(symbol_name)
        if symbol:
            symbol.references.append((line, file))
    
    def get_symbols_in_scope(self, scope_id: str) -> List[Symbol]:
        """Get all symbols defined in a specific scope."""
        if scope_id not in self.scopes:
            return []
        return list(self.scopes[scope_id].symbols.values())
    
    def get_all_symbols_by_kind(self, kind: SymbolKind) -> List[Symbol]:
        """Get all symbols of a specific kind."""
        return [symbol for symbol in self.symbols.values() if symbol.kind == kind]
    
    def dump_symbol_table(self) -> Dict[str, Any]:
        """Dump the entire symbol table for debugging."""
        return {
            'scopes': {sid: {
                'scope_id': scope.scope_id,
                'scope_type': scope.scope_type,
                'parent_scope': scope.parent_scope,
                'name': scope.name,
                'symbols': list(scope.symbols.keys()),
                'child_scopes': scope.child_scopes,
                'start_line': scope.start_line,
                'end_line': scope.end_line
            } for sid, scope in self.scopes.items()},
            'symbols': {sid: {
                'symbol_id': symbol.symbol_id,
                'name': symbol.name,
                'kind': symbol.kind.value,
                'type': str(symbol.type_info) if symbol.type_info else None,
                'scope_id': symbol.scope_id,
                'definition_line': symbol.definition_line,
                'references': len(symbol.references)
            } for sid, symbol in self.symbols.items()},
            'inheritance_graph': self.inheritance_graph,
            'template_instantiations': {k: len(v) for k, v in self.template_instantiations.items()}
        }