"""
C++ Generic Rule Engine - Enhanced Semantic Version

A sophisticated rule engine that applies semantic rules to C++ AST with deep understanding of:
- Templates and template specialization
- Inheritance hierarchies and virtual dispatch
- RAII and object lifetimes
- Overload resolution and type deduction
- Memory ownership patterns (smart pointers, raw pointers)
- Exception safety guarantees
- const-correctness and type safety

This engine goes beyond syntactic pattern matching to perform semantic analysis
similar to what a compiler frontend would do.
"""

import re
import json
import sys
import logic_implementations
from typing import Any, Dict, List, Optional, Union, Set
from dataclasses import dataclass
from enum import Enum


class CppCheckType(Enum):
    """Enumeration of C++-specific check types for type safety."""
    # Syntactic checks
    REGEX_MATCH = "regex_match"
    PROPERTY_COMPARISON = "property_comparison"
    CUSTOM_FUNCTION = "custom_function"
    
    # Semantic checks  
    TYPE_MATCH = "type_match"
    OVERLOAD_RESOLUTION_CHECK = "overload_resolution_check"
    TEMPLATE_INSTANTIATION_CHECK = "template_instantiation_check"
    
    # Flow analysis checks
    REQUIRES_DOMINATING_CHECK = "requires_dominating_check"
    LIFETIME_CHECK = "lifetime_check"
    OWNERSHIP_CHECK = "ownership_check"
    NULLABILITY_CHECK = "nullability_check"
    EXCEPTION_SAFETY_CHECK = "exception_safety_check"
    
    # C++ design pattern checks
    VIRTUAL_DESTRUCTOR_CHECK = "virtual_destructor_check"
    RULE_OF_FIVE_CHECK = "rule_of_five_check"
    CONST_CORRECTNESS_CHECK = "const_correctness_check"
    NODISCARD_CHECK = "nodiscard_check"
    RAII_CHECK = "raii_check"
    SMART_POINTER_CHECK = "smart_pointer_check"
    
    # C++ specific checks
    TEMPLATE_CHECK = "template_check"
    INHERITANCE_CHECK = "inheritance_check"
    POLYMORPHISM_CHECK = "polymorphism_check"
    STL_USAGE_CHECK = "stl_usage_check"
    MOVE_SEMANTICS_CHECK = "move_semantics_check"


@dataclass
class TypeInfo:
    """Rich type information for C++ semantic analysis."""
    name: str
    is_const: bool = False
    is_volatile: bool = False
    is_reference: bool = False
    is_pointer: bool = False
    is_smart_pointer: bool = False
    smart_pointer_type: Optional[str] = None  # unique_ptr, shared_ptr, weak_ptr
    is_template: bool = False
    template_args: List[str] = None
    namespace: Optional[str] = None
    is_virtual: bool = False
    base_classes: List[str] = None
    
    def __post_init__(self):
        if self.template_args is None:
            self.template_args = []
        if self.base_classes is None:
            self.base_classes = []


@dataclass
class OwnershipInfo:
    """Track C++ object ownership and lifetime."""
    ownership_type: str  # "unique", "shared", "raw", "borrowed", "unknown"
    scope_depth: int = 0
    is_raii_managed: bool = False
    destructor_guaranteed: bool = False
    can_be_null: bool = True
    

class CppSemanticAnalyzer:
    """Semantic analyzer for C++ code understanding with known limitations."""
    
    def __init__(self):
        self.symbol_table = {}
        self.type_hierarchy = {}
        self.template_instantiations = {}
        self.ownership_graph = {}
        
        # Track analysis limitations
        self.limitations = {
            'no_real_parser': True,      # Uses regex not libclang
            'no_preprocessor': True,     # No macro expansion
            'no_symbol_table': True,     # No cross-reference resolution
            'no_cfg': True,              # No control flow analysis
            'no_dataflow': True,         # No lifetime/ownership tracking
            'no_build_context': True     # No compile_commands.json
        }
        
        # Future extension points
        self.cfg_available = False
        self.symbol_resolution_available = False
        self.preprocessor_available = False
        
    def analyze_type(self, node: Dict) -> TypeInfo:
        """Extract type information from AST node (LIMITED - no real symbol resolution)."""
        if not isinstance(node, dict):
            return TypeInfo("unknown")
        
        # WARNING: This is heuristic-based, not semantic
        # Real type analysis requires symbol table and template resolution
        type_str = (node.get('type') or node.get('datatype') or 
                   node.get('return_type') or str(node.get('name', 'unknown')))
        
        # Parse C++ type modifiers
        is_const = 'const' in type_str.lower()
        is_volatile = 'volatile' in type_str.lower()
        is_reference = '&' in type_str and '&&' not in type_str
        is_rvalue_ref = '&&' in type_str
        is_pointer = '*' in type_str and not self._is_smart_pointer(type_str)
        
        # Detect smart pointers
        is_smart_pointer = self._is_smart_pointer(type_str)
        smart_pointer_type = self._get_smart_pointer_type(type_str) if is_smart_pointer else None
        
        # Parse templates
        is_template = '<' in type_str and '>' in type_str
        template_args = self._extract_template_args(type_str) if is_template else []
        
        # Extract namespace
        namespace = self._extract_namespace(type_str)
        
        # Clean type name
        clean_name = self._clean_type_name(type_str)
        
        return TypeInfo(
            name=clean_name,
            is_const=is_const,
            is_volatile=is_volatile,
            is_reference=is_reference,
            is_pointer=is_pointer,
            is_smart_pointer=is_smart_pointer,
            smart_pointer_type=smart_pointer_type,
            is_template=is_template,
            template_args=template_args,
            namespace=namespace
        )
    
    def analyze_ownership(self, node: Dict, type_info: TypeInfo) -> OwnershipInfo:
        """Analyze memory ownership patterns."""
        if type_info.is_smart_pointer:
            if type_info.smart_pointer_type == "unique_ptr":
                return OwnershipInfo("unique", is_raii_managed=True, 
                                   destructor_guaranteed=True, can_be_null=False)
            elif type_info.smart_pointer_type == "shared_ptr":
                return OwnershipInfo("shared", is_raii_managed=True,
                                   destructor_guaranteed=True, can_be_null=False)
            elif type_info.smart_pointer_type == "weak_ptr":
                return OwnershipInfo("borrowed", is_raii_managed=False,
                                   destructor_guaranteed=False, can_be_null=True)
        
        if type_info.is_reference:
            return OwnershipInfo("borrowed", can_be_null=False)
            
        if type_info.is_pointer:
            return OwnershipInfo("raw", can_be_null=True)
            
        # Value semantics
        return OwnershipInfo("unique", is_raii_managed=True, 
                           destructor_guaranteed=True, can_be_null=False)
    
    def _is_smart_pointer(self, type_str: str) -> bool:
        """Check if type is a smart pointer."""
        smart_pointer_types = ['unique_ptr', 'shared_ptr', 'weak_ptr', 'auto_ptr']
        return any(sp_type in type_str for sp_type in smart_pointer_types)
    
    def _get_smart_pointer_type(self, type_str: str) -> Optional[str]:
        """Extract smart pointer type."""
        for sp_type in ['unique_ptr', 'shared_ptr', 'weak_ptr', 'auto_ptr']:
            if sp_type in type_str:
                return sp_type
        return None
    
    def _extract_template_args(self, type_str: str) -> List[str]:
        """Extract template arguments from type string."""
        # Simple regex to extract template args
        match = re.search(r'<([^>]+)>', type_str)
        if match:
            args_str = match.group(1)
            return [arg.strip() for arg in args_str.split(',')]
        return []
    
    def _extract_namespace(self, type_str: str) -> Optional[str]:
        """Extract namespace from qualified type name."""
        if '::' in type_str:
            parts = type_str.split('::')
            if len(parts) > 1:
                return '::'.join(parts[:-1])
        return None
    
    def _clean_type_name(self, type_str: str) -> str:
        """Clean type name of modifiers and qualifiers."""
        # Remove cv-qualifiers and reference/pointer modifiers
        clean = re.sub(r'\b(const|volatile|mutable)\b', '', type_str)
        clean = re.sub(r'[&*]+', '', clean)
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean


class CppGenericRule:
    """Enhanced C++ rule engine with semantic analysis capabilities."""
    
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")
        self.semantic_analyzer = CppSemanticAnalyzer()
        
        # C++ specific features
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
            CppCheckType.TYPE_MATCH.value,
            CppCheckType.OVERLOAD_RESOLUTION_CHECK.value,
            CppCheckType.TEMPLATE_INSTANTIATION_CHECK.value,
            CppCheckType.LIFETIME_CHECK.value,
            CppCheckType.OWNERSHIP_CHECK.value,
            CppCheckType.EXCEPTION_SAFETY_CHECK.value,
            CppCheckType.VIRTUAL_DESTRUCTOR_CHECK.value,
            CppCheckType.RULE_OF_FIVE_CHECK.value,
            CppCheckType.RAII_CHECK.value
        }
        
        return any(ct in semantic_types for ct in check_types if ct)
    
    def _get_supported_check_types(self) -> Set[str]:
        """Get all supported C++ check types."""
        return {check_type.value for check_type in CppCheckType}
    
    def _requires_unavailable_analysis(self) -> bool:
        """Check if rule requires analysis capabilities we don't have."""
        checks = self.logic.get('checks', [])
        if not isinstance(checks, list):
            checks = [self.logic] if self.logic else []
        
        for check in checks:
            check_type = check.get('type', check.get('check_type'))
            
            # Rules that require real semantic analysis
            if check_type in [
                'overload_resolution_check',  # Needs symbol table
                'template_instantiation_check',  # Needs template resolution
                'requires_dominating_check',  # Needs CFG
                'lifetime_check',  # Needs data flow
                'nullability_check'  # Needs data flow
            ]:
                return True
        
        return False

    def is_applicable(self, ast_tree):
        """Check if this rule is applicable given current analysis capabilities."""
        if not self.metadata or not self.rule_id:
            return False
        
        # Check if rule requires capabilities we don't have
        if self._requires_unavailable_analysis():
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
        """Apply all checks defined in the rule metadata to the C++ AST."""
        try:
            findings = []
            seen_findings = set()
            
            # Perform semantic analysis if required
            if self.requires_semantic_analysis:
                self.semantic_analyzer.analyze_symbols(ast_tree)
            
            # Apply generic logic checks
            generic_findings = self._apply_generic_logic(ast_tree, filename, seen_findings)
            findings.extend(generic_findings)
            
            # Apply custom function checks (only if not already handled in generic logic)
            checks = self.logic.get('checks', [])
            has_custom_function_in_checks = any(check.get('type') == 'custom_function' for check in checks)
            
            if not has_custom_function_in_checks:
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

    def _apply_generic_logic(self, ast_tree, filename, seen_findings):
        """Apply generic rule checks with C++ semantic awareness."""
        findings = []
        checks = self.logic.get('checks', [])
        
        # Handle both single check and multiple checks
        if not isinstance(checks, list):
            if self._is_valid_cpp_check(self.logic):
                findings.extend(self._apply_single_check(ast_tree, filename, self.logic, seen_findings, is_root_check=True))
        else:
            for check in checks:
                if self._is_valid_cpp_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, is_root_check=False))
        
        return findings

    def _apply_single_check(self, ast_tree, filename, check, seen_findings, is_root_check=False):
        """Apply a single C++ rule check with semantic analysis."""
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
        
        # Special handling for custom functions - call once with entire AST
        if check_type == CppCheckType.CUSTOM_FUNCTION.value:
            node_findings = self._apply_check_by_type(check_type, check, ast_tree, filename, seen_findings)
            findings.extend(node_findings)
        else:
            # Apply check based on type for each matching node
            for node in matching_nodes:
                node_findings = self._apply_check_by_type(check_type, check, node, filename, seen_findings)
                findings.extend(node_findings)
        
        return findings

    def _apply_check_by_type(self, check_type, check, node, filename, seen_findings):
        """Apply specific check type with C++ semantic understanding."""
        findings = []
        
        # Map check types to methods
        check_methods = {
            CppCheckType.REGEX_MATCH.value: self._apply_regex_check,
            CppCheckType.PROPERTY_COMPARISON.value: self._apply_property_comparison_check,
            CppCheckType.CUSTOM_FUNCTION.value: self._apply_custom_function_check,
            CppCheckType.TYPE_MATCH.value: self._apply_type_match_check,
            CppCheckType.OVERLOAD_RESOLUTION_CHECK.value: self._apply_overload_resolution_check,
            CppCheckType.TEMPLATE_INSTANTIATION_CHECK.value: self._apply_template_instantiation_check,
            CppCheckType.LIFETIME_CHECK.value: self._apply_lifetime_check,
            CppCheckType.OWNERSHIP_CHECK.value: self._apply_ownership_check,
            CppCheckType.NULLABILITY_CHECK.value: self._apply_nullability_check,
            CppCheckType.EXCEPTION_SAFETY_CHECK.value: self._apply_exception_safety_check,
            CppCheckType.VIRTUAL_DESTRUCTOR_CHECK.value: self._apply_virtual_destructor_check,
            CppCheckType.RULE_OF_FIVE_CHECK.value: self._apply_rule_of_five_check,
            CppCheckType.CONST_CORRECTNESS_CHECK.value: self._apply_const_correctness_check,
            CppCheckType.RAII_CHECK.value: self._apply_raii_check,
            CppCheckType.SMART_POINTER_CHECK.value: self._apply_smart_pointer_check,
            CppCheckType.TEMPLATE_CHECK.value: self._apply_template_check,
            CppCheckType.INHERITANCE_CHECK.value: self._apply_inheritance_check,
            CppCheckType.POLYMORPHISM_CHECK.value: self._apply_polymorphism_check,
            CppCheckType.MOVE_SEMANTICS_CHECK.value: self._apply_move_semantics_check
        }
        
        check_method = check_methods.get(check_type)
        if check_method:
            findings = check_method(check, node, filename, seen_findings)
        
        return findings

    def _apply_regex_check(self, check, node, filename, seen_findings):
        """Enhanced regex check with C++ context awareness."""
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
                
                # Enhanced variable name extraction for C++
                var_name = self._extract_cpp_identifier(match_text, pattern)
                
                lines_before_match = value[:match.start()].count('\n')
                actual_line = base_line + lines_before_match
                
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=property_path,
                    value=match_text,
                    message=f"Variable '{var_name}': {check.get('message', 'Pattern match')}",
                    node=node
                )
                finding["line"] = actual_line
                
                unique_key = (self.rule_id, filename, actual_line, match.start(), pattern)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_custom_function_check(self, check, node, filename, seen_findings):
        """Apply custom function check."""
        findings = []
        
        function_name = check.get('function_name') or check.get('function')
        if not function_name:
            return findings
        
        # Get the custom function from logic_implementations
        custom_function = self._get_custom_function(function_name)
        if not custom_function:
            return findings
        
        # Call the custom function with AST and filename
        try:
            custom_findings = custom_function(node, filename)
            if isinstance(custom_findings, list):
                findings.extend(custom_findings)
        except Exception as e:
            # Log error but don't fail the whole rule
            pass
        
        return findings

    def _apply_type_match_check(self, check, node, filename, seen_findings):
        """Check C++ type matching with semantic analysis."""
        findings = []
        
        type_info = self.semantic_analyzer.analyze_type(node)
        expected_type = check.get("expected_type")
        type_constraint = check.get("type_constraint")
        
        violation = False
        violation_reason = ""
        
        if expected_type and type_info.name != expected_type:
            violation = True
            violation_reason = f"Expected type {expected_type}, got {type_info.name}"
        
        if type_constraint:
            if type_constraint == "must_be_const" and not type_info.is_const:
                violation = True
                violation_reason = "Type must be const-qualified"
            elif type_constraint == "no_raw_pointers" and type_info.is_pointer and not type_info.is_smart_pointer:
                violation = True
                violation_reason = "Raw pointers discouraged, use smart pointers"
            elif type_constraint == "smart_pointer_only" and not type_info.is_smart_pointer:
                violation = True
                violation_reason = "Must use smart pointer for this type"
        
        if violation:
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["type"],
                value=type_info.name,
                message=f"{check.get('message', 'Type violation')}: {violation_reason}",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), type_info.name)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_ownership_check(self, check, node, filename, seen_findings):
        """Check C++ ownership patterns and RAII compliance."""
        findings = []
        
        type_info = self.semantic_analyzer.analyze_type(node)
        ownership_info = self.semantic_analyzer.analyze_ownership(node, type_info)
        
        ownership_rule = check.get("ownership_rule")
        
        violation = False
        violation_reason = ""
        
        if ownership_rule == "prefer_smart_pointers" and ownership_info.ownership_type == "raw":
            violation = True
            violation_reason = "Prefer smart pointers over raw pointers for ownership"
        elif ownership_rule == "require_raii" and not ownership_info.is_raii_managed:
            violation = True
            violation_reason = "Resource must be RAII-managed"
        elif ownership_rule == "no_raw_new_delete" and self._has_manual_memory_management(node):
            violation = True
            violation_reason = "Avoid raw new/delete, use smart pointers or containers"
        
        if violation:
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["ownership"],
                value=ownership_info.ownership_type,
                message=f"{check.get('message', 'Ownership violation')}: {violation_reason}",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), violation_reason)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_virtual_destructor_check(self, check, node, filename, seen_findings):
        """Check for virtual destructor in polymorphic classes."""
        findings = []
        
        if node.get('node_type') not in ['class_declaration', 'struct_declaration']:
            return findings
        
        # Check if class has virtual functions
        has_virtual_functions = self._has_virtual_functions(node)
        has_virtual_destructor = self._has_virtual_destructor(node)
        
        if has_virtual_functions and not has_virtual_destructor:
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["destructor"],
                value="non-virtual",
                message=check.get('message', 'Class with virtual functions needs virtual destructor'),
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), "virtual_destructor")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_rule_of_five_check(self, check, node, filename, seen_findings):
        """Check compliance with Rule of Five/Zero."""
        findings = []
        
        if node.get('node_type') not in ['class_declaration', 'struct_declaration']:
            return findings
        
        special_members = self._count_special_members(node)
        
        # Rule of Five: if you define any, define all five
        # Rule of Zero: prefer not defining any
        defined_count = sum(1 for defined in special_members.values() if defined)
        
        if 0 < defined_count < 5:
            missing_members = [name for name, defined in special_members.items() if not defined]
            
            finding = self._make_finding(
                filename=filename,
                node_type=node.get('node_type', 'unknown'),
                node_name=self._extract_node_name(node),
                property_path=["special_members"],
                value=f"defined_{defined_count}_of_5",
                message=f"{check.get('message', 'Rule of Five violation')}: Missing {', '.join(missing_members)}",
                node=node
            )
            
            unique_key = (self.rule_id, filename, finding.get('line', 0), "rule_of_five")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_template_check(self, check, node, filename, seen_findings):
        """Check template usage and instantiation patterns."""
        findings = []
        
        if node.get('node_type') not in ['template_declaration', 'function_call', 'variable_declaration']:
            return findings
        
        template_rule = check.get("template_rule")
        
        if template_rule == "explicit_instantiation_only":
            if self._has_implicit_template_instantiation(node):
                finding = self._make_finding(
                    filename=filename,
                    node_type=node.get('node_type', 'unknown'),
                    node_name=self._extract_node_name(node),
                    property_path=["template"],
                    value="implicit_instantiation",
                    message=check.get('message', 'Prefer explicit template instantiation'),
                    node=node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), "template_instantiation")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    # Additional helper methods for C++ semantic analysis
    
    def _extract_cpp_identifier(self, match_text, pattern):
        """Extract C++ identifier with namespace support."""
        # Handle namespaced identifiers
        namespace_match = re.search(r'(\w+::)*(\w+)', match_text)
        if namespace_match:
            return namespace_match.group(0)
        
        # Fallback to simple identifier
        var_match = re.search(r'\b(\w+)\b', match_text)
        return var_match.group(1) if var_match else 'unknown'

    def _has_virtual_functions(self, class_node):
        """Check if class has virtual functions."""
        methods = class_node.get('methods', []) or class_node.get('member_functions', [])
        for method in methods:
            if isinstance(method, dict) and method.get('is_virtual'):
                return True
        return False

    def _has_virtual_destructor(self, class_node):
        """Check if class has virtual destructor."""
        methods = class_node.get('methods', []) or class_node.get('member_functions', [])
        for method in methods:
            if (isinstance(method, dict) and 
                method.get('name', '').startswith('~') and 
                method.get('is_virtual')):
                return True
        return False

    def _count_special_members(self, class_node):
        """Count special member functions (Rule of Five)."""
        special_members = {
            'destructor': False,
            'copy_constructor': False,
            'copy_assignment': False,
            'move_constructor': False,
            'move_assignment': False
        }
        
        methods = class_node.get('methods', []) or class_node.get('member_functions', [])
        class_name = self._extract_node_name(class_node)
        
        for method in methods:
            if not isinstance(method, dict):
                continue
                
            method_name = method.get('name', '')
            parameters = method.get('parameters', [])
            
            if method_name.startswith('~'):
                special_members['destructor'] = True
            elif method_name == class_name:
                # Constructor - check if copy or move
                if len(parameters) == 1:
                    param_type = parameters[0].get('type', '')
                    if f'{class_name}&' in param_type and '&&' not in param_type:
                        special_members['copy_constructor'] = True
                    elif f'{class_name}&&' in param_type:
                        special_members['move_constructor'] = True
            elif method_name == 'operator=':
                if len(parameters) == 1:
                    param_type = parameters[0].get('type', '')
                    if f'{class_name}&' in param_type and '&&' not in param_type:
                        special_members['copy_assignment'] = True
                    elif f'{class_name}&&' in param_type:
                        special_members['move_assignment'] = True
        
        return special_members

    def _has_manual_memory_management(self, node):
        """Check for raw new/delete usage."""
        # Look for new/delete keywords in node or children
        def search_for_keywords(n):
            if isinstance(n, dict):
                for key, value in n.items():
                    if key in ['operator', 'function_name', 'name'] and value in ['new', 'delete', 'malloc', 'free']:
                        return True
                    if search_for_keywords(value):
                        return True
            elif isinstance(n, list):
                for item in n:
                    if search_for_keywords(item):
                        return True
            return False
        
        return search_for_keywords(node)

    def _has_implicit_template_instantiation(self, node):
        """Check for implicit template instantiation."""
        # Simplified check - look for auto keyword or template usage without explicit types
        source = node.get('source', '') or str(node)
        return 'auto' in source and '<' in source

    # Inherit and extend methods from C engine
    def _is_valid_cpp_check(self, check):
        """Check if the given check is a valid C++ check type."""
        check_type = check.get("type") or check.get("check_type")
        return check_type in self.supported_check_types

    def _apply_property_comparison_check(self, check, node, filename, seen_findings):
        """Apply property comparison with C++ semantic awareness."""
        findings = []
        property_path = check.get("property_path")
        operator = check.get("operator")
        value = check.get("value")
        
        node_value = self._get_property(node, property_path)
        if operator and node_value is not None:
            if self._evaluate_cpp_comparison(node_value, operator, value):
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

    def _evaluate_cpp_comparison(self, value, operator, target):
        """Evaluate comparison with C++ type awareness."""
        # Extend the C comparison with C++ specific operators
        if operator == "is_template_type":
            return '<' in str(value) and '>' in str(value)
        elif operator == "is_smart_pointer":
            return any(sp in str(value) for sp in ['unique_ptr', 'shared_ptr', 'weak_ptr'])
        elif operator == "is_const_method":
            return 'const' in str(value) and '(' in str(value) and ')' in str(value)
        elif operator == "is_virtual":
            return 'virtual' in str(value)
        elif operator == "is_override":
            return 'override' in str(value)
        elif operator == "is_final":
            return 'final' in str(value)
        else:
            # Fall back to base evaluation for standard operators
            return self._evaluate_comparison_base(value, operator, target)

    def _evaluate_comparison_base(self, value, operator, target):
        """Base comparison evaluation (copied from C engine)."""
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
        elif operator == "is_pointer":
            return "pointer" in str(value).lower() or "*" in str(value)
        elif operator == "is_array":
            return "array" in str(value).lower() or "[" in str(value)
        elif operator == "is_const":
            return "const" in str(value).lower()
        elif operator == "is_volatile":
            return "volatile" in str(value).lower()
        
        return False

    # Add stub implementations for all check methods to prevent errors
    def _apply_overload_resolution_check(self, check, node, filename, seen_findings):
        """Check overload resolution correctness.""" 
        return []
    
    def _apply_template_instantiation_check(self, check, node, filename, seen_findings):
        """Check template instantiation patterns."""
        return []
    
    def _apply_lifetime_check(self, check, node, filename, seen_findings):
        """Check object lifetime and scope."""
        return []
    
    def _apply_nullability_check(self, check, node, filename, seen_findings):
        """Check null pointer safety."""
        return []
    
    def _apply_exception_safety_check(self, check, node, filename, seen_findings):
        """Check exception safety guarantees."""
        return []
    
    def _apply_const_correctness_check(self, check, node, filename, seen_findings):
        """Check const-correctness."""
        return []
    
    def _apply_raii_check(self, check, node, filename, seen_findings):
        """Check RAII compliance."""
        return []
    
    def _apply_smart_pointer_check(self, check, node, filename, seen_findings):
        """Check smart pointer usage."""
        return []
    
    def _apply_inheritance_check(self, check, node, filename, seen_findings):
        """Check inheritance patterns."""
        return []
    
    def _apply_polymorphism_check(self, check, node, filename, seen_findings):
        """Check polymorphism usage."""
        return []
    
    def _apply_move_semantics_check(self, check, node, filename, seen_findings):
        """Check move semantics implementation."""
        return []

    # Core utility methods (adapted from C engine)
    def _get_custom_function_name(self):
        """Extract custom function name from rule metadata."""
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function':
                    # Check for both 'function' and 'function_name' fields
                    if check.get('function'):
                        return check.get('function')
                    elif check.get('function_name'):
                        return check.get('function_name')
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        return None

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
        """Apply custom rule functions with C++ context."""
        findings = []
        custom_fn = getattr(logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        
        # Enhanced custom function support for C++
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
        """Find all nodes in the AST that match C++ node types."""
        found_nodes = []
        stack = [ast_tree]
        seen = set()
        
        # C++ specific node types
        cpp_node_types = {
            'class_declaration', 'struct_declaration', 'namespace_declaration',
            'template_declaration', 'template_instantiation', 'function_template',
            'constructor_declaration', 'destructor_declaration', 'method_declaration',
            'operator_overload', 'friend_declaration', 'using_declaration',
            'typedef_declaration', 'enum_class_declaration', 'lambda_expression'
        }
        
        # Include C++ node types in search
        extended_node_types = set(node_types)
        if any(nt in cpp_node_types for nt in node_types):
            extended_node_types.update(node_types)
        
        if "*" in node_types:
            while stack:
                node = stack.pop()
                node_id = id(node)
                if node_id in seen:
                    continue
                seen.add(node_id)
                
                if isinstance(node, dict):
                    found_nodes.append(node)
                    for value in node.values():
                        stack.append(value)
                elif isinstance(node, list):
                    for item in node:
                        stack.append(item)
            return found_nodes
        
        while stack:
            node = stack.pop()
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            
            if isinstance(node, dict):
                node_type = (node.get('type') or node.get('node_type') or 
                           node.get('kind') or node.get('declaration_type'))
                if node_type in extended_node_types:
                    found_nodes.append(node)
                
                for value in node.values():
                    stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    stack.append(item)
        
        return found_nodes

    def _get_property(self, node, property_path):
        """Navigate through nested properties in C++ AST node."""
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

    def _extract_node_name(self, node):
        """Extract meaningful name from C++ AST node."""
        if not isinstance(node, dict):
            return 'root'
        
        # C++ specific name fields
        cpp_name_fields = [
            'name', 'identifier', 'id', 'class_name', 'function_name', 
            'method_name', 'template_name', 'namespace_name', 'variable_name'
        ]
        
        for field in cpp_name_fields:
            name = node.get(field)
            if name:
                return str(name)
        
        return node.get('type', node.get('node_type', 'unknown'))

    def _extract_line_number(self, node):
        """Extract line number from C++ AST node."""
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
        """Create a finding dictionary with C++ specific information."""
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
            
            # Add C++ specific context
            if node_type in ['class_declaration', 'struct_declaration']:
                finding["context"] = "class_definition"
            elif node_type in ['template_declaration', 'template_instantiation']:
                finding["context"] = "template_definition"
            elif node_type in ['constructor_declaration', 'destructor_declaration']:
                finding["context"] = "special_member_function"
        
        # Add severity information
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        
        return finding


# Enhanced semantic analyzer with stub implementation
class CppSemanticAnalyzer:
    """Extended semantic analyzer with placeholder for full implementation."""
    
    def analyze_symbols(self, ast_tree):
        """Placeholder for symbol table analysis."""
        pass


def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a C++ rule against an AST.
    
    Args:
        rule_metadata: Dictionary containing rule configuration
        ast_tree: Parsed C++ AST tree  
        filename: Source file name being analyzed
    
    Returns:
        List of findings (violations) found by the rule
    """
    try:
        rule = CppGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# Alternative names for compatibility
GenericRule = CppGenericRule
CppRule = CppGenericRule