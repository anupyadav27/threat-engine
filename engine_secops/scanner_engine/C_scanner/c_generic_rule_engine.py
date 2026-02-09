"""
C Generic Rule Engine - Enhanced Version

A generic rule engine that can apply any rule based on JSON metadata to C AST.
Handles AST traversal, rule applicability checking, and pattern matching for C language constructs.
Supports C-specific features like pointers, memory management, preprocessor directives, and type checking.
"""

import re
import json
import sys
from . import logic_implementations
from typing import Any, Dict, List, Optional, Union


class CGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    def is_applicable(self, ast_tree):
        """Check if this rule is applicable to the given C AST tree."""
        if not self.metadata or not self.rule_id:
            return False
            
        function_name = None
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if isinstance(check, dict):
                    if check.get('type') == 'custom_function':
                        function_name = check.get('function')
                        break
        # Also check for custom_function at the root logic level
        if not function_name and self.logic.get('custom_function'):
            function_name = self.logic.get('custom_function')
        
        custom_function = self._get_custom_function(function_name)
        required_node_types = self.logic.get("node_types", [])
        matching_nodes = []
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
        return len(matching_nodes) > 0 or custom_function is not None

    def check(self, ast_tree, filename):
        """Apply all checks defined in the rule metadata to the C AST."""
        try:
            findings = []
            seen_findings = set()
            
            # Apply generic logic checks
            generic_findings = self._apply_generic_logic(ast_tree, filename, seen_findings)
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

    def _get_custom_function_name(self):
        """Extract the custom function name from rule metadata."""
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check.get('function')
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        return None

    def _apply_generic_logic(self, ast_tree, filename, seen_findings):
        """Apply generic rule checks that don't require custom functions."""
        findings = []
        if not isinstance(self.logic.get('checks'), list):
            if self._is_valid_generic_check(self.logic):
                findings.extend(self._apply_single_check(ast_tree, filename, self.logic, seen_findings, is_root_check=True))
        else:
            for check in self.logic.get("checks", []):
                if self._is_valid_generic_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, is_root_check=False))
        return findings

    def _apply_single_check(self, ast_tree, filename, check, seen_findings, is_root_check=False):
        """Apply a single rule check to the C AST."""
        findings = []
        check_type = check.get("type") or check.get("check_type")
        
        if is_root_check:
            required_node_types = self.logic.get("node_types", [])
        else:
            required_node_types = check.get("node_types", self.logic.get("node_types", []))
        
        matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types) if required_node_types else [ast_tree]
        
        for node in matching_nodes:
            node_type = node.get('node_type', 'unknown') if isinstance(node, dict) else 'root'
            node_name = self._extract_node_name(node)
            
            if isinstance(check, dict):
                if check_type == "regex_match":
                    findings.extend(self._apply_regex_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "property_comparison":
                    findings.extend(self._apply_property_comparison_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "forbidden_value":
                    findings.extend(self._apply_forbidden_value_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "required_value":
                    findings.extend(self._apply_required_value_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "pointer_check":
                    findings.extend(self._apply_pointer_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "memory_check":
                    findings.extend(self._apply_memory_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "preprocessor_check":
                    findings.extend(self._apply_preprocessor_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "type_check":
                    findings.extend(self._apply_type_check(check, node, filename, node_type, node_name, seen_findings))
        
        return findings

    def _is_valid_generic_check(self, check):
        """Check if the given check is a valid generic check type."""
        check_type = check.get("type") or check.get("check_type")
        if check_type == "custom_function":
            return False
        
        # C-specific check types
        supported_types = [
            "regex_match", "property_comparison", "forbidden_value", "required_value",
            "pointer_check", "memory_check", "preprocessor_check", "type_check",
            "function_complexity", "variable_naming", "const_check", "volatile_check",
            "cast_check", "array_bounds_check", "null_check", "buffer_overflow_check"
        ]
        return check_type in supported_types

    def _apply_regex_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply regex pattern matching to C code elements with granular detection."""
        findings = []
        patterns = check.get("patterns", [])
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
        
        # Get exclude patterns
        exclude_patterns = check.get("exclude_patterns", [])
        
        property_path = check.get("property_path")
        if not patterns or not property_path:
            return findings
        
        value = self._get_property(node, property_path)
        if isinstance(value, str):
            base_line = node.get('lineno', node.get('line', 1)) if node else 1
            
            for pattern in patterns:
                # Search the entire source for pattern matches
                for match in re.finditer(pattern, value, re.MULTILINE | re.DOTALL):
                    match_text = match.group(0).strip()
                    
                    # Check if this match should be excluded
                    should_exclude = False
                    for exclude_pattern in exclude_patterns:
                        if re.search(exclude_pattern, match_text, re.MULTILINE | re.DOTALL):
                            should_exclude = True
                            break
                    
                    if should_exclude:
                        continue
                    
                    # For cryptographic patterns, skip the hardcoded suffix checks
                    # Only apply suffix checks for specific rules about constants
                    if self.rule_id == 'unsigned_suffix_constants' and re.search(r'=\s*\d+[uUlL]+\s*;|=\s*0[xX][0-9A-Fa-f]+[uUlL]+\s*;|=\s*0[0-7]+[uUlL]+\s*;', match_text):
                        continue
                        
                    # Calculate line number more accurately
                    lines_before_match = value[:match.start()].count('\n')
                    actual_line = base_line + lines_before_match
                    
                    # Extract a meaningful variable name based on the pattern type
                    var_name = 'unknown'
                    if 'RSA_generate_key' in pattern:
                        var_name = f"RSA key ({match.group(0).split('(')[1].split(',')[0].strip()} bits)"
                    elif any(crypto in pattern.lower() for crypto in ['md5', 'sha1', 'des']):
                        # Try to extract crypto algorithm name
                        crypto_match = re.search(r'(?i)(md5|sha1|des)', match_text)
                        if crypto_match:
                            var_name = f"{crypto_match.group(1).upper()} usage"
                    else:
                        # Generic variable name extraction
                        var_match = re.search(r'unsigned\s+\w+\s+(\w+)', match_text)
                        var_name = var_match.group(1) if var_match else 'unknown'
                    
                    # Create individual finding for this specific violation
                    finding = {
                        "rule_id": self.rule_id,
                        "message": f"Variable '{var_name}': {check.get('message', 'Pattern match')}",
                        "node": f"{node_type}.{node_name}",
                        "file": filename,
                        "property_path": property_path,
                        "value": match_text,
                        "status": "violation",
                        "line": actual_line
                    }
                    
                    if "severity" in self.metadata:
                        finding["severity"] = self.metadata["severity"]
                    elif "defaultSeverity" in self.metadata:
                        finding["severity"] = self.metadata["defaultSeverity"]
                    
                    # Use line and pattern for uniqueness
                    unique_key = (self.rule_id, filename, actual_line, match.start(), pattern)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings

    def _apply_property_comparison_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply property comparison checks for C AST nodes."""
        findings = []
        property_path = check.get("property_path")
        operator = check.get("operator")
        value = check.get("value")
        
        node_value = self._get_property(node, property_path)
        if operator and node_value is not None:
            if self._evaluate_comparison(node_value, operator, value):
                finding = self._make_finding(filename, node_type, node_name, property_path, node_value, check.get('message', self.message), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        return findings

    def _apply_forbidden_value_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for forbidden values in C code (e.g., dangerous functions, banned constructs)."""
        findings = []
        property_path = check.get("property_path")
        forbidden_values = check.get("forbidden_values", [])
        
        value = self._get_property(node, property_path)
        if value in forbidden_values:
            finding = self._make_finding(filename, node_type, node_name, property_path, value, check.get('message', self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        return findings

    def _apply_required_value_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for required values in C code (e.g., required includes, necessary attributes)."""
        findings = []
        property_path = check.get("property_path")
        required_values = check.get("required_values", [])
        
        value = self._get_property(node, property_path)
        if value not in required_values:
            finding = self._make_finding(filename, node_type, node_name, property_path, value, check.get('message', self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        return findings

    def _apply_pointer_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply C-specific pointer safety checks."""
        findings = []
        check_subtype = check.get("subtype", "null_dereference")
        
        if check_subtype == "null_dereference":
            findings.extend(self._check_null_pointer_dereference(check, node, filename, node_type, node_name, seen_findings))
        elif check_subtype == "dangling_pointer":
            findings.extend(self._check_dangling_pointer(check, node, filename, node_type, node_name, seen_findings))
        elif check_subtype == "pointer_arithmetic":
            findings.extend(self._check_unsafe_pointer_arithmetic(check, node, filename, node_type, node_name, seen_findings))
        
        return findings

    def _apply_memory_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply C-specific memory management checks."""
        findings = []
        check_subtype = check.get("subtype", "memory_leak")
        
        if check_subtype == "memory_leak":
            findings.extend(self._check_memory_leak(check, node, filename, node_type, node_name, seen_findings))
        elif check_subtype == "double_free":
            findings.extend(self._check_double_free(check, node, filename, node_type, node_name, seen_findings))
        elif check_subtype == "buffer_overflow":
            findings.extend(self._check_buffer_overflow(check, node, filename, node_type, node_name, seen_findings))
        
        return findings

    def _apply_preprocessor_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply checks specific to C preprocessor directives."""
        findings = []
        directive_type = check.get("directive_type")
        
        if node_type in ["preprocessor_directive", "include_directive", "define_directive"]:
            value = self._get_property(node, ["directive", "name"]) or self._get_property(node, ["name"])
            if directive_type and value:
                if directive_type == "forbidden" and value in check.get("forbidden_directives", []):
                    finding = self._make_finding(filename, node_type, node_name, ["directive"], value, 
                                               check.get('message', 'Forbidden preprocessor directive'), node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), str(value))
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings

    def _apply_type_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply C-specific type checking rules."""
        findings = []
        type_constraint = check.get("type_constraint")
        
        if node_type in ["variable_declaration", "function_declaration", "parameter"]:
            type_info = self._get_property(node, ["type"]) or self._get_property(node, ["datatype"])
            if type_constraint and type_info:
                if not self._validate_type_constraint(type_info, type_constraint):
                    finding = self._make_finding(filename, node_type, node_name, ["type"], type_info,
                                               check.get('message', 'Type constraint violation'), node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), str(type_info))
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings

    def _check_null_pointer_dereference(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for potential null pointer dereferences."""
        findings = []
        # Implementation would check for pointer dereferences without null checks
        if node_type == "pointer_dereference" or node_type == "member_access":
            # Look for patterns where pointers might be null
            pointer_name = self._get_property(node, ["pointer", "name"]) or self._get_property(node, ["object", "name"])
            if pointer_name and not self._has_null_check_nearby(node, pointer_name):
                finding = self._make_finding(filename, node_type, node_name, ["pointer"], pointer_name,
                                           check.get('message', 'Potential null pointer dereference'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), pointer_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        return findings

    def _check_dangling_pointer(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for potential dangling pointer usage."""
        findings = []
        # Implementation would track pointer lifecycle
        return findings

    def _check_unsafe_pointer_arithmetic(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for unsafe pointer arithmetic operations."""
        findings = []
        if node_type == "binary_expression" and self._get_property(node, ["operator"]) in ["+", "-"]:
            # Check if operands involve pointers
            left_type = self._get_property(node, ["left", "type"])
            right_type = self._get_property(node, ["right", "type"])
            if "pointer" in str(left_type or "") or "pointer" in str(right_type or ""):
                finding = self._make_finding(filename, node_type, node_name, ["operator"], 
                                           self._get_property(node, ["operator"]),
                                           check.get('message', 'Unsafe pointer arithmetic'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), "pointer_arithmetic")
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        return findings

    def _check_memory_leak(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for potential memory leaks."""
        findings = []
        # Look for malloc/calloc without corresponding free
        if node_type == "function_call":
            func_name = self._get_property(node, ["function", "name"]) or self._get_property(node, ["name"])
            if func_name in ["malloc", "calloc", "realloc"]:
                # Check if there's a corresponding free call
                if not self._has_corresponding_free(node, filename):
                    finding = self._make_finding(filename, node_type, node_name, ["function"], func_name,
                                               check.get('message', 'Potential memory leak'), node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), func_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        return findings

    def _check_double_free(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for potential double free errors."""
        findings = []
        # Implementation would track free calls and detect multiple frees
        return findings

    def _check_buffer_overflow(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for potential buffer overflow vulnerabilities."""
        findings = []
        if node_type == "function_call":
            func_name = self._get_property(node, ["function", "name"]) or self._get_property(node, ["name"])
            if func_name in ["strcpy", "strcat", "sprintf", "gets"]:
                finding = self._make_finding(filename, node_type, node_name, ["function"], func_name,
                                           check.get('message', 'Potential buffer overflow'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), func_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        return findings

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
        """Apply custom rule functions from logic_implementations module."""
        findings = []
        custom_fn = getattr(logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        
        # Check if the custom function takes AST and filename parameters
        try:
            import inspect
            sig = inspect.signature(custom_fn)
            params = list(sig.parameters.keys())
            
            if len(params) >= 2 and 'ast_tree' in params and 'filename' in params:
                # Function expects AST and filename
                custom_findings = custom_fn(ast_tree, filename)
                if isinstance(custom_findings, list):
                    findings.extend(custom_findings)
                return findings
        except Exception:
            pass
        
        # Fallback to old node-based approach
        def visit_node(node):
            if custom_fn(node):
                # Extract line number from C AST structure
                line_number = self._extract_line_number(node)
                
                # Create finding with proper deduplication
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                
                # Add deduplication logic
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
        """Find all nodes in the AST that match the specified types."""
        found_nodes = []
        stack = [ast_tree]
        seen = set()
        
        # Handle wildcard - if "*" is in node_types, match all nodes
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
                # Check both 'type' and 'node_type' fields for C AST nodes
                node_type = node.get('type') or node.get('node_type') or node.get('kind')
                if node_type in node_types:
                    found_nodes.append(node)
                
                for value in node.values():
                    stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    stack.append(item)
        
        return found_nodes

    def _get_property(self, node, property_path):
        """Navigate through nested properties in the AST node."""
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

    def _evaluate_comparison(self, value, operator, target):
        """Evaluate comparison operations for C-specific types."""
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

    def _extract_node_name(self, node):
        """Extract a meaningful name from a C AST node."""
        if not isinstance(node, dict):
            return 'root'
        
        # Try common name fields for C AST nodes
        name_fields = ['name', 'identifier', 'id', 'function_name', 'variable_name']
        for field in name_fields:
            name = node.get(field)
            if name:
                return str(name)
        
        # Fallback to node type or unknown
        return node.get('type', node.get('node_type', 'unknown'))

    def _extract_line_number(self, node):
        """Extract line number from C AST node."""
        if not isinstance(node, dict):
            return 0
        
        # Try various line number fields
        line_fields = ['line', 'lineno', 'line_number', 'start_line']
        for field in line_fields:
            line = node.get(field)
            if isinstance(line, int) and line > 0:
                return line
        
        # Try location information
        loc = node.get('location', {}) or node.get('loc', {})
        if isinstance(loc, dict):
            return loc.get('line', loc.get('start_line', 0))
        
        return 0

    def _validate_type_constraint(self, type_info, constraint):
        """Validate C type against constraints."""
        type_str = str(type_info).lower()
        
        if constraint == "no_void_pointer":
            return not ("void" in type_str and "*" in type_str)
        elif constraint == "signed_only":
            return "unsigned" not in type_str
        elif constraint == "no_union":
            return "union" not in type_str
        elif constraint == "pointer_required":
            return "*" in type_str
        elif constraint == "const_required":
            return "const" in type_str
        
        return True

    def _has_null_check_nearby(self, node, pointer_name):
        """Check if there's a null check for the pointer nearby in the code."""
        # This is a simplified implementation
        # In practice, this would analyze the control flow
        return False

    def _has_corresponding_free(self, node, filename):
        """Check if there's a corresponding free call for a malloc."""
        # This is a simplified implementation
        # In practice, this would analyze the entire function or file
        return False

    def _make_finding(self, filename, node_type, node_name, property_path, value, message=None, node=None):
        """Create a finding dictionary with all necessary information."""
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
        
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        
        return finding


def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a C rule against an AST.
    
    Args:
        rule_metadata: Dictionary containing rule configuration
        ast_tree: Parsed C AST tree
        filename: Source file name being analyzed
    
    Returns:
        List of findings (violations) found by the rule
    """
    try:
        rule = CGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# For backward compatibility and alternative names
GenericRule = CGenericRule
CRule = CGenericRule