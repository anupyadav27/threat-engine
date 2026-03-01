"""
C# Generic Rule Engine - Enhanced Version with Roslyn Support

A generic rule engine that can apply any rule based on JSON metadata to C# AST.
Handles AST traversal, rule applicability checking, pattern matching, and semantic analysis.
Supports both Roslyn-based semantic analysis and regex-based fallback.
"""

import re
import json
import sys
from . import logic_implementations
from typing import Any, Dict, List, Optional, Union


class CSharpGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")
        self.roslyn_available = False
        self._init_roslyn()

    def _init_roslyn(self):
        """Initialize Roslyn integration if available."""
        try:
            import clr  # type: ignore # pylint: disable=import-error
            clr.AddReference("Microsoft.CodeAnalysis")
            clr.AddReference("Microsoft.CodeAnalysis.CSharp")
            self.roslyn_available = True
        except (ImportError, Exception):
            self.roslyn_available = False

    def is_applicable(self, ast_tree):
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
            
            # Apply Roslyn semantic analysis if available
            if self.roslyn_available and self._has_semantic_checks():
                semantic_findings = self._apply_semantic_analysis(ast_tree, filename, seen_findings)
                findings.extend(semantic_findings)
            
            return findings
        except Exception as e:
            import traceback
            traceback.print_exc()
            return []

    def _has_semantic_checks(self):
        """Check if rule requires semantic analysis."""
        semantic_check_types = ['taint_analysis', 'type_check', 'null_check', 'framework_check']
        
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') in semantic_check_types:
                    return True
        
        return self.logic.get('type') in semantic_check_types

    def _get_custom_function_name(self):
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check.get('function')
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        return None

    def _apply_generic_logic(self, ast_tree, filename, seen_findings):
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
        findings = []
        check_type = check.get("type") or check.get("check_type")
        
        if is_root_check:
            required_node_types = self.logic.get("node_types", [])
        else:
            required_node_types = check.get("node_types", self.logic.get("node_types", []))
        
        matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types) if required_node_types else [ast_tree]
        
        for node in matching_nodes:
            node_type = node.get('node_type', 'unknown') if isinstance(node, dict) else 'root'
            node_name = node.get('name', 'unknown') if isinstance(node, dict) else 'root'
            
            if isinstance(check, dict):
                if check_type == "regex_match":
                    findings.extend(self._apply_regex_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "context_aware_lock_check":
                    findings.extend(self._apply_context_aware_lock_check(check, ast_tree, filename))
                elif check_type == "context_aware_abstract_class_check":
                    findings.extend(self._apply_context_aware_abstract_class_check(check, ast_tree, filename))
                elif check_type == "context_aware_action_result_check":
                    findings.extend(self._apply_context_aware_action_result_check(check, ast_tree, filename))
                elif check_type == "property_comparison":
                    findings.extend(self._apply_property_comparison_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "forbidden_value":
                    findings.extend(self._apply_forbidden_value_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "required_value":
                    findings.extend(self._apply_required_value_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "attribute_check":
                    findings.extend(self._apply_attribute_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "access_modifier_check":
                    findings.extend(self._apply_access_modifier_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "namespace_check":
                    findings.extend(self._apply_namespace_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "compound_check":
                    findings.extend(self._apply_compound_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "operator_check":
                    findings.extend(self._apply_operator_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "node_context_check":
                    findings.extend(self._apply_node_context_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "event_type_check":
                    findings.extend(self._apply_event_type_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "anonymous_delegate_check":
                    findings.extend(self._apply_anonymous_delegate_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "exclude_literals_check":
                    findings.extend(self._apply_exclude_literals_check(check, node, filename, node_type, node_name, seen_findings))
        
        return findings

    def _is_valid_generic_check(self, check):
        check_type = check.get("type") or check.get("check_type")
        
        if check_type == "custom_function":
            return False
        
        # Support C# specific check types
        supported_types = [
            "regex_match", "context_aware_lock_check", "context_aware_abstract_class_check", 
            "context_aware_action_result_check", "property_comparison", "forbidden_value", 
            "required_value", "attribute_check", "access_modifier_check", "namespace_check", 
            "using_check", "method_complexity", "variable_naming", "class_design", 
            "interface_design", "property_check", "constructor_check", "exception_handling",
            # New check types for improved anonymous delegates rule
            "compound_check", "operator_check", "node_context_check", "event_type_check",
            "anonymous_delegate_check", "exclude_literals_check"
        ]
        
        return check_type in supported_types

    def _apply_regex_check(self, check, node, filename, node_type, node_name, seen_findings):
        findings = []
        patterns = check.get("patterns", [])
        exclude_patterns = check.get("exclude_patterns", [])
        source_exclude_patterns = check.get("source_exclude_patterns", [])
        context_exclude_patterns = check.get("context_exclude_patterns", [])  # Check N lines before match
        context_lines_to_check = check.get("context_lines_to_check", 10)  # Default: check 10 lines before
        method_name_exclude = check.get("method_name_exclude", [])
        
        # Check if we should exclude based on method name
        if method_name_exclude and node_name:
            for excluded_name in method_name_exclude:
                if node_name == excluded_name or node_name.startswith(excluded_name):
                    return findings  # Skip this entire node
        
        # Handle single pattern as well
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
        
        property_path = check.get("property_path")
        if not patterns or not property_path:
            return findings
        
        value = self._get_property(node, property_path)
        
        # Check source_exclude_patterns against entire source BEFORE processing matches
        # This is used to exclude entire nodes (e.g., classes with destructors)
        if source_exclude_patterns and isinstance(value, str):
            for source_exclude in source_exclude_patterns:
                if re.search(source_exclude, value, re.DOTALL | re.MULTILINE):
                    return findings  # Skip entire node if source contains exclusion pattern
        
        for pattern in patterns:
            if isinstance(value, str):
                # Use finditer to find ALL matches, not just the first one
                for match in re.finditer(pattern, value, re.DOTALL | re.MULTILINE):
                    matched_text = match.group()
                    
                    # Get the line containing the match for context-aware exclusion
                    match_start = match.start()
                    line_start = value.rfind('\n', 0, match_start) + 1
                    line_end = value.find('\n', match_start)
                    if line_end == -1:
                        line_end = len(value)
                    match_line_text = value[line_start:line_end]
                    
                    # Check exclude patterns against the LINE containing the match
                    is_excluded = False
                    if exclude_patterns:
                        for exclude_pattern in exclude_patterns:
                            if re.search(exclude_pattern, match_line_text, re.DOTALL | re.MULTILINE):
                                is_excluded = True
                                break
                    
                    # Check context_exclude_patterns against N lines BEFORE the match
                    # This is useful for excluding based on method attributes like [Fact], [Test]
                    if not is_excluded and context_exclude_patterns:
                        # Get context from parent_source if available
                        parent_source = node.get('parent_source', '') if node else ''
                        node_lineno = node.get('lineno', 1) if node else 1
                        
                        if parent_source:
                            # Split parent source into lines and get context before this line
                            parent_lines = parent_source.split('\n')
                            # Get N lines before the current node line
                            start_line = max(0, node_lineno - context_lines_to_check - 1)
                            end_line = node_lineno  # Include current line in context
                            context_text = '\n'.join(parent_lines[start_line:end_line])
                        else:
                            # Fallback to original context extraction from value
                            context_start = line_start
                            lines_found = 0
                            while context_start > 0 and lines_found < context_lines_to_check:
                                context_start = value.rfind('\n', 0, context_start - 1) + 1
                                if context_start == 0:
                                    break
                                lines_found += 1
                            context_text = value[context_start:line_end]
                        
                        for context_exclude in context_exclude_patterns:
                            if re.search(context_exclude, context_text, re.DOTALL | re.MULTILINE):
                                is_excluded = True
                                break
                    
                    if is_excluded:
                        continue  # Skip this match but check other matches
                    
                    # Calculate line number from the match position
                    lines_before_match = value[:match.start()].count('\n')
                    base_line = node.get('lineno', 1) if node else 1
                    match_line = base_line + lines_before_match
                    
                    # Create a copy of the node with the correct line number for this match
                    match_node = dict(node) if node else {}
                    match_node['lineno'] = match_line
                    
                    finding = self._make_finding(filename, node_type, node_name, property_path, match.group(), check.get('message', 'Pattern match'), match_node)
                    unique_key = (self.rule_id, filename, match_line, str(property_path), match.start())
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings

    def _apply_property_comparison_check(self, check, node, filename, node_type, node_name, seen_findings):
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

    def _apply_attribute_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for required or forbidden attributes on C# elements."""
        findings = []
        required_attributes = check.get("required_attributes", [])
        forbidden_attributes = check.get("forbidden_attributes", [])
        
        # Extract attributes from node
        node_attributes = self._extract_attributes(node)
        
        # Check required attributes
        for req_attr in required_attributes:
            if not any(attr.get('name') == req_attr for attr in node_attributes):
                finding = self._make_finding(filename, node_type, node_name, ['attributes'], node_attributes, 
                                           f"Missing required attribute: {req_attr}", node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), req_attr)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        # Check forbidden attributes
        for attr in node_attributes:
            if attr.get('name') in forbidden_attributes:
                finding = self._make_finding(filename, node_type, node_name, ['attributes'], attr.get('name'), 
                                           f"Forbidden attribute found: {attr.get('name')}", node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), attr.get('name'))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_access_modifier_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check access modifiers on C# elements."""
        findings = []
        required_modifier = check.get("required_modifier")
        forbidden_modifiers = check.get("forbidden_modifiers", [])
        
        # Extract access modifier from node source
        access_modifier = self._extract_access_modifier(node)
        
        if required_modifier and access_modifier != required_modifier:
            finding = self._make_finding(filename, node_type, node_name, ['access_modifier'], access_modifier,
                                       f"Expected access modifier '{required_modifier}', found '{access_modifier}'", node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), access_modifier)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        if access_modifier in forbidden_modifiers:
            finding = self._make_finding(filename, node_type, node_name, ['access_modifier'], access_modifier,
                                       f"Forbidden access modifier: {access_modifier}", node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), access_modifier)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_namespace_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check namespace conventions and requirements."""
        findings = []
        required_pattern = check.get("required_pattern")
        forbidden_patterns = check.get("forbidden_patterns", [])
        
        namespace = self._extract_namespace(node)
        
        if required_pattern and not re.match(required_pattern, namespace or ''):
            finding = self._make_finding(filename, node_type, node_name, ['namespace'], namespace,
                                       f"Namespace doesn't match required pattern: {required_pattern}", node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), namespace)
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        for forbidden_pattern in forbidden_patterns:
            if namespace and re.match(forbidden_pattern, namespace):
                finding = self._make_finding(filename, node_type, node_name, ['namespace'], namespace,
                                           f"Namespace matches forbidden pattern: {forbidden_pattern}", node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), namespace)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_context_aware_lock_check(self, check, ast_tree, filename):
        """Apply context-aware lock mismatch checking using custom logic."""
        findings = []
        
        try:
            # Use the custom implementation from logic_implementations
            if hasattr(logic_implementations, 'check_context_aware_lock_mismatches'):
                findings = logic_implementations.check_context_aware_lock_mismatches(ast_tree, filename)
            else:
                # Fallback to simpler implementation if custom logic not available
                findings = self._fallback_lock_check(ast_tree, filename)
                
        except Exception as e:
            # Log error but don't fail the entire rule check
            print(f"Warning: Context-aware lock check failed for {filename}: {e}")
            # Fallback to simple regex check
            findings = self._fallback_lock_check(ast_tree, filename)
            
        return findings
    
    def _fallback_lock_check(self, ast_tree, filename):
        """Fallback implementation for lock checking if custom logic fails."""
        findings = []
        source = ast_tree.get('source', '')
        if not source:
            return findings
            
        lines = source.split('\n')
        
        # Simple regex patterns for lock methods
        lock_release_patterns = [
            r'\.ReleaseReaderLock\s*\(',
            r'\.ExitReadLock\s*\(',
            r'\.ReleaseWriterLock\s*\(',
            r'\.ExitWriteLock\s*\('
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Skip comments, empty lines, and method definitions
            if (not line_clean or 
                line_clean.startswith('//') or 
                line_clean.startswith('/*') or
                line_clean.startswith('*') or
                'private string Log' in line or
                'private void Process' in line):
                continue
                
            # Check for lock release patterns
            for pattern in lock_release_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': self.rule_id,
                        'message': 'Potential lock type mismatch between acquisition and release (simple check)',
                        'file': filename,
                        'line': line_num,
                        'severity': 'Info',  # Lower severity for fallback
                        'property_path': ['CallExpression', 'name'],
                        'value': line_clean,
                        'node': f'CallExpression.{pattern}',
                        'status': 'violation'
                    })
                    break
                    
        return findings
    
    def _apply_context_aware_abstract_class_check(self, check, ast_tree, filename):
        """Apply context-aware abstract class public constructor checking using custom logic."""
        findings = []
        
        try:
            # Use the custom implementation from logic_implementations
            if hasattr(logic_implementations, 'check_abstract_class_public_constructors'):
                findings = logic_implementations.check_abstract_class_public_constructors(ast_tree, filename)
            else:
                # Fallback to simpler implementation if custom logic not available
                findings = self._fallback_abstract_class_check(ast_tree, filename)
                
        except Exception as e:
            # Log error but don't fail the entire rule check
            print(f"Warning: Context-aware abstract class check failed for {filename}: {e}")
            # Fallback to simple regex check
            findings = self._fallback_abstract_class_check(ast_tree, filename)
            
        return findings
    
    def _fallback_abstract_class_check(self, ast_tree, filename):
        """Fallback implementation for abstract class checking if custom logic fails."""
        findings = []
        source = ast_tree.get('source', '')
        if not source:
            return findings
            
        lines = source.split('\n')
        
        # Simple approach: look for lines with both abstract class and public constructor patterns
        abstract_classes = []
        
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Skip comments and empty lines
            if (not line_clean or 
                line_clean.startswith('//') or 
                line_clean.startswith('/*') or
                line_clean.startswith('*') or
                '"' in line_clean):
                continue
            
            # Find abstract class declarations
            if re.search(r'abstract\s+class\s+(\w+)', line):
                match = re.search(r'abstract\s+class\s+(\w+)', line)
                if match:
                    abstract_classes.append((match.group(1), line_num))
            
            # Find public constructors and check if they're in abstract classes
            if re.search(r'public\s+\w+\s*\(', line):
                constructor_match = re.search(r'public\s+(\w+)\s*\(', line)
                if constructor_match:
                    constructor_name = constructor_match.group(1)
                    # Check if this constructor belongs to an abstract class
                    for class_name, class_line in abstract_classes:
                        if constructor_name == class_name and abs(line_num - class_line) < 50:  # Simple proximity check
                            findings.append({
                                'rule_id': self.rule_id,
                                'message': f'Public constructor found in abstract class {class_name} (fallback detection)',
                                'file': filename,
                                'line': line_num,
                                'severity': 'Info',  # Lower severity for fallback
                                'property_path': ['ClassDeclaration', 'constructor'],
                                'value': line_clean,
                                'node': f'Constructor.{class_name}',
                                'status': 'violation'
                            })
                            break
                    
        return findings
    
    def _apply_context_aware_action_result_check(self, check, ast_tree, filename):
        """Apply context-aware action result method checking using custom logic."""
        findings = []
        
        try:
            # Use the custom implementation from logic_implementations
            if hasattr(logic_implementations, 'check_context_aware_action_result_methods'):
                findings = logic_implementations.check_context_aware_action_result_methods(ast_tree, filename)
            else:
                # Fallback to simpler implementation if custom logic not available
                print(f"Warning: Custom action result check not available for {filename}")
                
        except Exception as e:
            # Log error but don't fail the entire rule check
            print(f"Warning: Context-aware action result check failed for {filename}: {e}")
            
        return findings

    def _apply_semantic_analysis(self, ast_tree, filename, seen_findings):
        """Apply Roslyn-based semantic analysis when available."""
        findings = []
        
        if not self.roslyn_available:
            return findings
        
        try:
            # Apply taint analysis for security rules
            if self._is_security_rule():
                findings.extend(self._apply_taint_analysis(ast_tree, filename, seen_findings))
            
            # Apply type checking
            if self._requires_type_analysis():
                findings.extend(self._apply_type_analysis(ast_tree, filename, seen_findings))
            
            # Apply framework-specific checks (ASP.NET, Entity Framework, etc.)
            if self._is_framework_rule():
                findings.extend(self._apply_framework_analysis(ast_tree, filename, seen_findings))
            
        except Exception as e:
            # Fall back to regex-based analysis if Roslyn fails
            pass
        
        return findings

    def _apply_taint_analysis(self, ast_tree, filename, seen_findings):
        """Apply taint analysis for security vulnerabilities."""
        findings = []
        
        # Define taint sources (user input)
        taint_sources = ['Request.Query', 'Request.Form', 'Console.ReadLine', 'Environment.GetEnvironmentVariable']
        
        # Define taint sinks (dangerous operations)
        taint_sinks = ['SqlCommand', 'Process.Start', 'File.WriteAllText', 'Directory.Delete']
        
        # Define sanitizers
        sanitizers = ['HttpUtility.HtmlEncode', 'SqlParameter', 'Path.GetFileName']
        
        # Simplified taint tracking (in real implementation, use Roslyn's data flow analysis)
        tainted_variables = set()
        
        # Find all nodes in the AST
        all_nodes = self._find_nodes_by_type(ast_tree, ['Assignment', 'CallExpression'])
        
        for node in all_nodes:
            source = node.get('source', '')
            
            # Check for taint sources
            for taint_source in taint_sources:
                if taint_source in source:
                    # Extract variable name being assigned
                    var_match = re.match(r'\s*(\w+)\s*=', source)
                    if var_match:
                        tainted_variables.add(var_match.group(1))
            
            # Check for taint sinks with tainted data
            for taint_sink in taint_sinks:
                if taint_sink in source:
                    for tainted_var in tainted_variables:
                        if tainted_var in source:
                            # Check if sanitized
                            is_sanitized = any(sanitizer in source for sanitizer in sanitizers)
                            if not is_sanitized:
                                finding = self._make_finding(filename, node.get('node_type'), node.get('name'),
                                                           ['taint'], tainted_var, 
                                                           f"Tainted data flows to sink: {taint_sink}", node)
                                unique_key = (self.rule_id, filename, finding.get('line', 0), taint_sink)
                                if unique_key not in seen_findings:
                                    seen_findings.add(unique_key)
                                    findings.append(finding)
        
        return findings

    def _apply_type_analysis(self, ast_tree, filename, seen_findings):
        """Apply type-based analysis."""
        findings = []
        # Placeholder for type analysis using Roslyn semantic model
        return findings

    def _apply_framework_analysis(self, ast_tree, filename, seen_findings):
        """Apply framework-specific analysis (ASP.NET, Entity Framework, etc.)."""
        findings = []
        
        # ASP.NET specific checks
        aspnet_nodes = self._find_nodes_by_type(ast_tree, ['Attribute', 'MethodDeclaration'])
        for node in aspnet_nodes:
            source = node.get('source', '')
            
            # Check for missing authorization
            if '[HttpGet]' in source or '[HttpPost]' in source:
                if '[Authorize]' not in source and '[AllowAnonymous]' not in source:
                    finding = self._make_finding(filename, node.get('node_type'), node.get('name'),
                                               ['authorization'], 'missing',
                                               "API endpoint missing authorization attribute", node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), 'authorization')
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
        
        return findings

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
        findings = []
        try:
            custom_fn = getattr(logic_implementations, function_name, None)
            if not custom_fn or not callable(custom_fn):
                return findings
        except (AttributeError, TypeError):
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
                # Extract line number from node structure
                line_number = node.get('lineno', 0) if isinstance(node, dict) else 0
                
                # Create finding with proper deduplication
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                
                # Add deduplication logic
                source = node.get('source', '') if isinstance(node, dict) else ''
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
        if not function_name:
            return None
        try:
            if hasattr(logic_implementations, function_name):
                func = getattr(logic_implementations, function_name)
                if callable(func):
                    return func
        except (AttributeError, TypeError):
            pass
        return None

    def _find_nodes_by_type(self, ast_tree, node_types):
        found_nodes = []
        stack = [ast_tree]
        seen = set()
        
        while stack:
            node = stack.pop()
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            
            if isinstance(node, dict):
                # Check both 'type' and 'node_type' fields for C# compatibility
                node_type = node.get('type') or node.get('node_type')
                if node_type in node_types:
                    found_nodes.append(node)
                
                for value in node.values():
                    stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    stack.append(item)
        
        return found_nodes

    def _get_property(self, node, property_path):
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
        if value is None:
            return False
        
        if operator == "equals":
            return value == target
        elif operator == "strict_equals":  # C# == comparison
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
        
        return False

    def _extract_attributes(self, node):
        """Extract C# attributes from a node."""
        attributes = []
        source = node.get('source', '') if isinstance(node, dict) else ''
        
        # Find attributes in the source code
        attr_pattern = r'\[(\w+)(?:\([^\]]*\))?\]'
        matches = re.findall(attr_pattern, source)
        
        for match in matches:
            attributes.append({'name': match})
        
        return attributes

    def _extract_access_modifier(self, node):
        """Extract access modifier from C# node."""
        source = node.get('source', '') if isinstance(node, dict) else ''
        
        # Look for access modifiers
        modifiers = ['public', 'private', 'protected', 'internal', 'protected internal', 'private protected']
        
        for modifier in modifiers:
            if re.search(r'\b' + modifier + r'\b', source):
                return modifier
        
        return 'internal'  # Default in C#

    def _extract_namespace(self, node):
        """Extract namespace from C# node or parent source."""
        parent_source = node.get('parent_source', '') if isinstance(node, dict) else ''
        
        # Find namespace declaration
        namespace_match = re.search(r'namespace\s+([\w\.]+)', parent_source)
        if namespace_match:
            return namespace_match.group(1)
        
        return None

    def _is_security_rule(self):
        """Check if this is a security-related rule."""
        security_keywords = ['injection', 'xss', 'csrf', 'authentication', 'authorization', 'security']
        rule_text = (self.rule_id + ' ' + self.message).lower()
        return any(keyword in rule_text for keyword in security_keywords)

    def _requires_type_analysis(self):
        """Check if rule requires type information."""
        type_keywords = ['type', 'cast', 'null', 'reference']
        rule_text = (self.rule_id + ' ' + self.message).lower()
        return any(keyword in rule_text for keyword in type_keywords)

    def _is_framework_rule(self):
        """Check if this is a framework-specific rule."""
        framework_keywords = ['aspnet', 'mvc', 'webapi', 'entity', 'framework']
        rule_text = (self.rule_id + ' ' + self.message).lower()
        return any(keyword in rule_text for keyword in framework_keywords)

    def _apply_compound_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply compound check with multiple conditions that must all pass."""
        findings = []
        conditions = check.get("conditions", [])
        
        # All conditions must pass for the compound check to trigger
        all_conditions_met = True
        condition_results = []
        
        for condition in conditions:
            condition_type = condition.get("type")
            
            if condition_type == "operator_check":
                result = self._check_operator_condition(condition, node)
            elif condition_type == "node_context_check":
                result = self._check_node_context_condition(condition, node)
            elif condition_type == "event_type_check":
                result = self._check_event_type_condition(condition, node)
            elif condition_type == "anonymous_delegate_check":
                result = self._check_anonymous_delegate_condition(condition, node)
            elif condition_type == "exclude_literals_check":
                result = self._check_exclude_literals_condition(condition, node)
            else:
                result = False
            
            condition_results.append(result)
            if not result:
                all_conditions_met = False
        
        # Only create finding if all conditions are met
        if all_conditions_met and any(condition_results):
            finding = self._make_finding(filename, node_type, node_name, 
                                       check.get("property_path", ["source"]), 
                                       node.get("source", ""), 
                                       check.get("message", self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(check.get("property_path", [])))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_operator_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for specific operators in assignment expressions."""
        return self._apply_single_condition_check(check, node, filename, node_type, node_name, seen_findings, self._check_operator_condition)

    def _apply_node_context_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check node context (e.g., left side of assignment)."""
        return self._apply_single_condition_check(check, node, filename, node_type, node_name, seen_findings, self._check_node_context_condition)

    def _apply_event_type_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if left side of assignment is an event."""
        return self._apply_single_condition_check(check, node, filename, node_type, node_name, seen_findings, self._check_event_type_condition)

    def _apply_anonymous_delegate_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if right side is an anonymous delegate or lambda."""
        return self._apply_single_condition_check(check, node, filename, node_type, node_name, seen_findings, self._check_anonymous_delegate_condition)

    def _apply_exclude_literals_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Exclude string literals and comments."""
        return self._apply_single_condition_check(check, node, filename, node_type, node_name, seen_findings, self._check_exclude_literals_condition)

    def _apply_single_condition_check(self, check, node, filename, node_type, node_name, seen_findings, condition_checker):
        """Helper method to apply single condition checks."""
        findings = []
        if condition_checker(check, node):
            finding = self._make_finding(filename, node_type, node_name, 
                                       check.get("property_path", ["source"]), 
                                       node.get("source", ""), 
                                       check.get("message", self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(check.get("property_path", [])))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        return findings

    def _check_operator_condition(self, condition, node):
        """Check if node has specific operator."""
        property_path = condition.get("property_path", [])
        operator = condition.get("operator")
        expected_value = condition.get("value")
        
        actual_value = self._get_property(node, property_path)
        
        if operator == "equals":
            return actual_value == expected_value
        elif operator == "contains":
            return expected_value in str(actual_value) if actual_value else False
        
        # For assignment expressions, check the source for operator patterns
        source = node.get("source", "")
        if expected_value == "-=" and "-=" in source:
            return True
        
        return False

    def _check_node_context_condition(self, condition, node):
        """Check node context like member expressions."""
        property_path = condition.get("property_path", [])
        expected_values = condition.get("values", [])
        
        # For AST nodes without detailed structure, use source analysis
        source = node.get("source", "")
        
        # Check if it's a member expression (contains a dot)
        if "MemberExpression" in expected_values and "." in source:
            return True
        
        # Check if it's an identifier (single word before -=)
        if "Identifier" in expected_values:
            # Look for pattern like "variable -="
            if re.search(r'\b\w+\s*-=', source):
                return True
        
        return False

    def _check_event_type_condition(self, condition, node):
        """Check if the left side of assignment is an event."""
        source = node.get("source", "")
        
        # Look for event-like patterns
        # Events typically have names like MessageReceived, DataProcessed, StatusChanged
        event_patterns = [
            r'\b\w*[Ee]vent\w*\s*-=',  # Contains "event" in name
            r'\b\w*Received\s*-=',      # MessageReceived pattern
            r'\b\w*Processed\s*-=',     # DataProcessed pattern  
            r'\b\w*Changed\s*-=',       # StatusChanged pattern
            r'\b\w*Handler\s*-=',       # Handler pattern
            r'\.\w*[Ee]vent\w*\s*-=',   # member.event pattern
        ]
        
        for pattern in event_patterns:
            if re.search(pattern, source):
                return True
        
        # Additional heuristic: if it's a member access with capitalized name
        # (following C# event naming conventions)
        member_pattern = r'\.([A-Z]\w*)\s*-='
        match = re.search(member_pattern, source)
        if match:
            member_name = match.group(1)
            # Events typically follow PascalCase and have certain suffixes
            if (member_name[0].isupper() and 
                any(suffix in member_name for suffix in ['Event', 'Changed', 'Received', 'Processed', 'Handler'])):
                return True
        
        return False

    def _check_anonymous_delegate_condition(self, condition, node):
        """Check if right side contains anonymous delegate or lambda."""
        source = node.get("source", "")
        patterns = condition.get("patterns", [])
        
        # Check for lambda expressions
        if "lambda_expression" in patterns:
            # Look for lambda patterns: => 
            if re.search(r'-=\s*[^;]*=>', source):
                return True
        
        # Check for anonymous methods  
        if "anonymous_method" in patterns:
            # Look for delegate keyword
            if re.search(r'-=\s*[^;]*\bdelegate\b', source):
                return True
        
        return False

    def _check_exclude_literals_condition(self, condition, node):
        """Check if the code is inside string literals or comments."""
        source = node.get("source", "")
        parent_source = node.get("parent_source", "") or source
        exclude_contexts = condition.get("exclude_contexts", [])
        
        # Check for string literals
        if "StringLiteral" in exclude_contexts:
            # Look for string literal patterns containing our code
            string_patterns = [
                r'"[^"]*-=[^"]*"',       # Double quoted strings
                r"'[^']*-=[^']*'",       # Single quoted strings  
                r'@"[^"]*-=[^"]*"',      # Verbatim strings
            ]
            
            for pattern in string_patterns:
                if re.search(pattern, parent_source):
                    return False  # Exclude this - it's in a string literal
        
        # Check for comments
        if "Comment" in exclude_contexts:
            # Look for comment patterns containing our code
            comment_patterns = [
                r'//.*-=.*',             # Single line comments
                r'/\*[^*]*-=[^*]*\*/',   # Multi-line comments
            ]
            
            for pattern in comment_patterns:
                if re.search(pattern, parent_source):
                    return False  # Exclude this - it's in a comment
        
        return True  # Don't exclude - it's regular code

    def _make_finding(self, filename, node_type, node_name, property_path, value, message=None, node=None):
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
            finding["line"] = node.get('lineno', 1)
        
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        
        return finding


def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a C# rule against an AST.
    """
    try:
        rule = CSharpGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []

# For backward compatibility
GenericRule = CSharpGenericRule