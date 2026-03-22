"""
Ansible Generic Rule Engine - Enhanced Version

A generic rule engine that can apply any rule based on JSON metadata to Ansible AST.
Handles AST traversal, rule applicability checking, and pattern matching for Ansible playbooks and roles.
"""

import re
import json
from ansible_scanner import logic_implementations
from typing import Any, Dict, List, Optional, Union


class AnsibleGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

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
            generic_findings = self._apply_generic_logic(ast_tree, filename, seen_findings)
            findings.extend(generic_findings)
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
        node_types = check.get("node_types", self.logic.get("node_types", []))
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
                elif check_type == "property_comparison":
                    findings.extend(self._apply_property_comparison_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "forbidden_value":
                    findings.extend(self._apply_forbidden_value_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "required_value":
                    findings.extend(self._apply_required_value_check(check, node, filename, node_type, node_name, seen_findings))
        return findings

    def _is_valid_generic_check(self, check):
        check_type = check.get("type") or check.get("check_type")
        if check_type == "custom_function":
            return False
        # Support additional check types relevant for Ansible
        supported_types = [
            "regex_match", "property_comparison", "forbidden_value", "required_value",
            "module_check", "variable_check", "permission_check", "security_check",
            "become_check", "handler_check", "task_check", "role_check"
        ]
        return check_type in supported_types

    def _apply_regex_check(self, check, node, filename, node_type, node_name, seen_findings):
        findings = []
        patterns = check.get("patterns", [])
        # Handle single pattern as well
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
        property_path = check.get("property_path")
        if not patterns or not property_path:
            return findings
        
        value = self._get_property(node, property_path)
        if not isinstance(value, str):
            return findings
            
        for pattern in patterns:
            try:
                # Use DOTALL and MULTILINE flags for Ansible YAML content
                # DOTALL allows . to match newlines, MULTILINE allows ^ and $ to match line boundaries
                flags = re.DOTALL | re.MULTILINE
                
                # Handle case-sensitive patterns (if pattern contains uppercase, make it case-sensitive)
                if not any(c.isupper() for c in pattern if c.isalpha()):
                    flags |= re.IGNORECASE
                
                # Enhanced pattern matching for Ansible
                if re.search(pattern, value, flags):
                    # Extract line number more accurately
                    line_number = self._extract_line_number(node, value, pattern)
                    
                    # Create more detailed finding
                    finding = self._make_finding(
                        filename, node_type, node_name, property_path, 
                        self._extract_match_context(value, pattern), 
                        check.get('message', 'Pattern match'), node
                    )
                    finding['line'] = line_number
                    finding['pattern'] = pattern
                    
                    unique_key = (self.rule_id, filename, line_number, str(property_path), pattern)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
            except re.error as e:
                # Handle regex compilation errors gracefully
                print(f"Warning: Invalid regex pattern '{pattern}' in rule {self.rule_id}: {e}")
                continue
                
        return findings
    
    def _extract_line_number(self, node, source, pattern):
        """Extract more accurate line number for pattern match."""
        # Try to get line number from node
        line_number = node.get('lineno', 1)
        
        # If we have location info, use it
        if 'loc' in node and isinstance(node['loc'], dict):
            start_loc = node['loc'].get('start', {})
            if isinstance(start_loc, dict) and 'line' in start_loc:
                line_number = start_loc['line']
        
        # Ansible-specific: check for __line__ marker
        if '__line__' in node:
            line_number = node['__line__']
        
        # Check for _line_number attribute
        if '_line_number' in node:
            line_number = node['_line_number']
        
        # If pattern found, try to calculate relative line offset
        try:
            match = re.search(pattern, source, re.DOTALL | re.MULTILINE)
            if match:
                lines_before_match = source[:match.start()].count('\n')
                line_number = max(1, line_number + lines_before_match)
        except Exception:
            pass

        return line_number
    
    def _extract_match_context(self, source, pattern, context_lines=2):
        """Extract contextual code around pattern match for better reporting."""
        try:
            match = re.search(pattern, source, re.DOTALL | re.MULTILINE)
            if match:
                # Get the matched text
                matched_text = match.group()
                start_pos = match.start()
                end_pos = match.end()
                
                # Find context around the match
                lines = source.split('\n')
                match_line_start = source[:start_pos].count('\n')
                match_line_end = source[:end_pos].count('\n')
                
                # Extract context lines
                context_start = max(0, match_line_start - context_lines)
                context_end = min(len(lines), match_line_end + context_lines + 1)
                
                context = '\n'.join(lines[context_start:context_end])
                return context[:500] + '...' if len(context) > 500 else context
        except Exception:
            pass

        # Fallback to truncated source
        return source[:200] + '...' if len(source) > 200 else source

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

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
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
                # Extract line number from Ansible AST structure
                line_number = 0
                if isinstance(node, dict):
                    # Check for Ansible-specific line markers
                    if '__line__' in node:
                        line_number = node['__line__']
                    elif '_line_number' in node:
                        line_number = node['_line_number']
                    elif 'loc' in node and isinstance(node['loc'], dict):
                        start_loc = node['loc'].get('start', {})
                        if isinstance(start_loc, dict) and 'line' in start_loc:
                            line_number = start_loc['start']['line']
                    # Fallback to legacy lineno field
                    if line_number == 0:
                        line_number = node.get('lineno', 0)
                
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                findings.append(finding)
        
        def traverse(node):
            if isinstance(node, dict):
                visit_node(node)
                # Only traverse children array if it exists, not all dict values
                if 'children' in node and isinstance(node['children'], list):
                    for child in node['children']:
                        traverse(child)
                else:
                    # Fallback: traverse all values but skip raw data fields
                    for key, v in node.items():
                        if key not in ['raw_data', 'data', 'source', 'parent_source']:
                            traverse(v)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
        
        traverse(ast_tree)
        return findings

    def _get_custom_function(self, function_name):
        if not function_name:
            return None
        if hasattr(logic_implementations, function_name):
            func = getattr(logic_implementations, function_name)
            if callable(func):
                return func
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
                # Check both 'type' and 'node_type' fields
                node_type = node.get('type') or node.get('node_type')
                if node_type in node_types:
                    found_nodes.append(node)
                
                # Special handling for Ansible-specific node types
                if node_type == 'play' and 'play' in node_types:
                    # Include play definitions
                    found_nodes.append(node)
                elif node_type == 'task' and 'task' in node_types:
                    # Include task definitions
                    found_nodes.append(node)
                elif node_type == 'role' and 'role' in node_types:
                    # Include role definitions
                    found_nodes.append(node)
                elif node_type == 'handler' and 'handler' in node_types:
                    # Include handler definitions
                    found_nodes.append(node)
                elif node_type == 'block' and 'block' in node_types:
                    # Include block structures
                    found_nodes.append(node)
                elif node_type == 'module' and 'module' in node_types:
                    # Include module calls
                    found_nodes.append(node)
                elif node_type == 'variable' and 'variable' in node_types:
                    # Include variable definitions
                    found_nodes.append(node)
                elif node_type == 'template' and 'template' in node_types:
                    # Include template usage
                    found_nodes.append(node)
                elif node_type == 'when' and 'when' in node_types:
                    # Include conditional statements
                    found_nodes.append(node)
                elif node_type == 'loop' and 'loop' in node_types:
                    # Include loop structures (with_items, loop, etc.)
                    found_nodes.append(node)
                elif node_type == 'become' and 'become' in node_types:
                    # Include privilege escalation directives
                    found_nodes.append(node)
                elif node_type == 'notify' and 'notify' in node_types:
                    # Include handler notifications
                    found_nodes.append(node)
                elif node_type == 'import_playbook' and 'import_playbook' in node_types:
                    # Include playbook imports
                    found_nodes.append(node)
                elif node_type == 'import_tasks' and 'import_tasks' in node_types:
                    # Include task imports
                    found_nodes.append(node)
                elif node_type == 'include_tasks' and 'include_tasks' in node_types:
                    # Include task includes
                    found_nodes.append(node)
                elif node_type == 'include_role' and 'include_role' in node_types:
                    # Include role includes
                    found_nodes.append(node)
                elif node_type == 'set_fact' and 'set_fact' in node_types:
                    # Include fact setting tasks
                    found_nodes.append(node)
                elif node_type == 'debug' and 'debug' in node_types:
                    # Include debug tasks
                    found_nodes.append(node)
                elif node_type == 'copy' and 'copy' in node_types:
                    # Include copy module tasks
                    found_nodes.append(node)
                elif node_type == 'file' and 'file' in node_types:
                    # Include file module tasks
                    found_nodes.append(node)
                elif node_type == 'docker_container' and 'docker_container' in node_types:
                    # Include Docker container tasks
                    found_nodes.append(node)
                elif node_type == 'kubernetes' and 'kubernetes' in node_types:
                    # Include Kubernetes tasks
                    found_nodes.append(node)
                elif node_type == 'shell' and 'shell' in node_types:
                    # Include shell command tasks
                    found_nodes.append(node)
                elif node_type == 'command' and 'command' in node_types:
                    # Include command tasks
                    found_nodes.append(node)
                
                # Recursively search child nodes
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, (dict, list)):
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
        elif operator == "in_list":
            # Check if value is in target list
            if isinstance(target, list):
                return value in target
            return False
        elif operator == "not_in_list":
            # Check if value is not in target list
            if isinstance(target, list):
                return value not in target
            return True
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

    def _make_finding(self, filename, node_type, node_name, property_path, value, message=None, node=None):
        finding = {
            "rule_id": self.rule_id,
            "message": message or self.message,
            "node": f"{node_type}.{node_name}" if node_name != 'unknown' else node_type,
            "file": filename,
            "property_path": property_path,
            "value": value if isinstance(value, str) and len(value) < 200 else str(value)[:200] + "...",
            "status": "violation"
        }
        
        # Enhanced line number extraction
        if node and isinstance(node, dict):
            line_number = self._extract_line_number_from_node(node)
            finding["line"] = line_number
        else:
            finding["line"] = 1
            
        # Add severity information
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        else:
            finding["severity"] = "Minor"
            
        # Add additional context for better debugging
        if node and isinstance(node, dict):
            # Add node type information
            actual_node_type = node.get('type') or node.get('node_type', 'unknown')
            finding["actual_node_type"] = actual_node_type
            
            # Add range information if available
            if 'range' in node:
                finding["range"] = node['range']
                
            # Add location information if available
            if 'loc' in node:
                finding["location"] = node['loc']
            
            # Add Ansible-specific context
            if 'module' in node:
                finding["module"] = node['module']
            if 'action' in node:
                finding["action"] = node['action']
            if 'name' in node and node['name'] != node_name:
                finding["task_name"] = node['name']
        
        return finding
    
    def _extract_line_number_from_node(self, node):
        """Enhanced line number extraction from AST node."""
        if not isinstance(node, dict):
            return 1
            
        # Try Ansible-specific line markers first
        if '__line__' in node:
            return node['__line__']
        
        if '_line_number' in node:
            return node['_line_number']
        
        # Try location info
        if 'loc' in node and isinstance(node['loc'], dict):
            start_loc = node['loc'].get('start', {})
            if isinstance(start_loc, dict) and 'line' in start_loc:
                return start_loc['line']
                
        # Try legacy lineno field
        if 'lineno' in node:
            return node['lineno']
            
        # Try to extract from range and source
        if 'range' in node and 'parent_source' in node:
            try:
                source = node['parent_source']
                start_pos = node['range'][0]
                lines_before = source[:start_pos].count('\n')
                return lines_before + 1
            except Exception:
                pass

        return 1


def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a rule against an Ansible AST.
    """
    try:
        rule = AnsibleGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# For backward compatibility
GenericRule = AnsibleGenericRule
