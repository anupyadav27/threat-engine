import re
from typing import Any, Dict, List, Optional, Union
from . import arm_logic_implementations  # Custom ARM rule logic functions

class ARMGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    def is_applicable(self, ast_tree):
        if not self.metadata or not self.rule_id:
            return False
        function_name = self._get_custom_function_name()
        required_node_types = self.logic.get("node_types", [])
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
            return bool(matching_nodes)
        return function_name is not None or True  # Apply to all if no specific types

    def check(self, ast_tree, filename):
        findings = []
        seen_findings = set()
        findings.extend(self._apply_generic_logic(ast_tree, filename, seen_findings))
        custom_function_name = self._get_custom_function_name()
        if custom_function_name:
            custom_function = self._get_custom_function(custom_function_name)
            if custom_function:
                findings.extend(self._apply_custom_function(ast_tree, filename, custom_function, seen_findings))
        return findings

    def _get_custom_function_name(self):
        checks = self.logic.get('checks', [])
        if isinstance(checks, list):
            for check in checks:
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check['function']
        if self.logic.get('custom_function'):
            return self.logic['custom_function']
        return None

    def _apply_generic_logic(self, ast_tree, filename, seen_findings):
        findings = []
        checks = self.logic.get('checks', [])
        if not isinstance(checks, list):
            if self._is_valid_generic_check(self.logic):
                findings.extend(self._apply_single_check(ast_tree, filename, self.logic, seen_findings, True))
        else:
            for check in checks:
                if self._is_valid_generic_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, False))
        return findings

    def _apply_single_check(self, ast_tree, filename, check, seen_findings, is_root_check=False):
        findings = []
        check_type = check.get("type") or check.get("check_type")
        node_types = check.get("node_types", self.logic.get("node_types", []))
        required_node_types = node_types if not is_root_check else self.logic.get("node_types", [])
        
        # Get matching nodes
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
        else:
            matching_nodes = [ast_tree]
            
        for node in matching_nodes:
            # Get node information
            if hasattr(node, 'node_type') and node.node_type == 'ResourceNode':
                node_type = getattr(node, 'type', 'unknown')
                node_name = getattr(node, 'name', 'unknown')
                line_num = getattr(node, 'line', 0)
            else:
                node_type = getattr(node, 'node_type', 'unknown')
                node_name = getattr(node, 'name', 'root')
                line_num = getattr(node, 'line', 0)
                
            if check_type == "regex_match":
                findings.extend(self._apply_regex_check(check, node, filename, node_type, node_name, seen_findings))
            elif check_type == "property_comparison":
                findings.extend(self._apply_property_comparison_check(check, node, filename, node_type, node_name, seen_findings))
            elif check_type == "forbidden_value":
                findings.extend(self._apply_forbidden_value_check(check, node, filename, node_type, node_name, seen_findings))
            elif check_type == "required_value":
                findings.extend(self._apply_required_value_check(check, node, filename, node_type, node_name, seen_findings))
            elif check_type == "conditional_check":
                findings.extend(self._apply_conditional_check(check, node, filename, node_type, node_name, seen_findings))
        return findings

    def _is_valid_generic_check(self, check):
        check_type = check.get("type") or check.get("check_type")
        return check_type in ["regex_match", "property_comparison", "forbidden_value", "required_value", "conditional_check"]

    def _apply_regex_check(self, check, node, filename, node_type, node_name, seen_findings):
        findings = []
        patterns = check.get("patterns", [])
        if check.get("pattern"):
            patterns = [check["pattern"]]
        property_path = check.get("property_path")
        if not patterns or not property_path:
            return findings
        value = self._get_property(node, property_path)
        for pattern in patterns:
            if isinstance(value, str) and re.search(pattern, value, re.DOTALL):
                finding = self._make_finding(filename, node_type, node_name, property_path, value, check.get('message', 'Pattern match'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path), f"{node_type}.{node_name}")
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
        if operator and node_value is not None and self._evaluate_comparison(node_value, operator, value):
            finding = self._make_finding(filename, node_type, node_name, property_path, node_value, check.get('message', self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path), f"{node_type}.{node_name}")
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
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path), f"{node_type}.{node_name}")
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
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path), f"{node_type}.{node_name}")
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        return findings

    def _apply_conditional_check(self, check, node, filename, node_type, node_name, seen_findings):
        findings = []
        property_path = check.get("property_path")
        condition_pattern = check.get("condition_pattern")
        target_check = check.get("target_check")
        value = self._get_property(node, property_path)
        if isinstance(value, str) and re.search(condition_pattern, value, re.DOTALL):
            target_type = target_check.get("type")
            if target_type == "regex_match":
                findings.extend(self._apply_regex_check(target_check, node, filename, node_type, node_name, seen_findings))
            elif target_type == "forbidden_value":
                findings.extend(self._apply_forbidden_value_check(target_check, node, filename, node_type, node_name, seen_findings))
            elif target_type == "required_value":
                findings.extend(self._apply_required_value_check(target_check, node, filename, node_type, node_name, seen_findings))
        return findings

    def _apply_custom_function(self, ast_tree, filename, custom_fn, seen_findings):
        findings = []
        
        def visit_node(node):
            # For AST nodes, convert to dict-like structure for custom functions
            node_dict = self._node_to_dict(node) if hasattr(node, 'node_type') else node
            if custom_fn(node_dict):
                line_num = getattr(node, 'line', 0) if hasattr(node, 'line') else 0
                
                # Generate unique key similar to other checks
                node_type = node_dict.get('type', 'unknown') if isinstance(node_dict, dict) else 'unknown'
                node_name = node_dict.get('name', 'unknown') if isinstance(node_dict, dict) else 'unknown'
                node_path = str(node_dict.get('path', [])) if isinstance(node_dict, dict) else ''
                
                unique_key = (self.rule_id, filename, line_num, node_path, f"{node_type}.{node_name}")
                
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    
                    finding = {
                        "rule_id": self.rule_id,
                        "message": self.message,
                        "file": filename,
                        "line": line_num,
                        "status": "violation",
                        # Add fields needed for scanner-level deduplication
                        "property_path": node_dict.get('path', []) if isinstance(node_dict, dict) else [],
                        "value": node_name,  
                        "node": node_dict
                    }
                    if "severity" in self.metadata:
                        finding["severity"] = self.metadata["severity"]
                    elif "defaultSeverity" in self.metadata:
                        finding["severity"] = self.metadata["defaultSeverity"]
                    findings.append(finding)
        
        def traverse(node):
            if hasattr(node, 'node_type'):
                # ARM AST node
                visit_node(node)
                children = getattr(node, 'children', [])
                for child in children:
                    traverse(child)
            elif isinstance(node, dict):
                visit_node(node)
                for v in node.values():
                    traverse(v)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
                    
        traverse(ast_tree)
        return findings
    
    def _node_to_dict(self, node):
        """Convert ARM AST node to dictionary for custom functions"""
        if not hasattr(node, 'node_type'):
            return node
            
        result = {
            'node_type': node.node_type
        }
        
        # Add common attributes
        for attr in ['type', 'name', 'apiVersion', 'location', 'definition', 'line', 'path']:
            if hasattr(node, attr):
                result[attr] = getattr(node, attr)
        
        # For ResourceNode, add properties structure
        if node.node_type == 'ResourceNode':
            properties = {}
            for child in getattr(node, 'children', []):
                if getattr(child, 'node_type', None) == 'PropertyNode':
                    self._add_property_to_dict_for_resource(child, properties, node.path)
            if properties:
                result['properties'] = properties
        
        return result
    
    def _add_property_to_dict_for_resource(self, prop_node, target_dict, resource_path):
        """Add PropertyNode to dictionary structure for ResourceNode properties"""
        if not hasattr(prop_node, 'path') or not prop_node.path:
            return
            
        path = prop_node.path
        
        # For ResourceNode properties, remove the resource path prefix and "properties"
        # e.g., ['resources', '0', 'properties', 'databaseOptions'] -> ['databaseOptions']
        expected_prefix = resource_path + ['properties']
        if len(path) <= len(expected_prefix):
            return
            
        # Check if path starts with the expected prefix
        if path[:len(expected_prefix)] == expected_prefix:
            relative_path = path[len(expected_prefix):]
        else:
            # Fallback: use the full path
            relative_path = path
        
        if not relative_path:
            return
            
        current = target_dict
        
        # Navigate to the right location in dict using relative path
        for part in relative_path[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Set the value
        last_part = relative_path[-1]
        children = getattr(prop_node, 'children', [])
        
        if children:
            # Look for literal value
            for child in children:
                if getattr(child, 'node_type', None) == 'LiteralNode':
                    current[last_part] = getattr(child, 'value', None)
                    return
            # If no literal, create nested dict
            current[last_part] = {}
            for child in children:
                if getattr(child, 'node_type', None) == 'PropertyNode':
                    self._add_property_to_dict_for_resource(child, current, resource_path)
        else:
            current[last_part] = None
    
    def _add_property_to_dict(self, prop_node, target_dict):
        """Add PropertyNode to dictionary structure"""
        if not hasattr(prop_node, 'path') or not prop_node.path:
            return
            
        path = prop_node.path
        current = target_dict
        
        # Navigate to the right location in dict
        for part in path[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Set the value
        last_part = path[-1]
        children = getattr(prop_node, 'children', [])
        
        if children:
            # Look for literal value
            for child in children:
                if getattr(child, 'node_type', None) == 'LiteralNode':
                    current[last_part] = getattr(child, 'value', None)
                    return
            # If no literal, create nested dict
            current[last_part] = {}
            for child in children:
                if getattr(child, 'node_type', None) == 'PropertyNode':
                    self._add_property_to_dict(child, current)
        else:
            current[last_part] = None

    def _get_custom_function(self, function_name):
        if not function_name:
            return None
        func = getattr(arm_logic_implementations, function_name, None)
        return func if callable(func) else None

    def _find_nodes_by_type(self, ast_tree, node_types):
        found_nodes = []
        
        def traverse_ast(node):
            if not node:
                return
                
            # Check if this node matches any of the required types
            node_type = getattr(node, 'node_type', None)
            if node_type in node_types:
                found_nodes.append(node)
            
            # For ResourceNode, also check by ARM resource type
            if (node_type == 'ResourceNode' and 
                hasattr(node, 'type') and 
                node.type in node_types):
                found_nodes.append(node)
            
            # Traverse children
            children = getattr(node, 'children', [])
            for child in children:
                traverse_ast(child)
        
        traverse_ast(ast_tree)
        return found_nodes

    def _get_property(self, node, property_path):
        if not property_path:
            return node
        
        # For ResourceNode, handle relative paths starting with "properties"
        if (hasattr(node, 'node_type') and node.node_type == 'ResourceNode' and
            property_path and property_path[0] == 'properties'):
            
            # Look for property with matching path suffix
            target_path_suffix = property_path[1:]  # Remove "properties" prefix
            
            for child in getattr(node, 'children', []):
                if (getattr(child, 'node_type', None) == 'PropertyNode' and
                    hasattr(child, 'path') and child.path):
                    
                    # Check if this property's path ends with our target
                    child_path = child.path
                    if (len(child_path) >= len(target_path_suffix) and 
                        child_path[-len(target_path_suffix):] == target_path_suffix):
                        
                        # Found the property, get its value
                        for value_child in getattr(child, 'children', []):
                            if (getattr(value_child, 'node_type', None) == 'LiteralNode' and
                                hasattr(value_child, 'value')):
                                return value_child.value
                        return child  # Return the property node if no literal value
            return None
        
        # Standard property traversal for other cases
        current = node
        for part in property_path:
            if hasattr(current, part):
                # Direct attribute access
                current = getattr(current, part)
            elif hasattr(current, 'children'):
                # Search in children for PropertyNode with matching path
                found = False
                for child in current.children:
                    if (getattr(child, 'node_type', None) == 'PropertyNode' and
                        hasattr(child, 'path') and 
                        child.path and child.path[-1] == part):
                        current = child
                        found = True
                        break
                if not found:
                    return None
            elif isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        
        # If we ended up with a PropertyNode, try to get its actual value
        if (hasattr(current, 'node_type') and 
            current.node_type == 'PropertyNode' and 
            hasattr(current, 'children') and current.children):
            # Look for LiteralNode child with value
            for child in current.children:
                if (getattr(child, 'node_type', None) == 'LiteralNode' and
                    hasattr(child, 'value')):
                    return child.value
        
        return current

    def _evaluate_comparison(self, value, operator, target):
        if value is None:
            return False
        if operator == "equals":
            return value == target
        elif operator == "contains":
            return str(target) in str(value)
        elif operator == "startswith":
            return str(value).startswith(str(target))
        elif operator == "endswith":
            return str(value).endswith(str(target))
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
            "node": f"{node_type}.{node_name}",
            "file": filename,
            "property_path": property_path,
            "value": value,
            "status": "violation"
        }
        
        # Get line number from ARM AST node
        if node:
            if hasattr(node, 'line') and node.line:
                finding["line"] = node.line
            elif hasattr(node, 'source_span') and node.source_span:
                finding["line"] = node.source_span[0] if isinstance(node.source_span, tuple) else 1
            elif isinstance(node, dict) and "line" in node:
                finding["line"] = node["line"]
        
        # Set severity
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        else:
            finding["severity"] = "medium"  # default severity
            
        return finding

def run_rule(rule_metadata, ast_tree, filename):
    rule = ARMGenericRule(rule_metadata)
    if not rule.is_applicable(ast_tree):
        return []
    return rule.check(ast_tree, filename)

# For backward compatibility
GenericRule = ARMGenericRule
