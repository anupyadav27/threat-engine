"""
Java Generic Rule Engine - Enhanced Version

A generic rule engine that can apply any rule based on JSON metadata to Java AST.
Handles AST traversal, rule applicability checking, and pattern matching.
"""

import re
import json
from java_scanner import logic_implementations
from typing import Any, Dict, List, Optional, Union


class JavaGenericRule:
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
                elif check_type == "conditional_check":
                    findings.extend(self._apply_conditional_check(check, node, filename, node_type, node_name, seen_findings))
        return findings

    def _is_valid_generic_check(self, check):
        check_type = check.get("type") or check.get("check_type")
        if check_type == "custom_function":
            return False
        supported_types = ["regex_match", "property_comparison", "forbidden_value", "required_value", "conditional_check"]
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
        for pattern in patterns:
            # Use DOTALL flag so . matches newlines (useful for multi-line source code)
            if isinstance(value, str) and re.search(pattern, value, re.DOTALL):
                finding = self._make_finding(filename, node_type, node_name, property_path, value, check.get('message', 'Pattern match'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
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

    def _apply_conditional_check(self, check, node, filename, node_type, node_name, seen_findings):
        findings = []
        property_path = check.get("property_path")
        condition_pattern = check.get("condition_pattern")
        target_check = check.get("target_check")
        
        if not property_path or not condition_pattern or not target_check:
            return findings
            
        value = self._get_property(node, property_path)
        
        # Check if condition pattern matches
        if isinstance(value, str) and re.search(condition_pattern, value, re.DOTALL):
            # Apply the target check
            target_check_type = target_check.get("type")
            if target_check_type == "regex_match":
                target_findings = self._apply_regex_check(target_check, node, filename, node_type, node_name, seen_findings)
                findings.extend(target_findings)
            elif target_check_type == "forbidden_value":
                target_findings = self._apply_forbidden_value_check(target_check, node, filename, node_type, node_name, seen_findings)
                findings.extend(target_findings)
            elif target_check_type == "required_value":
                target_findings = self._apply_required_value_check(target_check, node, filename, node_type, node_name, seen_findings)
                findings.extend(target_findings)
        
        return findings

    def _apply_custom_function(self, ast_tree, filename, function_name, seen_findings):
        findings = []
        custom_fn = getattr(logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        def visit_node(node):
            if custom_fn(node):
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": node.get('lineno', 0),
                    "status": "violation"
                }
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
                if node.get('node_type') in node_types:
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
        if node:
            finding["line"] = node.get('lineno', 1)
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        return finding

def run_rule(rule_metadata, ast_tree, filename):
    """
    Main entry point for running a rule against an AST.
    """
    try:
        rule = JavaGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []

# For backward compatibility
GenericRule = JavaGenericRule