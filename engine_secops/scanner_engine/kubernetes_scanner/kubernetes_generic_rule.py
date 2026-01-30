"""
Kubernetes Generic Rule Engine - Enhanced Version

A generic rule engine that can apply any rule based on JSON metadata to Kubernetes manifests.
Handles YAML traversal, rule applicability checking, and pattern matching for Kubernetes resources.
"""

import re
import json
import sys
from kubernetes_scanner import logic_implementations
from typing import Any, Dict, List, Optional, Union


class KubernetesGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    def is_applicable(self, manifest):
        """
        Check if this rule is applicable to the given Kubernetes manifest.
        """
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
        
        # Check for resource types (kind) and API versions
        required_kinds = self.logic.get("resource_types", [])
        required_api_versions = self.logic.get("api_versions", [])
        
        matching_resources = []
        if required_kinds or required_api_versions:
            matching_resources = self._find_matching_resources(
                manifest, required_kinds, required_api_versions
            )
        
        return len(matching_resources) > 0 or custom_function is not None

    def check(self, manifest, filename):
        """
        Run the rule checks against the manifest and return findings.
        """
        try:
            findings = []
            seen_findings = set()
            
            # Apply generic logic checks
            generic_findings = self._apply_generic_logic(manifest, filename, seen_findings)
            findings.extend(generic_findings)
            
            # Apply custom function if defined
            custom_function_name = self._get_custom_function_name()
            if custom_function_name:
                custom_function = self._get_custom_function(custom_function_name)
                if custom_function:
                    custom_findings = self._apply_custom_function(
                        manifest, filename, custom_function_name, seen_findings
                    )
                    findings.extend(custom_findings)
            
            return findings
        except Exception as e:
            import traceback
            traceback.print_exc()
            return []

    def _get_custom_function_name(self):
        """Extract custom function name from logic definition."""
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check.get('function')
        
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        
        return None

    def _apply_generic_logic(self, manifest, filename, seen_findings):
        """Apply generic rule checks defined in metadata."""
        findings = []
        
        if not isinstance(self.logic.get('checks'), list):
            # Single check at root level
            if self._is_valid_generic_check(self.logic):
                findings.extend(
                    self._apply_single_check(manifest, filename, self.logic, seen_findings, is_root_check=True)
                )
        else:
            # Multiple checks
            for check in self.logic.get("checks", []):
                if self._is_valid_generic_check(check):
                    findings.extend(
                        self._apply_single_check(manifest, filename, check, seen_findings, is_root_check=False)
                    )
        
        return findings

    def _apply_single_check(self, manifest, filename, check, seen_findings, is_root_check=False):
        """Apply a single check to the manifest."""
        findings = []
        check_type = check.get("type") or check.get("check_type")
        
        # Get resource types to check
        if is_root_check:
            required_kinds = self.logic.get("resource_types", [])
            required_api_versions = self.logic.get("api_versions", [])
        else:
            required_kinds = check.get("resource_types", self.logic.get("resource_types", []))
            required_api_versions = check.get("api_versions", self.logic.get("api_versions", []))
        
        # Find matching resources
        matching_resources = self._find_matching_resources(
            manifest, required_kinds, required_api_versions
        ) if (required_kinds or required_api_versions) else [manifest]
        
        # Apply check to each matching resource
        for resource in matching_resources:
            resource_kind = resource.get('kind', 'unknown') if isinstance(resource, dict) else 'root'
            resource_name = self._get_resource_name(resource)
            
            if isinstance(check, dict):
                if check_type == "regex_match":
                    findings.extend(
                        self._apply_regex_check(check, resource, filename, resource_kind, resource_name, seen_findings)
                    )
                elif check_type == "property_comparison":
                    findings.extend(
                        self._apply_property_comparison_check(check, resource, filename, resource_kind, resource_name, seen_findings)
                    )
                elif check_type == "forbidden_value":
                    findings.extend(
                        self._apply_forbidden_value_check(check, resource, filename, resource_kind, resource_name, seen_findings)
                    )
                elif check_type == "required_value":
                    findings.extend(
                        self._apply_required_value_check(check, resource, filename, resource_kind, resource_name, seen_findings)
                    )
                elif check_type == "missing_property":
                    findings.extend(
                        self._apply_missing_property_check(check, resource, filename, resource_kind, resource_name, seen_findings)
                    )
        
        return findings

    def _is_valid_generic_check(self, check):
        """Check if this is a valid generic check (not custom function)."""
        check_type = check.get("type") or check.get("check_type")
        
        if check_type == "custom_function":
            return False
        
        # Supported check types for Kubernetes
        supported_types = [
            "regex_match", "property_comparison", "forbidden_value", "required_value",
            "missing_property", "security_context_check", "resource_limit_check", 
            "rbac_check", "network_policy_check"
        ]
        
        return check_type in supported_types

    def _apply_regex_check(self, check, resource, filename, resource_kind, resource_name, seen_findings):
        """Apply regex pattern matching check."""
        findings = []
        patterns = check.get("patterns", [])
        
        # Handle single pattern as well
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
        
        property_path = check.get("property_path")
        if not patterns or not property_path:
            return findings
        
        value = self._get_property(resource, property_path)
        
        for pattern in patterns:
            if isinstance(value, str) and re.search(pattern, value, re.DOTALL | re.MULTILINE):
                finding = self._make_finding(
                    filename, resource_kind, resource_name, property_path, 
                    value, check.get('message', 'Pattern match'), resource
                )
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_property_comparison_check(self, check, resource, filename, resource_kind, resource_name, seen_findings):
        """Apply property comparison check."""
        findings = []
        property_path = check.get("property_path")
        operator = check.get("operator")
        value = check.get("value")
        
        node_value = self._get_property(resource, property_path)
        
        if operator and node_value is not None:
            if self._evaluate_comparison(node_value, operator, value):
                finding = self._make_finding(
                    filename, resource_kind, resource_name, property_path, 
                    node_value, check.get('message', self.message), resource
                )
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
        
        return findings

    def _apply_forbidden_value_check(self, check, resource, filename, resource_kind, resource_name, seen_findings):
        """Check for forbidden values."""
        findings = []
        property_path = check.get("property_path")
        forbidden_values = check.get("forbidden_values", [])
        
        value = self._get_property(resource, property_path)
        
        if value in forbidden_values:
            finding = self._make_finding(
                filename, resource_kind, resource_name, property_path, 
                value, check.get('message', self.message), resource
            )
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_required_value_check(self, check, resource, filename, resource_kind, resource_name, seen_findings):
        """Check for required values."""
        findings = []
        property_path = check.get("property_path")
        required_values = check.get("required_values", [])
        
        value = self._get_property(resource, property_path)
        
        if value not in required_values:
            finding = self._make_finding(
                filename, resource_kind, resource_name, property_path, 
                value, check.get('message', self.message), resource
            )
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_missing_property_check(self, check, resource, filename, resource_kind, resource_name, seen_findings):
        """Check for missing required properties."""
        findings = []
        property_path = check.get("property_path")
        
        value = self._get_property(resource, property_path)
        
        if value is None:
            finding = self._make_finding(
                filename, resource_kind, resource_name, property_path, 
                None, check.get('message', self.message), resource
            )
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
        
        return findings

    def _apply_custom_function(self, manifest, filename, function_name, seen_findings):
        """Apply custom function logic."""
        findings = []
        custom_fn = getattr(logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        
        # Check if the custom function takes manifest and filename parameters
        try:
            import inspect
            sig = inspect.signature(custom_fn)
            params = list(sig.parameters.keys())
            
            if len(params) >= 2 and 'manifest' in params and 'filename' in params:
                # Function expects manifest and filename
                custom_findings = custom_fn(manifest, filename)
                if isinstance(custom_findings, list):
                    findings.extend(custom_findings)
                return findings
        except Exception:
            pass
        
        # Fallback to old node-based approach
        def visit_node(node):
            if custom_fn(node):
                # Extract line number if available
                line_number = node.get('__line__', 0) if isinstance(node, dict) else 0
                
                # Create finding with proper deduplication
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                
                # Add deduplication logic
                resource_kind = node.get('kind', '') if isinstance(node, dict) else ''
                resource_name = self._get_resource_name(node)
                unique_key = (self.rule_id, filename, line_number, resource_kind, resource_name)
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
        
        traverse(manifest)
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

    def _find_matching_resources(self, manifest, required_kinds, required_api_versions):
        """Find resources matching specified kinds and API versions."""
        found_resources = []
        
        def check_resource(resource):
            if not isinstance(resource, dict):
                return False
            
            # Check kind (support both 'kind' field and 'type' field from AST)
            kind_match = True
            if required_kinds:
                kind = resource.get('kind', '') or resource.get('type', '')
                kind_match = kind in required_kinds
            
            # Check API version
            api_match = True
            if required_api_versions:
                api_version = resource.get('apiVersion', '') or resource.get('api_version', '')
                api_match = api_version in required_api_versions
            
            return kind_match and api_match
        
        # Check if this is already an AST resource node
        if isinstance(manifest, dict):
            node_type = manifest.get('node_type', '') or manifest.get('type', '')
            
            # If this is a KubernetesResource node from AST, check it directly
            if node_type == 'KubernetesResource' or 'kind' in manifest:
                if check_resource(manifest):
                    found_resources.append(manifest)
                    return found_resources
        
        # Fallback: traverse for nested resources
        def traverse(node):
            if isinstance(node, dict):
                # Check if this node is a Kubernetes resource
                if 'kind' in node or node.get('node_type') == 'KubernetesResource':
                    if check_resource(node):
                        found_resources.append(node)
                
                # Continue traversing
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        traverse(value)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
        
        # Handle single resource or list of resources
        if isinstance(manifest, dict):
            if 'kind' in manifest and manifest.get('kind') == 'List':
                # Kubernetes List object
                items = manifest.get('items', [])
                for item in items:
                    traverse(item)
            else:
                traverse(manifest)
        elif isinstance(manifest, list):
            for item in manifest:
                traverse(item)
        
        return found_resources

    def _get_resource_name(self, resource):
        """Extract resource name from metadata."""
        if not isinstance(resource, dict):
            return 'unknown'
        
        metadata = resource.get('metadata', {})
        if isinstance(metadata, dict):
            return metadata.get('name', 'unknown')
        
        return 'unknown'

    def _get_property(self, node, property_path):
        """Navigate through nested properties using a path."""
        if not property_path:
            return None
        
        # Handle string path (convert to list)
        if isinstance(property_path, str):
            property_path = property_path.split('.')
        
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
        """Evaluate comparison operations."""
        if value is None:
            return False
        
        if operator == "equals":
            return value == target
        elif operator == "not_equals":
            return value != target
        elif operator == "contains":
            # Handle both list and string contains
            if isinstance(value, list):
                return target in value
            else:
                return str(target) in str(value)
        elif operator == "not_contains":
            # Handle both list and string not contains
            if isinstance(value, list):
                return target not in value
            else:
                return str(target) not in str(value)
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
        elif operator == "in":
            if isinstance(target, list):
                return value in target
            return False
        elif operator == "not_in":
            if isinstance(target, list):
                return value not in target
            return True
        
        return False

    def _make_finding(self, filename, resource_kind, resource_name, property_path, value, message=None, resource=None):
        """Create a finding dictionary."""
        # Extract proper resource name from resource dict if available
        if resource and isinstance(resource, dict):
            if resource_name == 'unknown':
                resource_name = resource.get('name') or resource.get('resource_name', 'unknown')
        
        finding = {
            "rule_id": self.rule_id,
            "message": message or self.message,
            "resource": f"{resource_kind}/{resource_name}",
            "file": filename,
            "property_path": property_path,
            "value": value,
            "status": "violation"
        }
        
        # Add line number if available
        if resource and isinstance(resource, dict):
            finding["line"] = resource.get('__line__', 1)
        else:
            finding["line"] = 1
        
        # Add severity
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        elif "defaultSeverity" in self.metadata:
            finding["severity"] = self.metadata["defaultSeverity"]
        
        return finding


def run_rule(rule_metadata, manifest, filename):
    """
    Main entry point for running a rule against a Kubernetes manifest.
    
    Args:
        rule_metadata: Dictionary containing rule definition
        manifest: Parsed Kubernetes YAML manifest (dict or list)
        filename: Path to the manifest file
    
    Returns:
        List of findings (violations)
    """
    try:
        rule = KubernetesGenericRule(rule_metadata)
        if not rule.is_applicable(manifest):
            return []
        
        findings = rule.check(manifest, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# For backward compatibility
GenericRule = KubernetesGenericRule
K8sGenericRule = KubernetesGenericRule
