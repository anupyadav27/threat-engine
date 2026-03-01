"""
CloudFormation Generic Rule Engine - Enhanced Version

A generic rule engine that can apply any rule based on JSON metadata to CloudFormation AST.
Handles AST traversal, rule applicability checking, and pattern matching for CloudFormation templates.
"""

import re
import json
import sys
import yaml
from . import cloudformation_logic_implementations
from typing import Any, Dict, List, Optional, Union


class CloudFormationGenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    def is_applicable(self, ast_tree):
        """Check if this rule is applicable to the given CloudFormation template."""
        if not self.metadata or not self.rule_id:
            return False
            
        # Check for custom function applicability
        function_name = self._get_custom_function_name()
        if function_name:
            custom_function = self._get_custom_function(function_name)
            if custom_function:
                return True
        
        # Check for required node types
        required_node_types = self.logic.get("node_types", [])
        if required_node_types:
            matching_nodes = self._find_nodes_by_type(ast_tree, required_node_types)
            return len(matching_nodes) > 0
            
        # Check for required resource types
        required_resource_types = self.logic.get("resource_types", [])
        if required_resource_types:
            matching_resources = self._find_resources_by_type(ast_tree, required_resource_types)
            return len(matching_resources) > 0
            
        return True  # Default to applicable for CloudFormation templates

    def check(self, ast_tree, filename):
        """Run the rule checks against the CloudFormation template."""
        try:
            # Store AST tree for cross-resource checks
            self._ast_tree = ast_tree
            
            findings = []
            seen_findings = set()
            
            # Apply generic logic checks
            generic_findings = self._apply_generic_logic(ast_tree, filename, seen_findings)
            findings.extend(generic_findings)
            
            # Apply custom function if present
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
        """Extract custom function name from rule metadata."""
        if isinstance(self.logic.get('checks'), list):
            for check in self.logic.get('checks', []):
                if check.get('type') == 'custom_function' and check.get('function_name'):
                    return check.get('function_name')
                if check.get('type') == 'custom_function' and check.get('function'):
                    return check.get('function')
        if self.logic.get('custom_function'):
            return self.logic.get('custom_function')
        return None

    def _apply_generic_logic(self, ast_tree, filename, seen_findings):
        """Apply generic rule checks based on metadata configuration."""
        findings = []
        
        if not isinstance(self.logic.get('checks'), list):
            # Single check at root level
            if self._is_valid_generic_check(self.logic):
                findings.extend(self._apply_single_check(ast_tree, filename, self.logic, seen_findings, is_root_check=True))
        else:
            # Multiple checks
            for check in self.logic.get("checks", []):
                if self._is_valid_generic_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, is_root_check=False))
                if self._is_valid_generic_check(check):
                    findings.extend(self._apply_single_check(ast_tree, filename, check, seen_findings, is_root_check=False))
                    
        return findings

    def _apply_single_check(self, ast_tree, filename, check, seen_findings, is_root_check=False):
        """Apply a single check configuration to the CloudFormation template."""
        findings = []
        check_type = check.get("type") or check.get("check_type")
        
        # Get target nodes based on check configuration
        target_nodes = self._get_target_nodes(ast_tree, check, is_root_check)
        
        for node in target_nodes:
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
                elif check_type == "resource_policy_check":
                    findings.extend(self._apply_resource_policy_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "intrinsic_function_check":
                    findings.extend(self._apply_intrinsic_function_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "security_group_check":
                    findings.extend(self._apply_security_group_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "encryption_check":
                    findings.extend(self._apply_encryption_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "administration_services_restriction":
                    findings.extend(self._apply_administration_services_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "s3_public_access_check":
                    findings.extend(self._apply_s3_public_access_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "public_network_access_check":
                    findings.extend(self._apply_public_network_access_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "s3_https_check":
                    findings.extend(self._apply_s3_https_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "iam_policy_scope_check":
                    findings.extend(self._apply_iam_policy_scope_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "tag_validation_check":
                    findings.extend(self._apply_tag_validation_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "tag_naming_convention_check":
                    findings.extend(self._apply_tag_naming_convention_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "parsing_failure_check":
                    findings.extend(self._apply_parsing_failure_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "public_api_security_check":
                    findings.extend(self._apply_public_api_security_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "backup_retention_check":
                    findings.extend(self._apply_backup_retention_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "versioning_check":
                    findings.extend(self._apply_versioning_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "log_group_declaration_check":
                    findings.extend(self._apply_log_group_declaration_check(check, node, filename, node_type, node_name, seen_findings))
                elif check_type == "logging_check":
                    findings.extend(self._apply_logging_check(check, node, filename, node_type, node_name, seen_findings))
                    
        return findings

    def _get_target_nodes(self, ast_tree, check, is_root_check=False):
        """Get target nodes for a check based on node types and resource types."""
        target_nodes = []
        
        # Get node types
        if is_root_check:
            node_types = self.logic.get("node_types", [])
            resource_types = self.logic.get("resource_types", [])
        else:
            node_types = check.get("node_types", self.logic.get("node_types", []))
            resource_types = check.get("resource_types", self.logic.get("resource_types", []))
        
        # Find nodes by type
        if node_types:
            target_nodes.extend(self._find_nodes_by_type(ast_tree, node_types))
        
        # Find resources by type
        if resource_types:
            target_nodes.extend(self._find_resources_by_type(ast_tree, resource_types))
        
        # If no specific targeting, use the whole tree
        if not target_nodes and not node_types and not resource_types:
            target_nodes = [ast_tree]
            
        return target_nodes

    def _is_valid_generic_check(self, check):
        """Check if a check configuration is valid for generic processing."""
        check_type = check.get("type") or check.get("check_type")
        if check_type == "custom_function":
            return False
            
        # CloudFormation-specific check types
        supported_types = [
            "regex_match", "property_comparison", "forbidden_value", "required_value",
            "resource_policy_check", "intrinsic_function_check", "security_group_check",
            "encryption_check", "public_access_check", "logging_check", "administration_services_restriction",
            "s3_public_access_check", "public_network_access_check", "s3_https_check", "iam_policy_scope_check",
            "tag_validation_check", "tag_naming_convention_check", "parsing_failure_check", "public_api_security_check", "backup_retention_check", "versioning_check", "log_group_declaration_check"
        ]
        return check_type in supported_types

    def _apply_regex_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply regex pattern matching to CloudFormation properties."""
        findings = []
        patterns = check.get("patterns", [])
        
        # Handle single pattern
        single_pattern = check.get("pattern")
        if single_pattern:
            patterns = [single_pattern]
            
        property_path = check.get("property_path", [])
        if not patterns:
            return findings
            
        value = self._get_property(node, property_path)
        
        for pattern in patterns:
            if isinstance(value, str) and re.search(pattern, value, re.DOTALL | re.MULTILINE):
                finding = self._make_finding(filename, node_type, node_name, property_path, value, 
                                           check.get('message', 'Pattern match'), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
                    
        return findings

    def _apply_property_comparison_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Apply property value comparison checks."""
        findings = []
        property_path = check.get("property_path", [])
        operator = check.get("operator")
        expected_value = check.get("value")
        
        node_value = self._get_property(node, property_path)
        
        if operator and node_value is not None:
            if self._evaluate_comparison(node_value, operator, expected_value):
                finding = self._make_finding(filename, node_type, node_name, property_path, node_value, 
                                           check.get('message', self.message), node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
                    
        return findings

    def _apply_forbidden_value_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for forbidden values in CloudFormation properties."""
        findings = []
        property_path = check.get("property_path", [])
        forbidden_values = check.get("forbidden_values", [])
        
        value = self._get_property(node, property_path)
        
        if value in forbidden_values:
            finding = self._make_finding(filename, node_type, node_name, property_path, value, 
                                       check.get('message', self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
                
        return findings

    def _apply_required_value_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for required values in CloudFormation properties."""
        findings = []
        property_path = check.get("property_path", [])
        required_values = check.get("required_values", [])
        
        value = self._get_property(node, property_path)
        
        if value not in required_values:
            finding = self._make_finding(filename, node_type, node_name, property_path, value, 
                                       check.get('message', self.message), node)
            unique_key = (self.rule_id, filename, finding.get('line', 0), str(property_path))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                findings.append(finding)
                
        return findings

    def _apply_resource_policy_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check resource policies for security issues."""
        findings = []
        
        # Look for policy documents
        policy_properties = ["PolicyDocument", "AssumeRolePolicyDocument", "Policy"]
        for prop in policy_properties:
            policy_doc = self._get_property(node, ["properties", prop])
            if policy_doc:
                # Check for wildcard principals, actions, or resources
                if self._has_wildcard_policy(policy_doc):
                    finding = self._make_finding(filename, node_type, node_name, ["properties", prop], 
                                               policy_doc, check.get('message', 'Overly permissive policy'), node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), str(["properties", prop]))
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
        return findings

    def _apply_intrinsic_function_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for proper use of CloudFormation intrinsic functions."""
        findings = []
        
        # Look for intrinsic functions in the node
        intrinsic_functions = self._find_intrinsic_functions(node)
        
        forbidden_functions = check.get("forbidden_functions", [])
        required_functions = check.get("required_functions", [])
        
        for func_name, func_value in intrinsic_functions:
            if forbidden_functions and func_name in forbidden_functions:
                finding = self._make_finding(filename, node_type, node_name, [], func_value,
                                           f"Forbidden intrinsic function: {func_name}", node)
                unique_key = (self.rule_id, filename, finding.get('line', 0), func_name)
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
                    
        return findings

    def _apply_security_group_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check security group rules for overly permissive access."""
        findings = []
        
        if node.get('resource_type') == 'AWS::EC2::SecurityGroup':
            ingress_rules = self._get_property(node, ["properties", "SecurityGroupIngress"]) or []
            egress_rules = self._get_property(node, ["properties", "SecurityGroupEgress"]) or []
            
            for rules, rule_type in [(ingress_rules, "ingress"), (egress_rules, "egress")]:
                if isinstance(rules, list):
                    for rule in rules:
                        if self._is_permissive_rule(rule):
                            finding = self._make_finding(filename, node_type, node_name, 
                                                       ["properties", f"SecurityGroup{rule_type.title()}"],
                                                       rule, f"Overly permissive {rule_type} rule", node)
                            unique_key = (self.rule_id, filename, finding.get('line', 0), f"{rule_type}_rule")
                            if unique_key not in seen_findings:
                                seen_findings.add(unique_key)
                                findings.append(finding)
                                
        return findings

    def _apply_encryption_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for proper encryption configuration."""
        findings = []
        
        encryption_properties = {
            "AWS::S3::Bucket": ["BucketEncryption"],
            "AWS::RDS::DBInstance": ["StorageEncrypted"],
            "AWS::EBS::Volume": ["Encrypted"],
            "AWS::SNS::Topic": ["KmsMasterKeyId"],
            "AWS::SQS::Queue": ["KmsMasterKeyId"]
        }
        
        resource_type = node.get('resource_type', '')
        if resource_type in encryption_properties:
            for prop in encryption_properties[resource_type]:
                encryption_value = self._get_property(node, ["properties", prop])
                if not self._is_encryption_enabled(encryption_value, prop):
                    finding = self._make_finding(filename, node_type, node_name, ["properties", prop],
                                               encryption_value, f"Encryption not properly configured for {prop}", node)
                    unique_key = (self.rule_id, filename, finding.get('line', 0), prop)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
        return findings

    def _apply_administration_services_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check security group rules for administration services accessible from public IPs."""
        findings = []
        
        if node.get('resource_type') == 'AWS::EC2::SecurityGroup':
            administration_ports = check.get("administration_ports", [22, 3389, 5985, 5986, 21, 23, 135, 445, 1433, 3306, 5432])
            forbidden_cidrs = check.get("forbidden_cidrs", ["0.0.0.0/0", "::/0"])
            
            ingress_rules = self._get_property(node, ["properties", "SecurityGroupIngress"]) or []
            
            # Handle both list and dict formats for ingress rules
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]
            
            for rule in ingress_rules:
                if self._is_administration_rule_vulnerable(rule, administration_ports, forbidden_cidrs):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    cidr = rule.get('CidrIp', rule.get('CidrIpv6', 'Unknown'))
                    protocol = rule.get('IpProtocol', '').lower()
                    
                    # Format port information for the message
                    if protocol == '-1' or protocol == 'all':
                        port_info = "all ports"
                    elif from_port is not None and to_port is not None:
                        if from_port == to_port:
                            port_info = f"port {from_port}"
                        else:
                            port_info = f"ports {from_port}-{to_port}"
                    elif from_port is not None:
                        port_info = f"port {from_port}"
                    else:
                        port_info = "unknown port"
                    
                    finding = self._make_finding(
                        filename, node_type, node_name, 
                        ["properties", "SecurityGroupIngress"],
                        rule, 
                        f"Security group allows administration services ({port_info}) access from {cidr}",
                        node
                    )
                    
                    unique_key = (self.rule_id, filename, finding.get('line', 0), f"admin_{port_info}_{cidr}")
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
        return findings

    def _is_administration_rule_vulnerable(self, rule, administration_ports, forbidden_cidrs):
        """Check if a security group rule allows administration services from forbidden CIDRs."""
        if not isinstance(rule, dict):
            return False
            
        # Get port information
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        protocol = rule.get('IpProtocol', '').lower()
        
        # Skip non-TCP rules for most administration services
        if protocol not in ['tcp', '-1', 'all']:
            return False
        
        # Check if rule covers administration ports
        covers_admin_port = False
        
        # Convert port values to integers for comparison
        try:
            if from_port is not None:
                from_port = int(from_port) if isinstance(from_port, str) else from_port
            if to_port is not None:
                to_port = int(to_port) if isinstance(to_port, str) else to_port
        except (ValueError, TypeError):
            # If port values can't be converted to int, skip this check
            return False
        
        if from_port is None and to_port is None:
            # Rule allows all ports
            covers_admin_port = True
        elif from_port is not None and to_port is not None:
            # Check if port range includes any administration ports
            for admin_port in administration_ports:
                if from_port <= admin_port <= to_port:
                    covers_admin_port = True
                    break
        elif from_port is not None and to_port is None:
            # Single port rule
            covers_admin_port = from_port in administration_ports
        
        if not covers_admin_port:
            return False
            
        # Check if rule allows access from forbidden CIDRs
        cidr_ip = rule.get('CidrIp')
        cidr_ipv6 = rule.get('CidrIpv6')
        
        if cidr_ip in forbidden_cidrs or cidr_ipv6 in forbidden_cidrs:
            return True
            
        return False

    def _apply_s3_public_access_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check S3 bucket public access block configuration and ACL settings."""
        findings = []
        
        if node.get('resource_type') == 'AWS::S3::Bucket':
            check_properties = check.get("check_properties", [])
            
            for prop_check in check_properties:
                property_path = prop_check.get("property_path", [])
                expected_value = prop_check.get("expected_value")
                forbidden_values = prop_check.get("forbidden_values", [])
                custom_message = prop_check.get("message", "S3 bucket public access misconfiguration")
                
                actual_value = self._get_property(node, property_path)
                
                # Check if the property is missing or has wrong value
                violation_found = False
                violation_reason = ""
                
                if expected_value is not None:
                    # Handle expected value logic (existing functionality)
                    if actual_value is None:
                        # Property is missing entirely
                        violation_found = True
                        violation_reason = f"Property {'.'.join(property_path[2:])} is not configured"
                    elif actual_value != expected_value:
                        # Property has wrong value
                        violation_found = True
                        violation_reason = f"Property {'.'.join(property_path[2:])} is {actual_value}, expected {expected_value}"
                
                elif forbidden_values:
                    # Handle forbidden values logic (new functionality for ACLs)
                    if actual_value in forbidden_values:
                        violation_found = True
                        violation_reason = f"Property {'.'.join(property_path[2:])} has forbidden value '{actual_value}'"
                
                if violation_found:
                    finding = self._make_finding(
                        filename, node_type, node_name, 
                        property_path,
                        actual_value, 
                        f"{custom_message} - {violation_reason}",
                        node
                    )
                    
                    # Create unique key for deduplication
                    prop_name = '.'.join(property_path[2:]) if len(property_path) > 2 else 'unknown'
                    unique_key = (self.rule_id, filename, finding.get('line', 0), prop_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
        return findings

    def _apply_public_network_access_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for resources that allow public network access."""
        findings = []
        
        resource_type = node.get('resource_type', '')
        resource_checks = check.get("resource_checks", [])
        
        # Find applicable checks for this resource type
        applicable_checks = [rc for rc in resource_checks if rc.get("resource_type") == resource_type]
        
        for resource_check in applicable_checks:
            property_path = resource_check.get("property_path", [])
            forbidden_value = resource_check.get("forbidden_value")
            custom_message = resource_check.get("message", "Resource allows public network access")
            
            # Handle wildcard in property path for arrays (like NetworkInterfaces)
            if "*" in property_path:
                findings.extend(self._check_wildcard_property(
                    node, property_path, forbidden_value, custom_message, 
                    filename, node_type, node_name, seen_findings
                ))
            else:
                # Regular property check
                actual_value = self._get_property(node, property_path)
                
                if actual_value == forbidden_value:
                    finding = self._make_finding(
                        filename, node_type, node_name,
                        property_path,
                        actual_value,
                        custom_message,
                        node
                    )
                    
                    prop_name = '.'.join(property_path[2:]) if len(property_path) > 2 else 'unknown'
                    unique_key = (self.rule_id, filename, finding.get('line', 0), prop_name)
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
                        
        return findings

    def _check_wildcard_property(self, node, property_path, forbidden_value, message, filename, node_type, node_name, seen_findings):
        """Handle property paths with wildcards for checking arrays."""
        findings = []
        
        # Find the wildcard position
        wildcard_index = property_path.index("*")
        base_path = property_path[:wildcard_index]
        remaining_path = property_path[wildcard_index + 1:]
        
        # Get the array at the base path
        array_value = self._get_property(node, base_path)
        
        if isinstance(array_value, list):
            for i, item in enumerate(array_value):
                if isinstance(item, dict):
                    # Construct the specific path for this array item
                    specific_path = base_path + [str(i)] + remaining_path
                    actual_value = self._get_nested_value(item, remaining_path)
                    
                    if actual_value == forbidden_value:
                        finding = self._make_finding(
                            filename, node_type, node_name,
                            specific_path,
                            actual_value,
                            f"{message} (item {i})",
                            node
                        )
                        
                        prop_name = f"{'.'.join(base_path[2:])}.{i}.{'.'.join(remaining_path)}" if len(base_path) > 2 else f"item_{i}"
                        unique_key = (self.rule_id, filename, finding.get('line', 0), prop_name)
                        if unique_key not in seen_findings:
                            seen_findings.add(unique_key)
                            findings.append(finding)
                            
        return findings

    def _get_nested_value(self, obj, path):
        """Get a nested value from an object using a path list."""
        current = obj
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _apply_s3_https_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check S3 bucket policies for HTTPS-only requirements."""
        findings = []
        
        if node.get('resource_type') == 'AWS::S3::BucketPolicy':
            # Check both PolicyDocument and PolicyText (different property names used)
            policy_props = ['PolicyDocument', 'PolicyText']
            
            policy_found = False
            secure_transport_found = False
            deny_http_found = False
            
            for policy_prop in policy_props:
                policy = self._get_property(node, ['properties', policy_prop])
                if policy and isinstance(policy, dict):
                    policy_found = True
                    
                    statements = policy.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    
                    for i, statement in enumerate(statements):
                        if isinstance(statement, dict):
                            # Check for HTTPS requirement (allow with aws:SecureTransport: true)
                            if self._check_https_requirement(statement):
                                secure_transport_found = True
                            
                            # Check for HTTP denial (deny with aws:SecureTransport: false)
                            if self._check_http_denial(statement):
                                deny_http_found = True
            
            # Generate findings if security requirements are not met
            if policy_found and not (secure_transport_found or deny_http_found):
                finding = self._make_finding(
                    filename, node_type, node_name,
                    ['properties', 'PolicyDocument'],  # Generic path
                    None,
                    "S3 bucket policy does not enforce HTTPS-only access (missing aws:SecureTransport condition)",
                    node
                )
                
                unique_key = (self.rule_id, filename, finding.get('line', 0), 'https_enforcement')
                if unique_key not in seen_findings:
                    seen_findings.add(unique_key)
                    findings.append(finding)
                    
        return findings

    def _check_https_requirement(self, statement):
        """Check if a statement requires HTTPS (allows with aws:SecureTransport: true)."""
        if statement.get('Effect', '').upper() != 'ALLOW':
            return False
            
        condition = statement.get('Condition', {})
        if not isinstance(condition, dict):
            return False
            
        bool_conditions = condition.get('Bool', {})
        if not isinstance(bool_conditions, dict):
            return False
            
        secure_transport = bool_conditions.get('aws:SecureTransport')
        
        # Check for various representations of true
        if secure_transport is True:
            return True
        if isinstance(secure_transport, str) and secure_transport.lower() == 'true':
            return True
            
        return False

    def _check_http_denial(self, statement):
        """Check if a statement denies HTTP (denies with aws:SecureTransport: false)."""
        if statement.get('Effect', '').upper() != 'DENY':
            return False
            
        condition = statement.get('Condition', {})
        if not isinstance(condition, dict):
            return False
            
        bool_conditions = condition.get('Bool', {})
        if not isinstance(bool_conditions, dict):
            return False
            
        secure_transport = bool_conditions.get('aws:SecureTransport')
        
        # Check for various representations of false
        if secure_transport is False:
            return True
        if isinstance(secure_transport, str) and secure_transport.lower() == 'false':
            return True
            
        return False

    def _apply_iam_policy_scope_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check for overly permissive IAM policies with wildcard actions or resources."""
        findings = []
        
        # Get the actual CloudFormation resource type from the resource_type field
        resource_type = node.get('resource_type')
        
        # Check if this is an IAM resource with policies
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties (note: using lowercase 'properties' key)
            properties = node.get('properties', {})
            
            # Collect all policy documents from different sources
            policy_documents = []
            
            # For AWS::IAM::Role, AWS::IAM::User, AWS::IAM::Group - check Policies property
            if resource_type in ['AWS::IAM::Role', 'AWS::IAM::User', 'AWS::IAM::Group']:
                policies_list = properties.get('Policies', [])
                if isinstance(policies_list, list):
                    for policy in policies_list:
                        if isinstance(policy, dict) and 'PolicyDocument' in policy:
                            policy_name = policy.get('PolicyName', 'unnamed')
                            policy_documents.append((policy['PolicyDocument'], f"Policies.{policy_name}"))
                            
            # For AWS::IAM::Policy and AWS::IAM::ManagedPolicy - check PolicyDocument
            elif resource_type in ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy']:
                if 'PolicyDocument' in properties:
                    policy_documents.append((properties['PolicyDocument'], 'PolicyDocument'))
                    
            # Check each policy document for overly permissive statements
            for policy_doc, policy_source in policy_documents:
                if isinstance(policy_doc, dict):
                    statements = policy_doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]  # Handle single statement
                        
                    for idx, statement in enumerate(statements):
                        if not isinstance(statement, dict):
                            continue
                            
                        # Only check Allow statements
                        effect = statement.get('Effect', '')
                        if effect.upper() != 'ALLOW':
                            continue
                            
                        # Check for wildcard actions
                        actions = statement.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                            
                        # Check for wildcard resources  
                        resources = statement.get('Resource', [])
                        if not isinstance(resources, list):
                            resources = [resources]
                            
                        has_wildcard_action = any(action == '*' for action in actions if isinstance(action, str))
                        has_wildcard_resource = any(resource == '*' for resource in resources if isinstance(resource, str))
                        
                        if has_wildcard_action and has_wildcard_resource:
                            violations = []
                            if has_wildcard_action:
                                violations.append('Action: "*"')
                            if has_wildcard_resource:
                                violations.append('Resource: "*"')
                                
                            violation_detail = ' and '.join(violations)
                            message = f"IAM policy grants overly broad permissions ({violation_detail})"
                            
                            line_num = node.get('lineno', 1)
                            finding_key = f"{node_name}_{policy_source}_statement_{idx}"
                            
                            if finding_key not in seen_findings:
                                finding = {
                                    'rule_id': self.rule_id,
                                    'message': message,
                                    'filename': filename,
                                    'line': line_num,
                                    'node': f"Resource.{node_name}",
                                    'severity': self.metadata.get('defaultSeverity', 'Medium')
                                }
                                findings.append(finding)
                                seen_findings.add(finding_key)
                                
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings

    def _apply_tag_validation_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if AWS resource tags have valid format according to AWS standards."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should have tags validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Look for Tags property in different formats
            tags = properties.get('Tags', [])
            
            if not isinstance(tags, list):
                return findings
                
            # Validate each tag
            for tag_index, tag in enumerate(tags):
                if not isinstance(tag, dict):
                    continue
                    
                tag_key = tag.get('Key', '')
                if not isinstance(tag_key, str):
                    continue
                    
                # Check tag key format
                validation_errors = self._validate_tag_key(tag_key)
                
                for error in validation_errors:
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_tag_{tag_index}_{error['type']}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"Invalid tag key '{tag_key}': {error['message']}",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': ['properties', 'Tags', str(tag_index), 'Key'],
                            'value': tag_key
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
    
    def _validate_tag_key(self, tag_key):
        """Validate a single tag key according to AWS standards."""
        errors = []
        
        # Check length (1-128 characters)
        if len(tag_key) == 0:
            errors.append({
                'type': 'empty',
                'message': 'tag key cannot be empty'
            })
        elif len(tag_key) > 128:
            errors.append({
                'type': 'length',
                'message': f'tag key length ({len(tag_key)}) exceeds 128 character limit'
            })
            
        # Check allowed characters
        # AWS allows: Unicode letters, digits, spaces, and _ . : / = + - @
        import re
        # Pattern for allowed characters (letters, digits, spaces, and specific symbols)
        allowed_pattern = r'^[\w\s.:/=+\-@]*$'
        
        if not re.match(allowed_pattern, tag_key):
            # Find invalid characters
            invalid_chars = []
            for char in tag_key:
                if not re.match(r'[\w\s.:/=+\-@]', char):
                    if char not in invalid_chars:
                        invalid_chars.append(char)
                        
            if invalid_chars:
                errors.append({
                    'type': 'invalid_chars',
                    'message': f'contains invalid characters: {", ".join(repr(c) for c in invalid_chars)}. Allowed: letters, digits, spaces, _ . : / = + - @'
                })
                
        return errors
        
    def _apply_tag_naming_convention_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if AWS resource tag keys follow the specified naming convention."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should have tags validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Look for Tags property in different formats
            tags = properties.get('Tags', [])
            
            if not isinstance(tags, list):
                return findings
                
            # Get naming convention configuration
            naming_convention = check.get('naming_convention', {})
            allowed_patterns = naming_convention.get('allowed_patterns', [])
            convention_type = naming_convention.get('type', 'kebab-case')
            description = naming_convention.get('description', 'follow naming convention')
                
            # Validate each tag key
            for tag_index, tag in enumerate(tags):
                if not isinstance(tag, dict):
                    continue
                    
                tag_key = tag.get('Key', '')
                if not isinstance(tag_key, str):
                    continue
                    
                # Check if tag key follows naming convention
                if not self._validate_tag_naming_convention(tag_key, allowed_patterns):
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_tag_naming_{tag_index}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"Tag key '{tag_key}' does not follow naming convention. Expected: {description}",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': ['properties', 'Tags', str(tag_index), 'Key'],
                            'value': tag_key
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
    
    def _validate_tag_naming_convention(self, tag_key, allowed_patterns):
        """Check if a tag key matches any of the allowed naming convention patterns."""
        import re
        
        if not allowed_patterns:
            return True
            
        for pattern in allowed_patterns:
            if re.match(pattern, tag_key):
                return True
                
        return False
        
        return errors

    def _apply_tag_validation_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if AWS resource tags have valid format according to AWS standards."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should have tags validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Look for Tags property in different formats
            tags = properties.get('Tags', [])
            
            if not isinstance(tags, list):
                return findings
                
            # Validate each tag
            for tag_index, tag in enumerate(tags):
                if not isinstance(tag, dict):
                    continue
                    
                tag_key = tag.get('Key', '')
                if not isinstance(tag_key, str):
                    continue
                    
                # Check tag key format
                validation_errors = self._validate_tag_key(tag_key)
                
                for error in validation_errors:
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_tag_{tag_index}_{error['type']}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"Invalid tag key '{tag_key}': {error['message']}",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': ['properties', 'Tags', str(tag_index), 'Key'],
                            'value': tag_key
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
    
    def _validate_tag_key(self, tag_key):
        """Validate a single tag key according to AWS standards."""
        errors = []
        
        # Check length (1-128 characters)
        if len(tag_key) == 0:
            errors.append({
                'type': 'empty',
                'message': 'tag key cannot be empty'
            })
        elif len(tag_key) > 128:
            errors.append({
                'type': 'length',
                'message': f'tag key length ({len(tag_key)}) exceeds 128 character limit'
            })
            
        # Check allowed characters
        # AWS allows: Unicode letters, digits, spaces, and _ . : / = + - @
        import re
        # Pattern for allowed characters (letters, digits, spaces, and specific symbols)
        allowed_pattern = r'^[\w\s.:/=+\-@]*$'
        
        if not re.match(allowed_pattern, tag_key):
            # Find invalid characters
            invalid_chars = []
            for char in tag_key:
                if not re.match(r'[\w\s.:/=+\-@]', char):
                    if char not in invalid_chars:
                        invalid_chars.append(char)
                        
            if invalid_chars:
                errors.append({
                    'type': 'invalid_chars',
                    'message': f'contains invalid characters: {", ".join(repr(c) for c in invalid_chars)}. Allowed: letters, digits, spaces, _ . : / = + - @'
                })
                
        return errors
        """Apply custom function logic to the CloudFormation template."""
        findings = []
        custom_fn = getattr(cloudformation_logic_implementations, function_name, None)
        if not custom_fn:
            return findings
        
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
        
        # Fallback to node-based approach
        def visit_node(node):
            if custom_fn(node):
                line_number = node.get('lineno', 1) if isinstance(node, dict) else 1
                
                finding = {
                    "rule_id": self.rule_id,
                    "message": self.message,
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                }
                
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
        """Get custom function implementation."""
        if not function_name:
            return None
        if hasattr(cloudformation_logic_implementations, function_name):
            func = getattr(cloudformation_logic_implementations, function_name)
            if callable(func):
                return func
        return None

    def _apply_custom_function(self, ast_tree, filename, custom_function_name, seen_findings):
        """Apply custom function to the AST."""
        findings = []
        custom_function = self._get_custom_function(custom_function_name)
        if custom_function:
            try:
                custom_findings = custom_function(ast_tree, filename, self.metadata)
                # Process findings to ensure they have proper line numbers
                for finding in custom_findings:
                    # Add line number if missing
                    if 'line' not in finding:
                        # Try to find line number from AST if possible
                        finding['line'] = self._find_line_number(ast_tree, finding.get('node', '').replace('Resource.', ''))
                    
                    # Check for duplicates
                    unique_key = (finding.get('rule_id', self.rule_id), filename, finding.get('line', 0), str(finding.get('property_path', [])))
                    if unique_key not in seen_findings:
                        seen_findings.add(unique_key)
                        findings.append(finding)
            except Exception as e:
                print(f"Error in custom function {custom_function_name}: {e}")
        return findings

    def _find_line_number(self, ast_tree, resource_name):
        """Try to find line number for a resource in the AST."""
        # This is a simplified implementation - in a real scanner you'd track line numbers during parsing
        try:
            resources = ast_tree.get('Resources', {})
            if resource_name in resources:
                # Return a placeholder line number - in practice this would come from the parser
                return hash(resource_name) % 100 + 1  # Simple hash-based line number
        except:
            pass
        return 0

    def _find_nodes_by_type(self, ast_tree, node_types):
        """Find all nodes of specified types in the CloudFormation AST."""
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
                node_type = node.get('node_type')
                if node_type in node_types:
                    found_nodes.append(node)
                
                # Continue traversal
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, (dict, list)):
                        stack.append(item)
                        
        return found_nodes

    def _find_resources_by_type(self, ast_tree, resource_types):
        """Find all CloudFormation resources of specified types."""
        found_resources = []
        
        # Get all Resource nodes
        resource_nodes = self._find_nodes_by_type(ast_tree, ["Resource"])
        
        for node in resource_nodes:
            resource_type = node.get('resource_type', '')
            
            # Handle CloudFormation Language Extensions where Type might be a dict
            if isinstance(resource_type, dict):
                # If it's a dict, it might be a CloudFormation function like Fn::Sub
                # For now, skip these dynamic types as we can't statically match them
                continue
                
            # Ensure resource_type is a string
            if not isinstance(resource_type, str):
                continue
                
            if any(re.match(rt, resource_type) for rt in resource_types):
                found_resources.append(node)
                
        return found_resources

    def _get_property(self, node, property_path):
        """Navigate property path to get value from CloudFormation node."""
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
        """Evaluate comparison operations for CloudFormation values."""
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
        elif operator == "is_empty":
            return not value
        elif operator == "is_not_empty":
            return bool(value)
            
        return False

    def _has_wildcard_policy(self, policy_doc):
        """Check if a policy document contains wildcards that make it overly permissive."""
        if not isinstance(policy_doc, dict):
            return False
            
        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
            
        for statement in statements:
            if not isinstance(statement, dict):
                continue
                
            # Check for wildcard principals
            principal = statement.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and "*" in str(principal)):
                return True
                
            # Check for wildcard actions
            action = statement.get("Action", [])
            if isinstance(action, str):
                action = [action]
            if "*" in action:
                return True
                
            # Check for wildcard resources
            resource = statement.get("Resource", [])
            if isinstance(resource, str):
                resource = [resource]
            if "*" in resource:
                return True
                
        return False

    def _find_intrinsic_functions(self, node):
        """Find CloudFormation intrinsic functions in a node."""
        functions = []
        
        def search_node(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.startswith("Fn::") or key == "Ref":
                        functions.append((key, value))
                    else:
                        search_node(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_node(item, f"{path}[{i}]")
                    
        search_node(node)
        return functions

    def _is_permissive_rule(self, rule):
        """Check if a security group rule is overly permissive."""
        if not isinstance(rule, dict):
            return False
            
        # Check for 0.0.0.0/0 CIDR
        cidr_ip = rule.get("CidrIp")
        if cidr_ip == "0.0.0.0/0":
            return True
            
        # Check for ::/0 IPv6 CIDR
        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 == "::/0":
            return True
            
        return False

    def _is_encryption_enabled(self, value, property_name):
        """Check if encryption is properly enabled for a property."""
        if property_name == "StorageEncrypted":
            return value is True
        elif property_name == "Encrypted":
            return value is True
        elif property_name in ["KmsMasterKeyId"]:
            return value is not None and value != ""
        elif property_name == "BucketEncryption":
            return isinstance(value, dict) and "ServerSideEncryptionConfiguration" in value
            
        return False

    def _apply_parsing_failure_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if CloudFormation template has parsing failures."""
        findings = []
        
        # Only check root CloudFormationTemplate node
        if node_type != 'CloudFormationTemplate':
            return findings
            
        try:
            # Check if this template has parsing errors indicated in the AST
            parsing_error = node.get('parsing_error')
            format_detected = node.get('format', 'unknown')
            
            if parsing_error:
                line_num = 1  # Default to line 1 for parsing errors
                finding_key = f"{filename}_parsing_error"
                
                if finding_key not in seen_findings:
                    error_type = parsing_error.get('type', 'unknown')
                    error_message = parsing_error.get('message', 'Unknown parsing error')
                    
                    # Determine error category
                    if 'yaml' in error_type.lower() or 'yaml' in error_message.lower():
                        category = "YAML syntax error"
                    elif 'json' in error_type.lower() or 'json' in error_message.lower():
                        category = "JSON syntax error"
                    else:
                        category = "Template structure error"
                    
                    finding = {
                        'rule_id': self.rule_id,
                        'message': f"CloudFormation parsing failure: {category} - {error_message}",
                        'filename': filename,
                        'line': line_num,
                        'node': 'Template',
                        'severity': self.metadata.get('defaultSeverity', 'Major'),
                        'property_path': [],
                        'value': error_message
                    }
                    findings.append(finding)
                    seen_findings.add(finding_key)
            
            elif format_detected == 'unknown':
                # Template was parsed but format couldn't be determined - potential issue
                line_num = 1
                finding_key = f"{filename}_unknown_format"
                
                if finding_key not in seen_findings:
                    finding = {
                        'rule_id': self.rule_id,
                        'message': "CloudFormation parsing failure: Unable to determine template format (YAML/JSON)",
                        'filename': filename,
                        'line': line_num,
                        'node': 'Template',
                        'severity': self.metadata.get('defaultSeverity', 'Major'),
                        'property_path': [],
                        'value': 'unknown_format'
                    }
                    findings.append(finding)
                    seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
        
    def _apply_public_api_security_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if API Gateway methods are configured with proper authentication."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should be validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Check property_checks configuration
            property_checks = check.get('property_checks', [])
            
            for prop_check in property_checks:
                property_path = prop_check.get('property_path', [])
                forbidden_values = prop_check.get('forbidden_values', [])
                required_values = prop_check.get('required_values', [])
                check_message = prop_check.get('message', 'Property validation failed')
                
                # Navigate to the property value
                current_value = properties
                for path_part in property_path[1:]:  # Skip 'properties' as it's already our starting point
                    if isinstance(current_value, dict) and path_part in current_value:
                        current_value = current_value[path_part]
                    else:
                        current_value = None
                        break
                
                # Check forbidden values
                if current_value in forbidden_values:
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_api_auth_{current_value}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. Found: {current_value}",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Major'),
                            'property_path': property_path,
                            'value': current_value
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                
                # Check if required values are missing (if AuthorizationType is not set at all)
                elif current_value is None and required_values:
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_api_auth_missing"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. AuthorizationType is missing",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Major'),
                            'property_path': property_path,
                            'value': None
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
        
    def _apply_backup_retention_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if database backup retention periods are sufficient for security incident recovery."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should be validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Check property_checks configuration
            property_checks = check.get('property_checks', [])
            
            for prop_check in property_checks:
                property_path = prop_check.get('property_path', [])
                minimum_value = prop_check.get('minimum_value', 7)
                recommended_value = prop_check.get('recommended_value', 30)
                check_message = prop_check.get('message', 'Backup retention validation failed')
                
                # Navigate to the property value
                current_value = properties
                for path_part in property_path[1:]:  # Skip 'properties' as it's already our starting point
                    if isinstance(current_value, dict) and path_part in current_value:
                        current_value = current_value[path_part]
                    else:
                        current_value = None
                        break
                
                # Check if backup retention period exists and is valid
                if current_value is None:
                    # BackupRetentionPeriod is missing - this means no backups (0 days)
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_backup_retention_missing"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. BackupRetentionPeriod is not configured (defaults to 0)",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Critical'),
                            'property_path': property_path,
                            'value': None
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                
                elif isinstance(current_value, (int, float)):
                    # Check if retention period is too short
                    if current_value < minimum_value:
                        line_num = node.get('lineno', 1)
                        finding_key = f"{node_name}_backup_retention_short_{current_value}"
                        
                        if finding_key not in seen_findings:
                            severity_level = "Critical" if current_value == 0 else "Major"
                            
                            if current_value == 0:
                                message = f"{check_message}. BackupRetentionPeriod is 0 (no backups)"
                            else:
                                message = f"{check_message}. Found: {current_value} days, minimum recommended: {minimum_value} days"
                                
                            finding = {
                                'rule_id': self.rule_id,
                                'message': message,
                                'filename': filename,
                                'line': line_num,
                                'node': f"Resource.{node_name}",
                                'severity': self.metadata.get('defaultSeverity', severity_level),
                                'property_path': property_path,
                                'value': current_value
                            }
                            findings.append(finding)
                            seen_findings.add(finding_key)
                        
                elif isinstance(current_value, str):
                    # Handle string values (might be CloudFormation parameters/functions)
                    try:
                        numeric_value = int(current_value)
                        if numeric_value < minimum_value:
                            line_num = node.get('lineno', 1)
                            finding_key = f"{node_name}_backup_retention_short_{numeric_value}"
                            
                            if finding_key not in seen_findings:
                                finding = {
                                    'rule_id': self.rule_id,
                                    'message': f"{check_message}. Found: {numeric_value} days, minimum recommended: {minimum_value} days",
                                    'filename': filename,
                                    'line': line_num,
                                    'node': f"Resource.{node_name}",
                                    'severity': self.metadata.get('defaultSeverity', 'Critical'),
                                    'property_path': property_path,
                                    'value': current_value
                                }
                                findings.append(finding)
                                seen_findings.add(finding_key)
                    except ValueError:
                        # String value that's not a number - might be CloudFormation function
                        # We can't validate these, so skip
                        pass
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings

    def _apply_logging_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if logging is properly configured for AWS resources."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should be validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Check property_checks configuration
            property_checks = check.get('property_checks', [])
            
            for prop_check in property_checks:
                property_path = prop_check.get('property_path', [])
                required_properties = prop_check.get('required_properties', [])
                check_message = prop_check.get('message', 'Logging configuration is missing or incomplete')
                
                # Navigate to the property value
                current_value = properties
                for path_part in property_path[1:]:  # Skip 'properties' as it's already our starting point
                    if isinstance(current_value, dict) and path_part in current_value:
                        current_value = current_value[path_part]
                    else:
                        current_value = None
                        break
                
                # Check if logging configuration exists
                if current_value is None:
                    # Logging configuration is missing
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_logging_missing_{property_path[-1]}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. {property_path[-1]} is not configured",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Critical'),
                            'property_path': property_path,
                            'value': None
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                
                elif isinstance(current_value, dict) and required_properties:
                    # Check if required sub-properties are present in logging configuration
                    for required_prop in required_properties:
                        if required_prop not in current_value:
                            line_num = node.get('lineno', 1)
                            finding_key = f"{node_name}_logging_incomplete_{required_prop}"
                            
                            if finding_key not in seen_findings:
                                finding = {
                                    'rule_id': self.rule_id,
                                    'message': f"{check_message}. Missing required property: {required_prop}",
                                    'filename': filename,
                                    'line': line_num,
                                    'node': f"Resource.{node_name}",
                                    'severity': self.metadata.get('defaultSeverity', 'Critical'),
                                    'property_path': property_path + [required_prop],
                                    'value': current_value
                                }
                                findings.append(finding)
                                seen_findings.add(finding_key)
                
                elif isinstance(current_value, list) and not current_value:
                    # Empty list for properties like EnableCloudwatchLogsExports
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_logging_empty_{property_path[-1]}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. {property_path[-1]} is configured but empty",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Critical'),
                            'property_path': property_path,
                            'value': current_value
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings

    def _apply_versioning_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if S3 bucket versioning is properly configured."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should be validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get the resource properties
            properties = node.get('properties', {})
            
            # Check property_checks configuration
            property_checks = check.get('property_checks', [])
            
            for prop_check in property_checks:
                property_path = prop_check.get('property_path', [])
                required_properties = prop_check.get('required_properties', [])
                required_value = prop_check.get('required_value')
                check_message = prop_check.get('message', 'Versioning configuration is missing or incorrect')
                
                # Navigate to the property value
                current_value = properties
                for path_part in property_path[1:]:  # Skip 'properties' as it's already our starting point
                    if isinstance(current_value, dict) and path_part in current_value:
                        current_value = current_value[path_part]
                    else:
                        current_value = None
                        break
                
                # Check if versioning configuration exists
                if current_value is None:
                    # VersioningConfiguration is missing
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_versioning_missing_{property_path[-1]}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. VersioningConfiguration is not configured",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': property_path,
                            'value': None
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                
                elif isinstance(current_value, dict) and required_properties:
                    # Check if required sub-properties are present in versioning configuration
                    for required_prop in required_properties:
                        if required_prop not in current_value:
                            line_num = node.get('lineno', 1)
                            finding_key = f"{node_name}_versioning_incomplete_{required_prop}"
                            
                            if finding_key not in seen_findings:
                                finding = {
                                    'rule_id': self.rule_id,
                                    'message': f"{check_message}. Missing required property: {required_prop}",
                                    'filename': filename,
                                    'line': line_num,
                                    'node': f"Resource.{node_name}",
                                    'severity': self.metadata.get('defaultSeverity', 'Info'),
                                    'property_path': property_path + [required_prop],
                                    'value': current_value
                                }
                                findings.append(finding)
                                seen_findings.add(finding_key)
                        elif required_value and current_value.get(required_prop) != required_value:
                            # Check specific value requirements (e.g., Status should be "Enabled")
                            actual_value = current_value.get(required_prop)
                            line_num = node.get('lineno', 1)
                            finding_key = f"{node_name}_versioning_wrong_value_{required_prop}_{actual_value}"
                            
                            if finding_key not in seen_findings:
                                if actual_value == "Suspended":
                                    message = f"S3 bucket versioning is suspended (should be Enabled for data protection)"
                                elif actual_value is None:
                                    message = f"S3 bucket versioning Status is not configured (should be Enabled)"
                                else:
                                    message = f"S3 bucket versioning Status is '{actual_value}' (should be 'Enabled')"
                                
                                finding = {
                                    'rule_id': self.rule_id,
                                    'message': message,
                                    'filename': filename,
                                    'line': line_num,
                                    'node': f"Resource.{node_name}",
                                    'severity': self.metadata.get('defaultSeverity', 'Info'),
                                    'property_path': property_path + [required_prop],
                                    'value': actual_value
                                }
                                findings.append(finding)
                                seen_findings.add(finding_key)
                
                elif isinstance(current_value, dict) and not current_value:
                    # Empty VersioningConfiguration object
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_versioning_empty_{property_path[-1]}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. VersioningConfiguration is configured but empty",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': property_path,
                            'value': current_value
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings

    def _apply_log_group_declaration_check(self, check, node, filename, node_type, node_name, seen_findings):
        """Check if resources that implicitly create log groups have explicit Log Group declarations."""
        findings = []
        
        # Get the actual CloudFormation resource type
        resource_type = node.get('resource_type')
        
        # Check if this resource type should be validated
        if resource_type not in check.get('resource_types', []):
            return findings
            
        try:
            # Get all resources from the AST to check for corresponding log groups
            # We need access to the full AST, not just the current node
            # This requires the AST to be passed to this method or stored in the rule instance
            if not hasattr(self, '_ast_tree') or not self._ast_tree:
                return findings
                
            # Get service mappings for this resource type
            service_mappings = check.get('service_mappings', [])
            applicable_mappings = [sm for sm in service_mappings if sm.get('resource_type') == resource_type]
            
            for mapping in applicable_mappings:
                log_group_pattern = mapping.get('log_group_naming_pattern', '')
                function_name_property = mapping.get('function_name_property', [])
                check_message = mapping.get('message', 'Resource should have an explicitly declared Log Group')
                
                # Get the function name from the resource
                function_name = self._get_property(node, function_name_property)
                
                if function_name is None:
                    # If no explicit function name, skip (will be implicit)
                    continue
                    
                # Generate expected log group name
                expected_log_group_name = log_group_pattern.replace('{FunctionName}', str(function_name))
                
                # Check if corresponding log group exists in the template
                log_group_exists = self._check_log_group_exists(expected_log_group_name)
                
                if not log_group_exists:
                    line_num = node.get('lineno', 1)
                    finding_key = f"{node_name}_missing_log_group_{function_name}"
                    
                    if finding_key not in seen_findings:
                        finding = {
                            'rule_id': self.rule_id,
                            'message': f"{check_message}. Expected Log Group: {expected_log_group_name}",
                            'filename': filename,
                            'line': line_num,
                            'node': f"Resource.{node_name}",
                            'severity': self.metadata.get('defaultSeverity', 'Info'),
                            'property_path': function_name_property,
                            'value': function_name
                        }
                        findings.append(finding)
                        seen_findings.add(finding_key)
                        
        except Exception as e:
            # Log parsing error but don't fail
            pass
            
        return findings
    
    def _check_log_group_exists(self, expected_log_group_name):
        """Check if a Log Group with the expected name exists in the template."""
        if not hasattr(self, '_ast_tree') or not self._ast_tree:
            return False
            
        try:
            # The AST tree is structured as a dict with 'template' containing the actual CloudFormation template
            template_data = self._ast_tree.get('template', {})
            
            # Look through all resources to find AWS::Logs::LogGroup resources  
            resources = template_data.get('Resources', {})
            
            for resource_name, resource_data in resources.items():
                resource_type = resource_data.get('Type')
                
                if resource_type == 'AWS::Logs::LogGroup':
                    # Check the LogGroupName property
                    properties = resource_data.get('Properties', {})
                    log_group_name = properties.get('LogGroupName')
                    
                    # Handle different value types (string, CloudFormation functions, etc.)
                    if isinstance(log_group_name, str) and log_group_name == expected_log_group_name:
                        return True
                    elif isinstance(log_group_name, dict):
                        # Handle CloudFormation intrinsic functions
                        # For now, assume they might match (to avoid false positives)
                        # But only if the expected name also contains a function
                        if isinstance(expected_log_group_name, str) and '{' not in expected_log_group_name:
                            # Expected name is simple string but log group name is function - no match
                            continue
                        # Both are complex, assume they might match to avoid false positive
                        return True
            
            # No matching log group found
            return False
            
        except Exception as e:
            # If we can't determine, assume it exists to avoid false positives
            return True

    def _make_finding(self, filename, node_type, node_name, property_path, value, message=None, node=None):
        """Create a finding object for a rule violation."""
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
    Main entry point for running a CloudFormation rule against an AST.
    """
    try:
        rule = CloudFormationGenericRule(rule_metadata)
        if not rule.is_applicable(ast_tree):
            return []
        findings = rule.check(ast_tree, filename)
        return findings
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []


# For backward compatibility and consistency
GenericRule = CloudFormationGenericRule
CloudFormationRule = CloudFormationGenericRule