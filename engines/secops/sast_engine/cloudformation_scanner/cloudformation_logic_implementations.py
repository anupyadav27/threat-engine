"""
Custom logic implementations for CloudFormation rules.
"""

def check_resource_wildcards_only(ast_tree, filename, rule_metadata):
    """
    Check for Resource: "*" wildcards specifically, ignoring Action/Principal wildcards.
    This addresses the false positive issue where Action wildcards were incorrectly flagged.
    """
    findings = []
    
    def check_policy_document(policy_doc, node_name, property_path, line_base=0):
        """Check a policy document for Resource wildcards only."""
        if not isinstance(policy_doc, dict):
            return []
        
        local_findings = []
        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for i, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue
            
            # Only check Resource field, ignore Action/Principal
            resource = statement.get("Resource")
            if resource:
                # Check if resource is "*" (string) or contains "*" (array)
                resource_has_wildcard = False
                
                if isinstance(resource, str) and resource == "*":
                    resource_has_wildcard = True
                elif isinstance(resource, list) and "*" in resource:
                    resource_has_wildcard = True
                    
                if resource_has_wildcard:
                    finding = {
                        "rule_id": rule_metadata.get("rule_id", "policies_granting_access_all"),
                        "message": "Policy grants access to all resources using wildcard (*) - violates least privilege principle",
                        "node": f"Resource.{node_name}",
                        "file": filename,
                        "property_path": ["properties", "PolicyDocument", "Statement", str(i), "Resource"],
                        "value": resource,
                        "status": "violation",
                        "severity": rule_metadata.get("defaultSeverity", "Critical"),
                        "line": line_base + i + 1  # Estimate line number
                    }
                    local_findings.append(finding)
        
        return local_findings
    
    # Navigate through the AST to find resources with policy documents
    template = ast_tree.get("template", {})
    if not template:
        return findings
    
    resources = template.get("Resources", {})
    if isinstance(resources, dict):
        for resource_name, resource_data in resources.items():
            if not isinstance(resource_data, dict):
                continue
            
            # Use 'Properties' not 'properties' - CloudFormation is case-sensitive
            properties = resource_data.get("Properties", {})
            if not isinstance(properties, dict):
                continue
            
            # Estimate base line number for this resource
            line_base = hash(resource_name) % 100 + 1
            
            # Check PolicyDocument
            policy_doc = properties.get("PolicyDocument")
            if policy_doc:
                findings.extend(check_policy_document(
                    policy_doc, 
                    resource_name, 
                    ["properties", "PolicyDocument"],
                    line_base
                ))
            
            # Check AssumeRolePolicyDocument  
            assume_policy_doc = properties.get("AssumeRolePolicyDocument")
            if assume_policy_doc:
                findings.extend(check_policy_document(
                    assume_policy_doc, 
                    resource_name, 
                    ["properties", "AssumeRolePolicyDocument"],
                    line_base + 10
                ))
            
            # Check inline policies in IAM Roles (Policies property)
            inline_policies = properties.get("Policies")
            if isinstance(inline_policies, list):
                for j, inline_policy in enumerate(inline_policies):
                    if isinstance(inline_policy, dict):
                        inline_policy_doc = inline_policy.get("PolicyDocument")
                        if inline_policy_doc:
                            findings.extend(check_policy_document(
                                inline_policy_doc, 
                                resource_name,
                                ["properties", "Policies", str(j), "PolicyDocument"],
                                line_base + 20 + j * 5
                            ))
    
    return findings


"""
Custom logic implementations for CloudFormation rules.
Functions that implement specific rule logic for CloudFormation vulnerability scanning.
"""

import re


def check_todo_tags_in_content(ast_tree, filename, rule_metadata):
    """
    Check for TODO tags and comments in CloudFormation template content.
    Detects unfinished work markers like TODO, FIXME, HACK, etc.
    """
    findings = []
    
    # Get the raw content from the AST
    raw_content = ast_tree.get("source", "")
    if not raw_content:
        return findings
    
    lines = raw_content.split('\n')
    
    # TODO patterns to detect (case insensitive)
    todo_patterns = [
        r'#\s*TODO\b',          # #TODO, # TODO
        r'#\s*FIXME\b',         # #FIXME, # FIXME  
        r'#\s*HACK\b',          # #HACK, # HACK
        r'#\s*XXX\b',           # #XXX, # XXX
        r'#\s*NOTE\b.*(?:TODO|FIXME|FIX|INCOMPLETE)',  # #NOTE: TODO, etc.
        r'TODO\s*:',            # TODO: in descriptions
        r'FIXME\s*:',           # FIXME: in descriptions
        r'(?:^|\s)TODO\s+',     # TODO followed by space (in descriptions)
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_content = line.strip()
        if not line_content:
            continue
            
        for pattern in todo_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Extract the relevant part of the line for context
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Get some context around the match
                    start = max(0, match.start() - 10)
                    end = min(len(line), match.end() + 20)
                    context = line[start:end].strip()
                    
                    finding = {
                        "rule_id": rule_metadata.get("rule_id", "track_uses_todo_tags"),
                        "message": f"Found TODO tag indicating unfinished work: '{context}'",
                        "node": f"Template",
                        "file": filename,
                        "property_path": ["content", f"line_{line_num}"],
                        "value": line.strip(),
                        "status": "violation",
                        "severity": rule_metadata.get("defaultSeverity", "Critical"),
                        "line": line_num
                    }
                    findings.append(finding)
                    break  # Only report one TODO per line
                    
    return findings


def check_clear_text_protocols(ast_tree, filename, rule_metadata):
    """
    Check for clear-text protocols that lack encryption and expose applications to security risks.
    Detects HTTP load balancers, publicly accessible databases, and other insecure protocol configurations.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        properties = resource_config.get("Properties", {})
        
        # Check AWS::ElasticLoadBalancingV2::LoadBalancer for HTTP protocol
        if resource_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            findings.extend(
                _check_load_balancer_protocols(resource_name, properties, filename, rule_metadata)
            )
        
        # Check AWS::ElasticLoadBalancing::LoadBalancer (Classic Load Balancer)
        elif resource_type == "AWS::ElasticLoadBalancing::LoadBalancer":
            findings.extend(
                _check_classic_load_balancer_protocols(resource_name, properties, filename, rule_metadata)
            )
        
        # Check AWS::RDS::DBInstance for publicly accessible databases
        elif resource_type == "AWS::RDS::DBInstance":
            findings.extend(
                _check_rds_public_access(resource_name, properties, filename, rule_metadata)
            )
        
        # Check AWS::RDS::DBCluster for publicly accessible clusters
        elif resource_type == "AWS::RDS::DBCluster":
            findings.extend(
                _check_rds_cluster_public_access(resource_name, properties, filename, rule_metadata)
            )
        
        # Check AWS::ElastiCache::CacheCluster for transit encryption
        elif resource_type == "AWS::ElastiCache::CacheCluster":
            findings.extend(
                _check_elasticache_encryption(resource_name, properties, filename, rule_metadata)
            )
        
        # Check AWS::ElastiCache::ReplicationGroup for transit encryption
        elif resource_type == "AWS::ElastiCache::ReplicationGroup":
            findings.extend(
                _check_elasticache_replication_encryption(resource_name, properties, filename, rule_metadata)
            )
    
    return findings


def _check_load_balancer_protocols(resource_name, properties, filename, rule_metadata):
    """Check Application/Network Load Balancer listeners for HTTP protocol."""
    findings = []
    
    # Check for HTTP listeners (should use HTTPS instead)
    listeners = properties.get("Listeners", [])
    
    for i, listener in enumerate(listeners):
        if isinstance(listener, dict):
            protocol = listener.get("Protocol", "")
            port = listener.get("Port")
            
            if protocol.upper() == "HTTP":
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
                    "message": f"Load balancer uses insecure HTTP protocol on port {port} - should use HTTPS for encrypted communication",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Listeners", str(i), "Protocol"],
                    "value": protocol,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Critical"),
                    "line": _estimate_line_number(resource_name, i)
                }
                findings.append(finding)
    
    return findings


def _check_classic_load_balancer_protocols(resource_name, properties, filename, rule_metadata):
    """Check Classic Load Balancer listeners for HTTP protocol."""
    findings = []
    
    listeners = properties.get("Listeners", [])
    
    for i, listener in enumerate(listeners):
        if isinstance(listener, dict):
            protocol = listener.get("Protocol", "")
            load_balancer_port = listener.get("LoadBalancerPort")
            
            if protocol.upper() == "HTTP":
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
                    "message": f"Classic load balancer uses insecure HTTP protocol on port {load_balancer_port} - should use HTTPS",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Listeners", str(i), "Protocol"],
                    "value": protocol,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Critical"),
                    "line": _estimate_line_number(resource_name, i)
                }
                findings.append(finding)
    
    return findings


def _check_rds_public_access(resource_name, properties, filename, rule_metadata):
    """Check RDS database instance for public accessibility."""
    findings = []
    
    publicly_accessible = properties.get("PubliclyAccessible")
    
    if publicly_accessible is True:
        finding = {
            "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
            "message": "RDS database instance is publicly accessible - exposes database to potential clear-text connections and security risks",
            "node": f"Resource.{resource_name}",
            "file": filename,
            "property_path": ["properties", "PubliclyAccessible"],
            "value": publicly_accessible,
            "status": "violation",
            "severity": rule_metadata.get("defaultSeverity", "Critical"),
            "line": _estimate_line_number(resource_name)
        }
        findings.append(finding)
    
    return findings


def _check_rds_cluster_public_access(resource_name, properties, filename, rule_metadata):
    """Check RDS cluster for public accessibility."""
    findings = []
    
    publicly_accessible = properties.get("PubliclyAccessible")
    
    if publicly_accessible is True:
        finding = {
            "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
            "message": "RDS cluster is publicly accessible - exposes cluster to potential clear-text connections and security risks",
            "node": f"Resource.{resource_name}",
            "file": filename,
            "property_path": ["properties", "PubliclyAccessible"],
            "value": publicly_accessible,
            "status": "violation",
            "severity": rule_metadata.get("defaultSeverity", "Critical"),
            "line": _estimate_line_number(resource_name)
        }
        findings.append(finding)
    
    return findings


def _check_elasticache_encryption(resource_name, properties, filename, rule_metadata):
    """Check ElastiCache cluster for transit encryption."""
    findings = []
    
    transit_encryption_enabled = properties.get("TransitEncryptionEnabled")
    
    # TransitEncryptionEnabled should be True for Redis clusters
    engine = properties.get("Engine", "")
    if engine.lower() == "redis" and transit_encryption_enabled is not True:
        finding = {
            "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
            "message": "ElastiCache Redis cluster does not have transit encryption enabled - data transmitted in clear text",
            "node": f"Resource.{resource_name}",
            "file": filename,
            "property_path": ["properties", "TransitEncryptionEnabled"],
            "value": transit_encryption_enabled,
            "status": "violation",
            "severity": rule_metadata.get("defaultSeverity", "Critical"),
            "line": _estimate_line_number(resource_name)
        }
        findings.append(finding)
    
    return findings


def _check_elasticache_replication_encryption(resource_name, properties, filename, rule_metadata):
    """Check ElastiCache replication group for transit encryption."""
    findings = []
    
    transit_encryption_enabled = properties.get("TransitEncryptionEnabled")
    
    if transit_encryption_enabled is not True:
        finding = {
            "rule_id": rule_metadata.get("rule_id", "using_cleartext_protocols_is"),
            "message": "ElastiCache replication group does not have transit encryption enabled - data transmitted in clear text",
            "node": f"Resource.{resource_name}",
            "file": filename,
            "property_path": ["properties", "TransitEncryptionEnabled"],
            "value": transit_encryption_enabled,
            "status": "violation",
            "severity": rule_metadata.get("defaultSeverity", "Critical"),
            "line": _estimate_line_number(resource_name)
        }
        findings.append(finding)
    
    return findings


def _estimate_line_number(resource_name, index=0):
    """Estimate line number for a resource and optional array index."""
    # Simple estimation based on resource name hash and index
    base_line = abs(hash(resource_name)) % 100 + 1
    return base_line + index


def check_unencrypted_ebs_volumes(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted EBS volumes that lack encryption, exposing data-at-rest to security risks.
    Detects AWS::EC2::Volume resources with Encrypted: false or missing Encrypted property.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::EC2::Volume resources
        if resource_type == "AWS::EC2::Volume":
            properties = resource_config.get("Properties", {})
            encrypted = properties.get("Encrypted")
            
            # Check for unencrypted volumes
            if encrypted is False:
                # Explicit Encrypted: false
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_ebs_volumes"),
                    "message": "EBS volume encryption is explicitly disabled - data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Encrypted"],
                    "value": encrypted,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
                
            elif encrypted is None:
                # Missing Encrypted property (defaults to false)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_ebs_volumes"),
                    "message": "EBS volume encryption is not configured - defaults to unencrypted, data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Encrypted"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_action_wildcards_only(ast_tree, filename, rule_metadata):
    """
    Check for Action: "*" wildcards specifically, ignoring Resource/Principal wildcards.
    This detects policies that grant all privileges, violating least privilege principle.
    """
    findings = []
    
    def check_policy_document(policy_doc, node_name, property_path, line_base=0):
        """Check a policy document for Action wildcards only."""
        if not isinstance(policy_doc, dict):
            return []
        
        local_findings = []
        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for i, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue
            
            # Only check Action field, ignore Resource/Principal
            action = statement.get("Action")
            if action:
                # Check if action is "*" (string) or contains "*" (array)
                action_has_wildcard = False
                
                if isinstance(action, str) and action == "*":
                    action_has_wildcard = True
                elif isinstance(action, list) and "*" in action:
                    action_has_wildcard = True
                    
                if action_has_wildcard:
                    finding = {
                        "rule_id": rule_metadata.get("rule_id", "policies_granting_all_privileges"),
                        "message": "Policy grants all privileges using wildcard (*) - violates least privilege principle",
                        "node": f"Resource.{node_name}",
                        "file": filename,
                        "property_path": ["properties", "PolicyDocument", "Statement", str(i), "Action"],
                        "value": action,
                        "status": "violation",
                        "severity": rule_metadata.get("defaultSeverity", "Critical"),
                        "line": line_base + i + 1  # Estimate line number
                    }
                    local_findings.append(finding)
        
        return local_findings
    
    # Navigate through the AST to find resources with policy documents
    template = ast_tree.get("template", {})
    if not template:
        return findings
    
    resources = template.get("Resources", {})
    if isinstance(resources, dict):
        for resource_name, resource_data in resources.items():
            if not isinstance(resource_data, dict):
                continue
            
            # Use 'Properties' not 'properties' - CloudFormation is case-sensitive
            properties = resource_data.get("Properties", {})
            if not isinstance(properties, dict):
                continue
            
            # Estimate base line number for this resource
            line_base = hash(resource_name) % 100 + 1
            
            # Check PolicyDocument
            policy_doc = properties.get("PolicyDocument")
            if policy_doc:
                findings.extend(check_policy_document(
                    policy_doc, 
                    resource_name, 
                    ["properties", "PolicyDocument"],
                    line_base
                ))
            
            # Check AssumeRolePolicyDocument  
            assume_policy_doc = properties.get("AssumeRolePolicyDocument")
            if assume_policy_doc:
                findings.extend(check_policy_document(
                    assume_policy_doc, 
                    resource_name, 
                    ["properties", "AssumeRolePolicyDocument"],
                    line_base + 10
                ))
            
            # Check inline policies in IAM Roles (Policies property)
            inline_policies = properties.get("Policies")
            if isinstance(inline_policies, list):
                for j, inline_policy in enumerate(inline_policies):
                    if isinstance(inline_policy, dict):
                        inline_policy_doc = inline_policy.get("PolicyDocument")
                        if inline_policy_doc:
                            findings.extend(check_policy_document(
                                inline_policy_doc, 
                                resource_name,
                                ["properties", "Policies", str(j), "PolicyDocument"],
                                line_base + 20 + j * 5
                            ))
    
    return findings


def check_unencrypted_efs_file_systems(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted EFS file systems that lack encryption, exposing data-at-rest to security risks.
    Detects AWS::EFS::FileSystem resources with Encrypted: false or missing Encrypted property.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::EFS::FileSystem resources
        if resource_type == "AWS::EFS::FileSystem":
            properties = resource_config.get("Properties", {})
            encrypted = properties.get("Encrypted")
            
            # Check for unencrypted file systems
            if encrypted is False:
                # Explicit Encrypted: false
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_efs_file"),
                    "message": "EFS file system encryption is explicitly disabled - data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Encrypted"],
                    "value": encrypted,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
                
            elif encrypted is None:
                # Missing Encrypted property (defaults to false)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_efs_file"),
                    "message": "EFS file system encryption is not configured - defaults to unencrypted, data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "Encrypted"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings

def check_unencrypted_opensearch_domains(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted OpenSearch domains that lack encryption, exposing data-at-rest to security risks.
    Detects AWS::OpenSearchService::Domain resources with EncryptionAtRestOptions.Enabled: false or missing EncryptionAtRestOptions.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::OpenSearchService::Domain resources
        if resource_type == "AWS::OpenSearchService::Domain":
            properties = resource_config.get("Properties", {})
            encryption_options = properties.get("EncryptionAtRestOptions", {})
            
            # Check if encryption options exist and are properly configured
            if isinstance(encryption_options, dict) and encryption_options:
                encryption_enabled = encryption_options.get("Enabled")
                
                if encryption_enabled is False:
                    # Explicit EncryptionAtRestOptions.Enabled: false
                    finding = {
                        "rule_id": rule_metadata.get("rule_id", "using_unencrypted_opensearch_domains"),
                        "message": "OpenSearch domain encryption is explicitly disabled - data-at-rest is not protected",
                        "node": f"Resource.{resource_name}",
                        "file": filename,
                        "property_path": ["properties", "EncryptionAtRestOptions", "Enabled"],
                        "value": encryption_enabled,
                        "status": "violation",
                        "severity": rule_metadata.get("defaultSeverity", "Info"),
                        "line": _estimate_line_number(resource_name)
                    }
                    findings.append(finding)
                    
            else:
                # Missing EncryptionAtRestOptions (defaults to false)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_opensearch_domains"),
                    "message": "OpenSearch domain encryption is not configured - defaults to unencrypted, data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "EncryptionAtRestOptions"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_unencrypted_rds_db_resources(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted RDS DB resources that lack encryption, exposing data-at-rest to security risks.
    Detects AWS::RDS::DBInstance and AWS::RDS::DBCluster resources with StorageEncrypted: false or missing StorageEncrypted property.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Check both RDS DBInstance and DBCluster resources
        if resource_type in ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster"]:
            properties = resource_config.get("Properties", {})
            storage_encrypted = properties.get("StorageEncrypted")
            
            # Check for unencrypted databases
            if storage_encrypted is False:
                # Explicit StorageEncrypted: false
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_rds_db"),
                    "message": "RDS database encryption is explicitly disabled - data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "StorageEncrypted"],
                    "value": storage_encrypted,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
                
            elif storage_encrypted is None:
                # Missing StorageEncrypted property (defaults to false)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_rds_db"),
                    "message": "RDS database encryption is not configured - defaults to unencrypted, data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "StorageEncrypted"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_unencrypted_sagemaker_notebook_instances(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted SageMaker notebook instances that lack encryption, exposing data-at-rest to security risks.
    Detects AWS::SageMaker::NotebookInstance resources with missing KmsKeyId property.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::SageMaker::NotebookInstance resources
        if resource_type == "AWS::SageMaker::NotebookInstance":
            properties = resource_config.get("Properties", {})
            kms_key_id = properties.get("KmsKeyId")
            
            # Check for missing KmsKeyId (unencrypted)
            if kms_key_id is None:
                # Missing KmsKeyId property (encryption disabled by default)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_sagemaker_notebook"),
                    "message": "SageMaker notebook instance encryption is not configured - data-at-rest is not protected",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "KmsKeyId"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_unencrypted_sns_topics(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted SNS topics that lack proper KMS encryption or use insecure default keys.
    Detects AWS::SNS::Topic resources with missing KmsMasterKeyId or using default aws/sns key.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::SNS::Topic resources
        if resource_type == "AWS::SNS::Topic":
            properties = resource_config.get("Properties", {})
            kms_master_key_id = properties.get("KmsMasterKeyId")
            
            # Check for encryption issues
            if kms_master_key_id is None:
                # Missing KmsMasterKeyId property (unencrypted by default)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_sns_topics"),
                    "message": "SNS topic encryption is not configured - messages are stored unencrypted",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "KmsMasterKeyId"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
            elif kms_master_key_id == "alias/aws/sns":
                # Using default AWS managed key (security sensitive according to rule)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_sns_topics"),
                    "message": "SNS topic uses default AWS managed key (alias/aws/sns) - consider using customer-managed key for better security control",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "KmsMasterKeyId"],
                    "value": kms_master_key_id,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_unencrypted_sqs_queues(ast_tree, filename, rule_metadata):
    """
    Check for unencrypted SQS queues that lack proper SSE configuration.
    Detects AWS::SQS::Queue resources with missing or disabled SqsManagedSseEnabled property.
    """
    findings = []
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Only check AWS::SQS::Queue resources
        if resource_type == "AWS::SQS::Queue":
            properties = resource_config.get("Properties", {})
            sqs_managed_sse_enabled = properties.get("SqsManagedSseEnabled")
            
            # Check for encryption issues
            if sqs_managed_sse_enabled is None:
                # Missing SqsManagedSseEnabled property (defaults to disabled/unencrypted)
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_sqs_queues"),
                    "message": "SQS queue encryption is not configured - messages are stored unencrypted by default",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "SqsManagedSseEnabled"],
                    "value": None,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
            elif sqs_managed_sse_enabled is False:
                # Explicit SqsManagedSseEnabled: false
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "using_unencrypted_sqs_queues"),
                    "message": "SQS queue encryption is explicitly disabled - messages are stored unencrypted",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "SqsManagedSseEnabled"],
                    "value": sqs_managed_sse_enabled,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings


def check_weak_ssltls_protocols(ast_tree, filename, rule_metadata):
    """
    Check for weak SSL/TLS protocol configurations in load balancers and CloudFront distributions.
    Detects AWS::ElasticLoadBalancingV2::Listener with weak SslPolicy and 
    AWS::CloudFront::Distribution with insecure ViewerProtocolPolicy.
    """
    findings = []
    
    # Define weak SSL/TLS policies that should be flagged
    weak_ssl_policies = [
        'ELBSecurityPolicy-2015-05',  # Supports SSLv3, TLSv1.0, TLSv1.1
        'ELBSecurityPolicy-2016-08',  # Supports TLSv1.0, TLSv1.1
        'ELBSecurityPolicy-TLS-1-0-2015-04',  # Supports TLSv1.0
        'ELBSecurityPolicy-TLS-1-1-2017-01',  # Supports TLSv1.1
        'ELBSecurityPolicy-FS-2018-06',  # Supports TLSv1.0, TLSv1.1
    ]
    
    # Define insecure ViewerProtocolPolicy values
    insecure_viewer_policies = [
        'allow-all',  # Allows HTTP
        'redirect-to-https'  # Initially accepts HTTP before redirect
    ]
    
    # Get all resources from the AST
    resources = ast_tree.get("template", {}).get("Resources", {})
    
    for resource_name, resource_config in resources.items():
        resource_type = resource_config.get("Type", "")
        
        # Check AWS::ElasticLoadBalancingV2::Listener for weak SSL policies
        if resource_type == "AWS::ElasticLoadBalancingV2::Listener":
            properties = resource_config.get("Properties", {})
            ssl_policy = properties.get("SslPolicy")
            protocol = properties.get("Protocol")
            
            # Only check HTTPS listeners
            if protocol == "HTTPS" and ssl_policy in weak_ssl_policies:
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "weak_ssltls_protocols_avoided"),
                    "message": f"Load balancer listener uses weak SSL/TLS policy '{ssl_policy}' - supports deprecated protocols vulnerable to attacks",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "SslPolicy"],
                    "value": ssl_policy,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
        
        # Check AWS::CloudFront::Distribution for insecure viewer protocol policies
        elif resource_type == "AWS::CloudFront::Distribution":
            properties = resource_config.get("Properties", {})
            distribution_config = properties.get("DistributionConfig", {})
            default_cache_behavior = distribution_config.get("DefaultCacheBehavior", {})
            viewer_protocol_policy = default_cache_behavior.get("ViewerProtocolPolicy")
            
            if viewer_protocol_policy in insecure_viewer_policies:
                finding = {
                    "rule_id": rule_metadata.get("rule_id", "weak_ssltls_protocols_avoided"),
                    "message": f"CloudFront distribution uses insecure ViewerProtocolPolicy '{viewer_protocol_policy}' - allows unencrypted HTTP connections",
                    "node": f"Resource.{resource_name}",
                    "file": filename,
                    "property_path": ["properties", "DistributionConfig", "DefaultCacheBehavior", "ViewerProtocolPolicy"],
                    "value": viewer_protocol_policy,
                    "status": "violation",
                    "severity": rule_metadata.get("defaultSeverity", "Info"),
                    "line": _estimate_line_number(resource_name)
                }
                findings.append(finding)
    
    return findings
