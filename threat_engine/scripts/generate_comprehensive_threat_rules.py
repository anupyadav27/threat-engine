"""
Comprehensive Threat Rule Generator

Generates threat rules covering:
- All AWS services from service_list.json
- MITRE ATT&CK for Cloud techniques
- All relationship types
- All threat categories

Usage:
    python generate_comprehensive_threat_rules.py --output threat_rules.yaml
"""

import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict
import re


class ComprehensiveThreatRuleGenerator:
    """Generates comprehensive threat rules covering all services and MITRE ATT&CK"""
    
    def __init__(self, service_list_path: str, relation_types_path: Optional[str] = None):
        self.service_list_path = Path(service_list_path)
        self.relation_types_path = Path(relation_types_path) if relation_types_path else None
        
        # Load services
        self.services = self._load_services()
        
        # Load relation types
        self.relation_types = self._load_relation_types()
        
        # MITRE ATT&CK for Cloud techniques mapping
        self.mitre_techniques = self._load_mitre_techniques()
        
        # Threat type to MITRE technique mapping
        self.threat_mitre_mapping = {
            "exposure": ["T1078.004", "T1190", "T1566", "T1071.001"],
            "identity": ["T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004", "T1134", "T1134.001", "T1134.002"],
            "lateral_movement": ["T1021", "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1071", "T1071.001", "T1071.002"],
            "data_exfiltration": ["T1020", "T1020.001", "T1020.002", "T1041", "T1048", "T1048.001", "T1048.002", "T1048.003"],
            "privilege_escalation": ["T1078", "T1134", "T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005"],
            "data_breach": ["T1048", "T1048.001", "T1048.002", "T1048.003", "T1485", "T1486"]
        }
        
        # Service categories for targeted rule generation
        self.service_categories = {
            "compute": ["ec2", "lambda", "ecs", "eks", "fargate", "batch", "lightsail", "elastic_beanstalk"],
            "storage": ["s3", "ebs", "efs", "glacier", "storagegateway", "fsx"],
            "database": ["rds", "dynamodb", "redshift", "docdb", "neptune", "opensearch", "elasticache", "memorydb", "keyspaces", "qldb", "timestream"],
            "network": ["vpc", "elbv2", "nlb", "cloudfront", "route53", "route53resolver", "directconnect", "transit_gateway", "vpn", "network_firewall"],
            "identity": ["iam", "cognito", "identitycenter", "organizations"],
            "secrets": ["secretsmanager", "ssm", "kms"],
            "messaging": ["sns", "sqs", "eventbridge", "kinesis"],
            "monitoring": ["cloudwatch", "cloudtrail", "config", "xray", "inspector", "inspector2", "guardduty", "securityhub", "macie"],
            "compute_orchestration": ["autoscaling", "stepfunctions", "apprunner", "appstream"],
            "api": ["api_gateway", "appsync"],
            "container": ["ecr", "ecs", "eks", "fargate"],
            "ml_ai": ["sagemaker", "bedrock", "comprehend", "rekognition"],
            "analytics": ["athena", "emr", "glue", "kinesis", "quicksight"],
            "developer_tools": ["codebuild", "codecommit", "codepipeline", "codeartifact"],
            "backup": ["backup", "dlm"],
            "security": ["wafv2", "shield", "securityhub", "guardduty", "macie", "inspector", "inspector2", "accessanalyzer"]
        }
        
        # Misconfig patterns by service category
        self.misconfig_patterns = self._load_misconfig_patterns()
    
    def _load_services(self) -> List[Dict[str, Any]]:
        """Load services from service_list.json"""
        with open(self.service_list_path, 'r') as f:
            data = json.load(f)
            services = data.get("services", [])
            
            # Also get from arn_generation if available
            if "arn_generation" in data:
                global_services = data["arn_generation"].get("global_services", [])
                regional_services = data["arn_generation"].get("regional_services", [])
                all_service_names = set(global_services + regional_services)
                
                # Add services that might not be in services array
                existing_names = {s.get("name") for s in services}
                for name in all_service_names:
                    if name not in existing_names:
                        services.append({
                            "name": name,
                            "enabled": True,
                            "scope": "global" if name in global_services else "regional",
                            "resource_types": []
                        })
            
            return services
    
    def _load_relation_types(self) -> List[Dict[str, Any]]:
        """Load relation types"""
        if not self.relation_types_path or not self.relation_types_path.exists():
            # Default relation types
            return [
                {"id": "uses", "category": "identity"},
                {"id": "assumes", "category": "identity"},
                {"id": "connected_to", "category": "network"},
                {"id": "internet_connected", "category": "exposure"},
                {"id": "encrypted_by", "category": "data"},
                {"id": "grants_access_to", "category": "identity"},
                {"id": "routes_to", "category": "network"},
                {"id": "attached_to", "category": "security"},
                {"id": "stores_data_in", "category": "data"},
                {"id": "triggers", "category": "compute"},
                {"id": "invokes", "category": "compute"},
                {"id": "serves_traffic_for", "category": "compute"},
                {"id": "exposed_through", "category": "exposure"},
                {"id": "publishes_to", "category": "messaging"},
                {"id": "subscribes_to", "category": "messaging"},
                {"id": "logging_enabled_to", "category": "monitoring"},
                {"id": "monitored_by", "category": "monitoring"},
                {"id": "backs_up_to", "category": "data"},
                {"id": "replicates_to", "category": "data"},
                {"id": "contained_by", "category": "network"}
            ]
        
        with open(self.relation_types_path, 'r') as f:
            data = json.load(f)
            return data.get("relation_types", [])
    
    def _load_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK for Cloud techniques"""
        return {
            "T1078": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "threat_types": ["identity", "privilege_escalation"]
            },
            "T1078.001": {
                "name": "Valid Accounts: Default Accounts",
                "description": "Adversaries may obtain and abuse credentials of default accounts",
                "threat_types": ["identity"]
            },
            "T1078.002": {
                "name": "Valid Accounts: Domain Accounts",
                "description": "Adversaries may obtain and abuse credentials of domain accounts",
                "threat_types": ["identity"]
            },
            "T1078.003": {
                "name": "Valid Accounts: Local Accounts",
                "description": "Adversaries may obtain and abuse credentials of local accounts",
                "threat_types": ["identity"]
            },
            "T1078.004": {
                "name": "Valid Accounts: Cloud Accounts",
                "description": "Adversaries may obtain and abuse credentials of cloud accounts",
                "threat_types": ["identity", "exposure"]
            },
            "T1134": {
                "name": "Access Token Manipulation",
                "description": "Adversaries may modify access tokens to escalate privileges",
                "threat_types": ["privilege_escalation"]
            },
            "T1134.001": {
                "name": "Access Token Manipulation: Token Impersonation/Theft",
                "description": "Adversaries may impersonate or steal access tokens",
                "threat_types": ["privilege_escalation"]
            },
            "T1134.002": {
                "name": "Access Token Manipulation: Create Process with Token",
                "description": "Adversaries may create processes with stolen tokens",
                "threat_types": ["privilege_escalation"]
            },
            "T1021": {
                "name": "Remote Services",
                "description": "Adversaries may use remote services to move between systems",
                "threat_types": ["lateral_movement"]
            },
            "T1021.001": {
                "name": "Remote Services: Remote Desktop Protocol",
                "description": "Adversaries may use RDP for lateral movement",
                "threat_types": ["lateral_movement"]
            },
            "T1021.002": {
                "name": "Remote Services: SMB/Windows Admin Shares",
                "description": "Adversaries may use SMB for lateral movement",
                "threat_types": ["lateral_movement"]
            },
            "T1021.003": {
                "name": "Remote Services: Distributed Component Object Model",
                "description": "Adversaries may use DCOM for lateral movement",
                "threat_types": ["lateral_movement"]
            },
            "T1021.004": {
                "name": "Remote Services: SSH",
                "description": "Adversaries may use SSH for lateral movement",
                "threat_types": ["lateral_movement"]
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may use application layer protocols for communication",
                "threat_types": ["lateral_movement", "exposure"]
            },
            "T1071.001": {
                "name": "Application Layer Protocol: Web Protocols",
                "description": "Adversaries may use web protocols for communication",
                "threat_types": ["exposure", "lateral_movement"]
            },
            "T1071.002": {
                "name": "Application Layer Protocol: File Transfer Protocols",
                "description": "Adversaries may use file transfer protocols",
                "threat_types": ["data_exfiltration"]
            },
            "T1020": {
                "name": "Automated Exfiltration",
                "description": "Adversaries may exfiltrate data using automated mechanisms",
                "threat_types": ["data_exfiltration"]
            },
            "T1020.001": {
                "name": "Automated Exfiltration: Traffic Duplication",
                "description": "Adversaries may duplicate traffic for exfiltration",
                "threat_types": ["data_exfiltration"]
            },
            "T1020.002": {
                "name": "Automated Exfiltration: Exfiltration Over C2 Channel",
                "description": "Adversaries may exfiltrate over C2 channels",
                "threat_types": ["data_exfiltration"]
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may exfiltrate data over C2 channels",
                "threat_types": ["data_exfiltration"]
            },
            "T1048": {
                "name": "Exfiltration Over Alternative Protocol",
                "description": "Adversaries may exfiltrate data over alternative protocols",
                "threat_types": ["data_exfiltration", "data_breach"]
            },
            "T1048.001": {
                "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                "description": "Adversaries may exfiltrate over encrypted non-C2 protocols",
                "threat_types": ["data_exfiltration"]
            },
            "T1048.002": {
                "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                "description": "Adversaries may exfiltrate over asymmetric encrypted protocols",
                "threat_types": ["data_exfiltration"]
            },
            "T1048.003": {
                "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
                "description": "Adversaries may exfiltrate over unencrypted protocols",
                "threat_types": ["data_exfiltration", "data_breach"]
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may exploit public-facing applications",
                "threat_types": ["exposure"]
            },
            "T1566": {
                "name": "Phishing",
                "description": "Adversaries may use phishing to gain initial access",
                "threat_types": ["exposure"]
            },
            "T1485": {
                "name": "Data Destruction",
                "description": "Adversaries may destroy data",
                "threat_types": ["data_breach"]
            },
            "T1486": {
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data for impact",
                "threat_types": ["data_breach"]
            }
        }
    
    def _load_misconfig_patterns(self) -> Dict[str, List[str]]:
        """Load misconfig patterns by service category"""
        return {
            "compute": [
                ".*public.*access.*",
                ".*internet.*reachable.*",
                ".*security.*group.*open.*",
                ".*imds.*v1.*",
                ".*user.*data.*exposed.*"
            ],
            "storage": [
                ".*bucket.*public.*",
                ".*public.*read.*",
                ".*public.*write.*",
                ".*versioning.*disabled.*",
                ".*encryption.*disabled.*",
                ".*logging.*not.*enabled.*"
            ],
            "database": [
                ".*database.*public.*",
                ".*rds.*public.*",
                ".*encryption.*disabled.*",
                ".*backup.*not.*enabled.*",
                ".*snapshot.*public.*",
                ".*ssl.*not.*required.*"
            ],
            "network": [
                r".*security.*group.*0\.0\.0\.0.*",
                ".*nacl.*allow.*all.*",
                ".*route.*table.*public.*",
                ".*internet.*gateway.*attached.*",
                ".*all.*traffic.*allowed.*"
            ],
            "identity": [
                ".*iam.*policy.*wildcard.*",
                ".*iam.*policy.*permissive.*",
                ".*iam.*role.*trust.*",
                ".*mfa.*not.*enabled.*",
                ".*root.*access.*",
                ".*admin.*access.*",
                ".*passrole.*"
            ],
            "secrets": [
                ".*secret.*rotation.*disabled.*",
                ".*secret.*public.*",
                ".*kms.*key.*rotation.*disabled.*",
                ".*parameter.*encryption.*disabled.*"
            ],
            "messaging": [
                ".*sns.*topic.*public.*",
                ".*sqs.*queue.*public.*",
                ".*encryption.*disabled.*"
            ],
            "monitoring": [
                ".*logging.*not.*enabled.*",
                ".*trail.*not.*encrypted.*",
                ".*config.*not.*enabled.*",
                ".*monitoring.*disabled.*"
            ],
            "api": [
                ".*api.*public.*",
                ".*cors.*wildcard.*",
                ".*authentication.*disabled.*",
                ".*rate.*limit.*disabled.*"
            ],
            "container": [
                ".*image.*scan.*disabled.*",
                ".*registry.*public.*",
                ".*vulnerability.*not.*scanned.*"
            ]
        }
    
    def get_service_category(self, service_name: str) -> Optional[str]:
        """Get category for a service"""
        for category, services in self.service_categories.items():
            if service_name in services:
                return category
        return None
    
    def generate_rules_for_service(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate threat rules for a specific service"""
        service_name = service.get("name", "")
        service_category = self.get_service_category(service_name)
        resource_types = service.get("resource_types", [])
        
        rules = []
        
        # Get misconfig patterns for this service category
        misconfig_patterns = self.misconfig_patterns.get(service_category, [])
        if not misconfig_patterns:
            # Use generic patterns (limit to 3 most common)
            misconfig_patterns = [
                ".*public.*",
                ".*encryption.*disabled.*",
                ".*logging.*not.*enabled.*"
            ]
        
        # Limit misconfig patterns to avoid explosion
        misconfig_patterns = misconfig_patterns[:3]
        
        # Generate rules for each threat type
        for threat_type, mitre_techniques in self.threat_mitre_mapping.items():
            # Get relevant relation types for this threat type (limit to top 3)
            relevant_relations = self._get_relevant_relations(threat_type, service_category)[:3]
            
            for misconfig_pattern in misconfig_patterns:
                for relation_type in relevant_relations:
                    # Determine target resource types (limit to top 2)
                    target_resources = self._get_target_resources(threat_type, service_category, relation_type)[:2]
                    
                    for target_resource in target_resources:
                        rule = self._create_rule(
                            service_name=service_name,
                            service_category=service_category,
                            threat_type=threat_type,
                            misconfig_pattern=misconfig_pattern,
                            relation_type=relation_type,
                            target_resource_type=target_resource,
                            mitre_techniques=mitre_techniques
                        )
                        if rule:
                            rules.append(rule)
        
        return rules
    
    def _get_relevant_relations(self, threat_type: str, service_category: Optional[str]) -> List[str]:
        """Get relevant relation types for threat type and service category"""
        base_relations = {
            "exposure": ["internet_connected", "exposed_through", "routes_to", "connected_to"],
            "identity": ["assumes", "uses", "has_policy", "grants_access_to", "controlled_by"],
            "lateral_movement": ["connected_to", "routes_to", "allows_traffic_from", "attached_to"],
            "data_exfiltration": ["uses", "stores_data_in", "replicates_to", "publishes_to"],
            "privilege_escalation": ["assumes", "grants_access_to", "controlled_by", "uses"],
            "data_breach": ["uses", "encrypted_by", "backs_up_to", "stores_data_in"]
        }
        
        relations = base_relations.get(threat_type, [])
        
        # Add category-specific relations
        if service_category == "compute":
            relations.extend(["serves_traffic_for", "invokes", "triggers"])
        elif service_category == "storage":
            relations.extend(["stores_data_in", "replicates_to"])
        elif service_category == "database":
            relations.extend(["uses", "stores_data_in"])
        elif service_category == "network":
            relations.extend(["routes_to", "connected_to", "allows_traffic_from"])
        
        return list(set(relations))  # Deduplicate
    
    def _get_target_resources(self, threat_type: str, service_category: Optional[str], relation_type: str) -> List[str]:
        """Get target resource types for threat detection"""
        targets = []
        
        if threat_type == "exposure":
            targets = ["ec2.*", "lambda.*", "ecs.*", "eks.*", "ec2.internet-gateway", "cloudfront.*"]
        elif threat_type == "lateral_movement":
            targets = ["rds.*", "dynamodb.*", "redshift.*", "secretsmanager.*", "ssm.*", "kms.*"]
        elif threat_type == "data_exfiltration":
            targets = ["s3.*", "rds.*", "dynamodb.*", "redshift.*", "efs.*", "ebs.*"]
        elif threat_type == "privilege_escalation":
            targets = ["iam.role", "iam.policy", "iam.user"]
        elif threat_type == "data_breach":
            targets = ["rds.*", "dynamodb.*", "s3.*", "redshift.*", "docdb.*"]
        else:
            # Generic targets
            targets = ["*"]
        
        return targets
    
    def _create_rule(
        self,
        service_name: str,
        service_category: Optional[str],
        threat_type: str,
        misconfig_pattern: str,
        relation_type: str,
        target_resource_type: str,
        mitre_techniques: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Create a threat rule"""
        # Generate rule ID
        pattern_clean = re.sub(r'[^\w]', '_', misconfig_pattern.replace(".*", "").replace(".", "_"))
        target_clean = target_resource_type.replace(".*", "").replace(".", "_")
        rule_id = f"{threat_type}_{service_name}_{pattern_clean[:20]}_{relation_type}_{target_clean[:20]}"
        rule_id = rule_id[:100].lower()
        
        # Determine severity
        severity = self._determine_severity(threat_type, misconfig_pattern, service_category)
        
        # Determine confidence
        confidence = "high" if threat_type in ["exposure", "data_breach"] and service_category else "medium"
        
        # Build title
        title = f"{threat_type.replace('_', ' ').title()} in {service_name} via {relation_type}"
        
        # Build description
        mitre_names = [self.mitre_techniques.get(t, {}).get("name", t) for t in mitre_techniques[:2]]
        description = (
            f"Detects {threat_type} threat in {service_name} when misconfig pattern "
            f"'{misconfig_pattern}' is combined with '{relation_type}' relationship to "
            f"'{target_resource_type}'. Maps to MITRE ATT&CK: {', '.join(mitre_names)}"
        )
        
        return {
            "rule_id": rule_id,
            "threat_type": threat_type,
            "mitre_techniques": mitre_techniques,
            "service": service_name,
            "service_category": service_category,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "misconfig_patterns": [misconfig_pattern],
            "relationship_conditions": {
                "required_relations": [
                    {
                        "relation_type": relation_type,
                        "target_resource_type": target_resource_type
                    }
                ]
            },
            "remediation": {
                "summary": f"Review and remediate {threat_type} threat in {service_name}",
                "steps": [
                    f"Review misconfig: {misconfig_pattern}",
                    f"Analyze relationship: {relation_type} → {target_resource_type}",
                    f"Apply security best practices for {service_name}",
                    "Re-scan to verify threat is resolved"
                ]
            }
        }
    
    def _determine_severity(self, threat_type: str, pattern: str, service_category: Optional[str]) -> str:
        """Determine severity based on threat type, pattern, and service"""
        critical_patterns = [
            "public.*write", "all.*traffic", "root.*access", 
            "admin.*access", "database.*public", "rds.*public"
        ]
        
        if any(cp in pattern for cp in critical_patterns):
            return "critical"
        
        if threat_type in ["data_breach", "exposure"]:
            return "high"
        elif threat_type in ["privilege_escalation", "data_exfiltration"]:
            return "high"
        elif service_category in ["identity", "secrets"]:
            return "high"
        else:
            return "medium"
    
    def generate_all_rules(self) -> List[Dict[str, Any]]:
        """Generate threat rules for all services"""
        all_rules = []
        
        print(f"Generating rules for {len(self.services)} services...")
        
        for i, service in enumerate(self.services):
            service_name = service.get("name", "")
            if not service_name:
                continue
            
            if i % 10 == 0:
                print(f"  Processing service {i+1}/{len(self.services)}: {service_name}")
            
            rules = self.generate_rules_for_service(service)
            all_rules.extend(rules)
        
        # Deduplicate
        seen_ids = set()
        unique_rules = []
        for rule in all_rules:
            rule_id = rule.get("rule_id", "")
            if rule_id and rule_id not in seen_ids:
                seen_ids.add(rule_id)
                unique_rules.append(rule)
        
        print(f"\nGenerated {len(unique_rules)} unique threat rules")
        
        return unique_rules
    
    def save_rules(self, rules: List[Dict[str, Any]], output_path: str):
        """Save rules to YAML file"""
        output = {
            "version": "1.0",
            "generated_at": str(Path().cwd()),
            "total_rules": len(rules),
            "total_services": len(self.services),
            "mitre_coverage": {
                "techniques_covered": len(set(
                    tech for rule in rules 
                    for tech in rule.get("mitre_techniques", [])
                )),
                "threat_types": len(set(r.get("threat_type") for r in rules))
            },
            "threat_rules": rules
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            yaml.dump(output, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"\nSaved {len(rules)} threat rules to {output_path}")
        print(f"Coverage:")
        print(f"  Services: {len(self.services)}")
        print(f"  MITRE Techniques: {output['mitre_coverage']['techniques_covered']}")
        print(f"  Threat Types: {output['mitre_coverage']['threat_types']}")


def main():
    parser = argparse.ArgumentParser(description="Generate comprehensive threat rules")
    parser.add_argument(
        "--service-list",
        default="/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/config/service_list.json",
        help="Path to service_list.json"
    )
    parser.add_argument(
        "--relation-types",
        default="/Users/apple/Desktop/threat-engine/inventory-engine/inventory_engine/config/relation_types.json",
        help="Path to relation_types.json"
    )
    parser.add_argument(
        "--output",
        default="/Users/apple/Desktop/threat-engine/threat_engine/threat_engine/config/threat_rules.yaml",
        help="Output YAML file"
    )
    
    args = parser.parse_args()
    
    generator = ComprehensiveThreatRuleGenerator(
        service_list_path=args.service_list,
        relation_types_path=args.relation_types
    )
    
    rules = generator.generate_all_rules()
    generator.save_rules(rules, args.output)


if __name__ == "__main__":
    main()
