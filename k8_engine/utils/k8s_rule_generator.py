#!/usr/bin/env python3
"""
Kubernetes Rule Generator
Generates service YAML files and metadata from rule_ids_QUALITY_IMPROVED.yaml
Based on the pattern used in other CSP engines
"""

import yaml
import os
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional


class K8sRuleGenerator:
    """Generate K8s service rules from enriched rule IDs"""
    
    # K8s component/service to resource type mapping
    COMPONENT_TYPE_MAP = {
        'apiserver': 'control_plane',
        'etcd': 'control_plane',
        'controllermanager': 'control_plane',
        'scheduler': 'control_plane',
        'kubelet': 'node',
        'core': 'workload',
        'pod': 'workload',
        'workload': 'workload',
        'rbac': 'workload',
        'admission': 'policy',
        'policy': 'policy',
        'network': 'workload',
        'service': 'workload',
        'ingress': 'workload',
        'storage': 'workload',
        'persistentvolume': 'workload',
        'configmap': 'workload',
        'secret': 'workload',
        'namespace': 'workload',
        'node': 'node',
        'cluster': 'cluster',
        'audit': 'control_plane',
        'certificate': 'infrastructure',
    }
    
    # Map services to K8s API discovery actions
    ACTION_MAP = {
        'pod': 'list_pods',
        'core': 'list_pods',
        'workload': 'list_pods',
        'deployment': 'list_deployments',
        'statefulset': 'list_statefulsets',
        'daemonset': 'list_daemonsets',
        'service': 'list_services',
        'ingress': 'list_ingresses',
        'networkpolicy': 'list_network_policies',
        'network': 'list_network_policies',
        'configmap': 'list_configmaps',
        'secret': 'list_secrets',
        'persistentvolume': 'list_persistent_volumes',
        'persistentvolumeclaim': 'list_persistent_volume_claims',
        'storageclass': 'list_storage_classes',
        'namespace': 'list_namespaces',
        'serviceaccount': 'list_service_accounts',
        'role': 'list_roles',
        'rolebinding': 'list_role_bindings',
        'clusterrole': 'list_cluster_roles',
        'clusterrolebinding': 'list_cluster_role_bindings',
        'rbac': 'list_cluster_roles',
        'job': 'list_jobs',
        'cronjob': 'list_cronjobs',
        'poddisruptionbudget': 'list_pod_disruption_budgets',
    }
    
    def __init__(self, rule_ids_path: Path, output_dir: Path):
        self.rule_ids_path = rule_ids_path
        self.output_dir = output_dir
        self.stats = {
            'total_rules': 0,
            'services_created': 0,
            'metadata_files': 0,
            'errors': []
        }
    
    def load_rules(self) -> Dict[str, List[Dict]]:
        """Load and group rules by service"""
        print(f"📖 Loading rules from {self.rule_ids_path}...")
        
        with open(self.rule_ids_path) as f:
            data = yaml.safe_load(f)
        
        rules = data.get('rule_ids', [])
        self.stats['total_rules'] = len(rules)
        print(f"   Found {len(rules)} rules")
        
        # Group by service
        services = defaultdict(list)
        for rule in rules:
            service = rule.get('service', 'general')
            services[service].append(rule)
        
        print(f"   Grouped into {len(services)} services")
        return dict(services)
    
    def generate_metadata_file(self, rule: Dict[str, Any], service: str) -> Path:
        """Generate metadata YAML file for a single rule"""
        rule_id = rule.get('rule_id', '')
        
        # Create metadata directory
        metadata_dir = self.output_dir / service / 'metadata'
        metadata_dir.mkdir(parents=True, exist_ok=True)
        
        # Filename: k8s.service.resource.check.yaml
        filename = f"{rule_id}.yaml"
        filepath = metadata_dir / filename
        
        # Build metadata content
        metadata = {
            'rule_id': rule_id,
            'service': service,
            'resource': rule.get('resource', ''),
            'requirement': rule.get('requirement', ''),
            'title': rule.get('title', ''),
            'description': rule.get('description', ''),
            'rationale': rule.get('rationale', ''),
            'severity': rule.get('severity', 'medium').lower(),
            'domain': rule.get('domain', ''),
            'subcategory': rule.get('subcategory', ''),
            'scope': rule.get('scope', ''),
            'references': rule.get('references', []),
            'compliance': rule.get('compliance', []),
        }
        
        # Write metadata file
        with open(filepath, 'w') as f:
            yaml.dump(metadata, f, default_flow_style=False, sort_keys=False)
        
        self.stats['metadata_files'] += 1
        return filepath
    
    def infer_check_logic(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Infer check logic from rule metadata"""
        rule_id = rule.get('rule_id', '')
        resource = rule.get('resource', '')
        requirement = rule.get('requirement', '').lower()
        title = rule.get('title', '').lower()
        
        # Default check structure
        check = {
            'check_id': rule_id,
            'name': rule.get('requirement', rule_id.replace('_', ' ').title()),
            'severity': rule.get('severity', 'medium').upper(),
            'for_each': None,  # Will be set based on service
            'param': 'item',
            'calls': [],
            'logic': 'AND',
            'errors_as_fail': []
        }
        
        # Infer operator based on requirement keywords
        operator = 'exists'
        expected = None
        
        if any(word in requirement for word in ['enabled', 'enable', 'configured', 'set']):
            operator = 'equals'
            expected = True
        elif any(word in requirement for word in ['disabled', 'disable', 'not', 'restrict', 'minimize']):
            operator = 'not_equals'
            expected = True
        elif 'encryption' in requirement or 'encrypted' in requirement:
            operator = 'exists'
        elif 'version' in requirement:
            operator = 'gte'
        
        # Build field check
        # For control plane components, check arguments
        # For workloads, check resource properties
        path = self._infer_field_path(rule_id, resource, requirement)
        
        check['calls'] = [{
            'action': 'identity',
            'params': {},
            'fields': [{
                'path': path,
                'operator': operator,
                'expected': expected
            }]
        }]
        
        return check
    
    def _infer_field_path(self, rule_id: str, resource: str, requirement: str) -> str:
        """Infer the field path to check based on rule metadata"""
        # Control plane checks typically look at arguments
        if any(comp in rule_id for comp in ['apiserver', 'etcd', 'scheduler', 'controllermanager']):
            # Extract argument name from rule_id
            # e.g., k8s.apiserver.argument.audit_log_enabled -> arguments.audit-log-path
            parts = rule_id.split('.')
            if len(parts) >= 4:
                arg_hint = parts[-1].replace('_', '-')
                return f'arguments.{arg_hint}'
            return 'arguments'
        
        # Workload checks
        if 'container' in requirement or 'pod' in requirement:
            if 'privileged' in requirement:
                return 'item.containers[].securityContext.privileged'
            elif 'capability' in requirement or 'capabilities' in requirement:
                return 'item.containers[].securityContext.capabilities'
            elif 'hostnetwork' in requirement.replace(' ', ''):
                return 'item.hostNetwork'
            elif 'hostpid' in requirement.replace(' ', ''):
                return 'item.hostPID'
            elif 'hostipc' in requirement.replace(' ', ''):
                return 'item.hostIPC'
            elif 'image' in requirement:
                return 'item.containers[].image'
            elif 'secret' in requirement:
                return 'item.containers[].env'
        
        # RBAC checks
        if 'rbac' in rule_id or 'role' in requirement:
            if 'wildcard' in requirement:
                return 'item.rules[].resources'
            elif 'cluster-admin' in requirement:
                return 'item.name'
            return 'item.rules'
        
        # Network checks
        if 'network' in requirement or 'ingress' in requirement or 'egress' in requirement:
            return 'item.policy_types'
        
        # Default: check item name or properties
        return 'item.name'
    
    def generate_service_yaml(self, service: str, rules: List[Dict[str, Any]]) -> Path:
        """Generate service YAML file with discovery and checks"""
        print(f"   📝 Generating {service} service YAML ({len(rules)} checks)...")
        
        # Create service directory
        service_dir = self.output_dir / service
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine component type
        component_type = self.COMPONENT_TYPE_MAP.get(service, 'workload')
        
        # Determine discovery action
        discovery_action = self.ACTION_MAP.get(service, 'list_pods')
        discovery_id = f"list_{service}_resources"
        
        # Build service YAML structure
        service_yaml = {
            'component': service,
            'component_type': component_type,
            'discovery': [{
                'discovery_id': discovery_id,
                'calls': [{
                    'action': discovery_action,
                    'fields': [
                        {'path': 'name', 'var': 'name'},
                        {'path': 'namespace', 'var': 'namespace'},
                        {'path': 'labels', 'var': 'labels'},
                    ]
                }]
            }],
            'checks': []
        }
        
        # Add checks
        for rule in rules:
            check = self.infer_check_logic(rule)
            check['for_each'] = discovery_id
            service_yaml['checks'].append(check)
        
        # Write service YAML
        filepath = service_dir / f"{service}_rules.yaml"
        with open(filepath, 'w') as f:
            yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False)
        
        self.stats['services_created'] += 1
        return filepath
    
    def generate_all(self):
        """Generate all service files and metadata"""
        print(f"\n🚀 K8s Rule Generator")
        print(f"=" * 60)
        
        # Load rules
        services = self.load_rules()
        
        # Generate metadata and service files
        print(f"\n📦 Generating service files...")
        for service, rules in sorted(services.items()):
            try:
                print(f"\n🔧 Processing {service}:")
                
                # Generate metadata files for each rule
                for rule in rules:
                    self.generate_metadata_file(rule, service)
                
                # Generate service YAML
                self.generate_service_yaml(service, rules)
                
            except Exception as e:
                error_msg = f"Error processing {service}: {e}"
                print(f"   ❌ {error_msg}")
                self.stats['errors'].append(error_msg)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print generation summary"""
        print(f"\n{'=' * 60}")
        print(f"✅ Generation Complete!")
        print(f"{'=' * 60}")
        print(f"Total Rules:          {self.stats['total_rules']}")
        print(f"Services Created:     {self.stats['services_created']}")
        print(f"Metadata Files:       {self.stats['metadata_files']}")
        print(f"Errors:               {len(self.stats['errors'])}")
        
        if self.stats['errors']:
            print(f"\n❌ Errors:")
            for error in self.stats['errors'][:10]:  # Show first 10
                print(f"   - {error}")
        
        print(f"\nOutput Directory: {self.output_dir}")


def main():
    """Main entry point"""
    # Paths
    base_dir = Path(__file__).parent.parent
    rule_ids_path = base_dir / 'rule_ids_QUALITY_IMPROVED.yaml'
    output_dir = base_dir / 'services'
    
    # Check if rule IDs file exists
    if not rule_ids_path.exists():
        print(f"❌ Error: Rule IDs file not found: {rule_ids_path}")
        return 1
    
    # Create generator and run
    generator = K8sRuleGenerator(rule_ids_path, output_dir)
    generator.generate_all()
    
    return 0


if __name__ == '__main__':
    exit(main())

