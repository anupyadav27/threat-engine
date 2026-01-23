#!/usr/bin/env python3
"""
Fix Resource Misalignment in OCI CSPM Rules
Extracts actual OCI resources from assertion-like resource names
and moves assertions to the proper field
"""

import yaml
from datetime import datetime
from collections import defaultdict, Counter
import re

# OCI Service to Resource Mappings (based on OCI Python SDK)
OCI_SERVICE_RESOURCES = {
    'compute': {
        'default': 'instance',
        'keywords': {
            'instance': 'instance',
            'vm': 'instance',
            'image': 'image',
            'boot': 'boot_volume_attachment',
            'volume': 'volume_attachment',
            'vnic': 'vnic_attachment',
            'launch': 'instance',
            'template': 'instance',
            'group': 'instance_pool',
            'spot': 'instance',
            'dedicated': 'dedicated_vm_host',
            'capacity': 'compute_capacity_reservation',
            'host': 'dedicated_vm_host',
        }
    },
    'database': {
        'default': 'autonomous_database',
        'keywords': {
            'database': 'database',
            'db': 'db_system',
            'autonomous': 'autonomous_database',
            'adb': 'autonomous_database',
            'cluster': 'db_system',
            'backup': 'backup',
            'snapshot': 'backup',
            'endpoint': 'autonomous_database',
            'parameter': 'db_system',
            'instance': 'db_system',
            'partition': 'database',
            'table': 'database',
            'schema': 'database',
        }
    },
    'object_storage': {
        'default': 'bucket',
        'keywords': {
            'bucket': 'bucket',
            'object': 'object',
            'storage': 'bucket',
            'namespace': 'namespace',
            'lifecycle': 'bucket',
            'replication': 'replication_policy',
            'retention': 'bucket',
        }
    },
    'block_storage': {
        'default': 'volume',
        'keywords': {
            'volume': 'volume',
            'boot': 'boot_volume',
            'backup': 'volume_backup',
            'snapshot': 'volume_backup',
            'group': 'volume_group',
        }
    },
    'virtual_network': {
        'default': 'vcn',
        'keywords': {
            'vcn': 'vcn',
            'subnet': 'subnet',
            'gateway': 'internet_gateway',
            'nat': 'nat_gateway',
            'service': 'service_gateway',
            'drg': 'drg',
            'route': 'route_table',
            'security': 'security_list',
            'nsg': 'network_security_group',
            'vnic': 'vnic',
            'endpoint': 'vcn',
            'vpn': 'ip_sec_connection',
            'peering': 'local_peering_gateway',
            'fastconnect': 'virtual_circuit',
            'cgw': 'cpe',
        }
    },
    'load_balancer': {
        'default': 'load_balancer',
        'keywords': {
            'load': 'load_balancer',
            'balancer': 'load_balancer',
            'lb': 'load_balancer',
            'listener': 'listener',
            'backend': 'backend_set',
            'certificate': 'certificate',
            'rule': 'rule_set',
        }
    },
    'identity': {
        'default': 'user',
        'keywords': {
            'user': 'user',
            'group': 'group',
            'policy': 'policy',
            'compartment': 'compartment',
            'dynamic': 'dynamic_group',
            'tag': 'tag_namespace',
            'domain': 'domain',
            'federation': 'identity_provider',
            'mfa': 'user',
            'key': 'api_key',
            'credential': 'user',
            'role': 'policy',
        }
    },
    'apigateway': {
        'default': 'gateway',
        'keywords': {
            'gateway': 'gateway',
            'deployment': 'deployment',
            'api': 'api',
            'certificate': 'certificate',
            'stage': 'deployment',
            'authorizer': 'gateway',
            'usage': 'gateway',
        }
    },
    'functions': {
        'default': 'application',
        'keywords': {
            'application': 'application',
            'function': 'function',
            'app': 'application',
            'layer': 'application',
            'version': 'application',
        }
    },
    'container_engine': {
        'default': 'cluster',
        'keywords': {
            'cluster': 'cluster',
            'node': 'node_pool',
            'pool': 'node_pool',
            'workload': 'cluster',
            'addon': 'addon',
            'pod': 'cluster',
            'namespace': 'cluster',
            'deployment': 'cluster',
            'service': 'cluster',
        }
    },
    'key_management': {
        'default': 'vault',
        'keywords': {
            'vault': 'vault',
            'key': 'key',
            'hsm': 'vault',
            'secret': 'key',
            'grant': 'key',
            'alias': 'key',
        }
    },
    'vault': {
        'default': 'secret',
        'keywords': {
            'secret': 'secret',
            'key': 'secret',
        }
    },
    'monitoring': {
        'default': 'alarm',
        'keywords': {
            'alarm': 'alarm',
            'metric': 'metric',
            'log': 'alarm',
            'trace': 'alarm',
            'sampling': 'alarm',
            'escalation': 'alarm',
            'incident': 'alarm',
            'notification': 'alarm',
        }
    },
    'logging': {
        'default': 'log_group',
        'keywords': {
            'log': 'log',
            'group': 'log_group',
            'agent': 'unified_agent_configuration',
        }
    },
    'audit': {
        'default': 'configuration',
        'keywords': {
            'configuration': 'configuration',
            'delivery': 'configuration',
            'recorder': 'configuration',
        }
    },
    'cloud_guard': {
        'default': 'target',
        'keywords': {
            'target': 'target',
            'detector': 'detector_recipe',
            'responder': 'responder_recipe',
            'recipe': 'detector_recipe',
            'rule': 'detector_rule',
            'finding': 'target',
        }
    },
    'file_storage': {
        'default': 'file_system',
        'keywords': {
            'file': 'file_system',
            'filesystem': 'file_system',
            'mount': 'mount_target',
            'export': 'export',
            'snapshot': 'snapshot',
        }
    },
    'dns': {
        'default': 'zone',
        'keywords': {
            'zone': 'zone',
            'record': 'record',
            'steering': 'steering_policy',
            'policy': 'steering_policy',
            'tsig': 'tsig_key',
        }
    },
    'streaming': {
        'default': 'stream',
        'keywords': {
            'stream': 'stream',
            'pool': 'stream_pool',
            'connect': 'connect_harness',
            'consumer': 'stream',
            'producer': 'stream',
        }
    },
    'nosql': {
        'default': 'table',
        'keywords': {
            'table': 'table',
            'index': 'index',
            'row': 'row',
        }
    },
    'mysql': {
        'default': 'db_system',
        'keywords': {
            'db': 'db_system',
            'database': 'db_system',
            'backup': 'backup',
            'configuration': 'configuration',
            'channel': 'channel',
            'heatwave': 'db_system',
        }
    },
    'data_catalog': {
        'default': 'catalog',
        'keywords': {
            'catalog': 'catalog',
            'asset': 'data_asset',
            'connection': 'connection',
            'entity': 'entity',
            'attribute': 'attribute',
            'classifier': 'catalog',
            'glossary': 'glossary',
            'job': 'job',
            'harvest': 'job',
        }
    },
    'data_science': {
        'default': 'project',
        'keywords': {
            'project': 'project',
            'notebook': 'notebook_session',
            'model': 'model',
            'deployment': 'model_deployment',
            'job': 'job',
            'run': 'job_run',
            'pipeline': 'pipeline',
            'endpoint': 'model_deployment',
            'experiment': 'project',
            'dataset': 'project',
        }
    },
    'data_flow': {
        'default': 'application',
        'keywords': {
            'application': 'application',
            'run': 'run',
            'endpoint': 'private_endpoint',
            'spark': 'application',
        }
    },
    'data_integration': {
        'default': 'workspace',
        'keywords': {
            'workspace': 'workspace',
            'project': 'project',
            'application': 'application',
            'pipeline': 'pipeline',
            'task': 'task',
            'flow': 'data_flow',
            'connection': 'connection',
            'parameter': 'pipeline',
            'ruleset': 'workspace',
        }
    },
    'events': {
        'default': 'rule',
        'keywords': {
            'rule': 'rule',
            'action': 'action',
            'trigger': 'rule',
            'event': 'rule',
        }
    },
    'ons': {
        'default': 'topic',
        'keywords': {
            'topic': 'topic',
            'subscription': 'subscription',
            'notification': 'topic',
        }
    },
    'queue': {
        'default': 'queue',
        'keywords': {
            'queue': 'queue',
        }
    },
    'waf': {
        'default': 'web_app_firewall',
        'keywords': {
            'firewall': 'web_app_firewall',
            'waf': 'web_app_firewall',
            'policy': 'web_app_firewall_policy',
            'rule': 'protection_rule',
            'acl': 'web_app_firewall_policy',
        }
    },
    'network_firewall': {
        'default': 'network_firewall',
        'keywords': {
            'firewall': 'network_firewall',
            'policy': 'network_firewall_policy',
        }
    },
    'analytics': {
        'default': 'analytics_instance',
        'keywords': {
            'instance': 'analytics_instance',
            'vanity': 'vanity_url',
        }
    },
    'devops': {
        'default': 'project',
        'keywords': {
            'project': 'project',
            'repository': 'repository',
            'build': 'build_pipeline',
            'deployment': 'deployment_pipeline',
            'artifact': 'deploy_artifact',
        }
    },
    'resource_manager': {
        'default': 'stack',
        'keywords': {
            'stack': 'stack',
            'job': 'job',
            'configuration': 'configuration_source_provider',
            'runbook': 'stack',
        }
    },
    'certificates': {
        'default': 'certificate',
        'keywords': {
            'certificate': 'certificate',
            'ca': 'certificate_authority',
            'bundle': 'ca_bundle',
        }
    },
    'bds': {
        'default': 'bds_instance',
        'keywords': {
            'instance': 'bds_instance',
            'cluster': 'bds_instance',
            'api_key': 'api_key',
            'metastore': 'metastore_configuration',
        }
    },
    'data_safe': {
        'default': 'data_safe_configuration',
        'keywords': {
            'configuration': 'data_safe_configuration',
            'target': 'target_database',
            'assessment': 'security_assessment',
            'masking': 'masking_policy',
        }
    },
    'edge_services': {
        'default': 'distribution',
        'keywords': {
            'distribution': 'distribution',
            'cdn': 'distribution',
            'cache': 'distribution',
            'origin': 'distribution',
            'policy': 'distribution',
        }
    },
    'redis': {
        'default': 'cluster',
        'keywords': {
            'cluster': 'cluster',
        }
    },
    'ai_anomaly_detection': {
        'default': 'detector',
        'keywords': {
            'detector': 'detector',
            'model': 'model',
        }
    },
}

def extract_resource_from_assertion_name(service: str, resource_name: str) -> str:
    """
    Extract actual OCI resource from assertion-like resource name
    """
    if service not in OCI_SERVICE_RESOURCES:
        return 'resource'
    
    service_config = OCI_SERVICE_RESOURCES[service]
    resource_lower = resource_name.lower()
    
    # Split by underscores and check each part
    parts = resource_lower.split('_')
    
    # Check for keyword matches
    for keyword, oci_resource in service_config['keywords'].items():
        if keyword in parts or keyword in resource_lower:
            return oci_resource
    
    # Return default resource for the service
    return service_config['default']

def is_assertion_like_resource(resource: str) -> bool:
    """Check if resource name looks like an assertion"""
    assertion_keywords = [
        'security', 'governance', 'compliance', 'privacy', 'threat',
        'resilience', 'incident', 'vulnerability', 'vuln', 'backup',
        'dr_', 'lineage', 'datalake', 'data_catalog', 'data_warehouse',
        'data_analytics', 'data_protection', 'data_governance',
        'machine_learning', 'ml_ops', 'ai_services', 'platform',
        'serverless', 'containers', 'network_', 'compute_',
        'identity_', 'logging_', 'monitoring_', 'streaming_',
        'cost_', 'supply_chain', 'paas_', 'configuration_management'
    ]
    return any(keyword in resource.lower() for keyword in assertion_keywords)

print("=" * 100)
print("FIXING RESOURCE MISALIGNMENT - OCI CSPM RULES")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_RESOURCE_FIX_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Fix misaligned rules
fixed_rules = []
changes = []
service_stats = Counter()

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        # Check if resource is misaligned
        if is_assertion_like_resource(resource):
            # Extract actual resource
            actual_resource = extract_resource_from_assertion_name(service, resource)
            
            # Build new assertion (combine old resource + old assertion)
            if assertion:
                new_assertion = f"{resource}.{assertion}"
            else:
                new_assertion = resource
            
            new_rule = f"{csp}.{service}.{actual_resource}.{new_assertion}"
            fixed_rules.append(new_rule)
            
            changes.append({
                'old': rule,
                'new': new_rule,
                'service': service,
                'old_resource': resource,
                'new_resource': actual_resource
            })
            
            service_stats[service] += 1
        else:
            # Keep rule as-is
            fixed_rules.append(rule)
    else:
        fixed_rules.append(rule)

print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")
print(f"\nRules Fixed: {len(changes)} ({len(changes)/len(rules)*100:.1f}%)")
print(f"Rules Unchanged: {len(rules) - len(changes)} ({(len(rules) - len(changes))/len(rules)*100:.1f}%)")

print(f"\n{'=' * 100}")
print("CHANGES BY SERVICE")
print(f"{'=' * 100}")

for service, count in service_stats.most_common():
    print(f"{service:30s} {count:4d} rules fixed")

print(f"\n{'=' * 100}")
print("SAMPLE FIXES (First 20)")
print(f"{'=' * 100}")

for change in changes[:20]:
    print(f"\nService: {change['service']}")
    print(f"Resource Change: {change['old_resource']:60s} → {change['new_resource']}")
    print(f"OLD: {change['old']}")
    print(f"NEW: {change['new']}")

# Update rules
data['rule_ids'] = fixed_rules
data['metadata']['total_rules'] = len(fixed_rules)
data['metadata']['last_resource_fix'] = datetime.now().isoformat()
data['metadata']['resource_fix_phase'] = 'complete'
data['metadata']['rules_fixed'] = len(changes)

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Resource Alignment Complete!")
print(f"✅ Rules Fixed: {len(changes)}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

