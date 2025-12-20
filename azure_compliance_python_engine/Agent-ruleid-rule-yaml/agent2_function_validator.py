"""
Agent 2: Azure SDK Function Validator

Takes AI-generated requirements and validates/maps to actual Azure SDK operations.
"""

import json
import sys
from typing import Dict, List, Any
from azure_sdk_dependency_analyzer import load_analyzer
from agent_logger import get_logger

logger = get_logger('agent2')

# Service name mapping: metadata service name → Azure SDK catalog service name
# None means no SDK coverage - will use monitor as fallback
SERVICE_NAME_MAPPING = {
    # Direct SDK mappings
    'aad': 'authorization',
    'aks': 'containerservice',
    'api': 'apimanagement',
    'backup': 'recoveryservicesbackup',
    'container': 'containerinstance',
    'event': 'eventhub',
    'function': 'web',
    'managementgroup': 'managementgroups',
    'mariadb': 'rdbms_mariadb',
    'mysql': 'rdbms_mysql',
    'postgresql': 'rdbms_postgresql',
    'webapp': 'web',
    
    # Network-related services
    'dns': 'network',
    'front': 'network',
    'traffic': 'network',
    
    # Storage-related services
    'blob': 'storage',
    'files': 'storage',
    
    # Security/IAM-related
    'iam': 'authorization',
    'rbac': 'authorization',
    'policy': 'authorization',
    
    # Key-related
    'key': 'keyvault',
    'certificates': 'keyvault',
    
    # Backup/Recovery-related
    'dataprotection': 'recoveryservicesbackup',
    
    # Management-related
    'management': 'managementgroups',
    'resource': 'subscription',
    
    # Monitoring-related
    'log': 'monitor',
    
    # Compute-related
    'machine': 'compute',
    
    # Services without direct SDK mapping (use monitor as fallback)
    # Note: These services are mapped in Agent 1 but not in SDK catalog, so use monitor fallback
    'billing': 'monitor',
    'cost': 'monitor',
    'data': 'monitor',
    'iot': 'monitor',
    'purview': 'monitor',
    'redis': 'monitor',
    'search': 'monitor',
    'cdn': 'network',  # CDN is network-related
    'config': 'authorization',  # Azure Policy/Config uses authorization
    'containerregistry': 'containerservice',  # ACR relates to containers
    'databricks': 'compute',  # Databricks is compute workloads
    'elastic': 'storage',  # Elastic SAN is storage
    'hdinsight': 'compute',  # HDInsight is compute clusters
    'logic': 'web',  # Logic Apps is part of Azure Web/App Services
    'netappfiles': 'storage',  # NetApp Files is storage
    'notification': 'eventhub',  # Notification Hubs uses event patterns
    'security': 'authorization',  # Security/Defender uses authorization patterns
    'synapse': 'sql',  # Synapse Analytics is SQL-based
    
    # Services without standard Azure Resource Manager SDK (use monitor as fallback)
    'devops': 'monitor',  # Uses azure-devops SDK (not ARM pattern)
    'intune': 'monitor',  # Part of Microsoft Graph API
    'power': 'monitor',  # Power BI uses separate API
}


def find_best_list_operation(analyzer, service: str, required_fields: List[str] = None) -> Dict[str, Any]:
    """
    Find the best list operation for a service.
    Prefers operations with 0 required params.
    If required_fields provided, picks operation that has those fields.
    """
    list_ops = analyzer.find_list_operations(service)
    
    if not list_ops:
        logger.warning(f"No list operations found for {service}")
        return None
    
    # Prefer operations with no required params
    no_params = [op for op in list_ops if len(op['required_params']) == 0]
    candidates = no_params if no_params else list_ops
    
    # If required_fields specified, score operations by field match
    if required_fields and len(candidates) > 1:
        scored_ops = []
        for op in candidates:
            fields = op.get('item_fields', {})
            if isinstance(fields, dict):
                field_set = set(fields.keys())
            else:
                field_set = set(fields) if fields else set()
            
            # Score: how many required fields are present
            score = sum(1 for f in required_fields if f in field_set)
            scored_ops.append((score, op))
        
        # Sort by score descending
        scored_ops.sort(key=lambda x: x[0], reverse=True)
        
        if scored_ops[0][0] > 0:
            logger.info(f"Selected operation with {scored_ops[0][0]}/{len(required_fields)} matching fields")
            return scored_ops[0][1]
    
    # Otherwise, take the first candidate
    return candidates[0]


def validate_function(rule: Dict[str, Any], analyzer) -> Dict[str, Any]:
    """
    Validate and map AI requirements to Azure SDK operations.
    
    Returns:
        Rule with added 'validated_function' section
    """
    service = rule['service']
    rule_id = rule['rule_id']
    
    logger.info(f"Validating function for {rule_id}")
    
    # Map service name to SDK name if needed
    sdk_service = SERVICE_NAME_MAPPING.get(service, service)
    if sdk_service != service:
        logger.info(f"Mapped service '{service}' to SDK service '{sdk_service}'")
    
    # Extract required fields from AI requirements
    ai_reqs = rule.get('ai_generated_requirements', {})
    ai_fields = ai_reqs.get('fields', [])
    required_fields = [f.get('azure_sdk_python_field', '') for f in ai_fields if f.get('azure_sdk_python_field')]
    
    # Find best list operation for this service (with field matching)
    operation = find_best_list_operation(analyzer, sdk_service, required_fields)
    
    if not operation:
        logger.error(f"No suitable operation found for {service}")
        return {
            **rule,
            'validated_function': {
                'error': f'No list operations found for service {service}'
            }
        }
    
    # Get fields DIRECTLY from the selected operation (not from index which may have wrong one)
    item_fields = operation.get('item_fields', [])
    if isinstance(item_fields, dict):
        item_fields = list(item_fields.keys())
    
    logger.info(f"Mapped to {service}.{operation['operation']}")
    logger.info(f"Available fields: {len(item_fields)} item fields")
    
    return {
        **rule,
        'validated_function': {
            'python_method': operation['python_method'],
            'azure_operation': operation['operation'],
            'yaml_action': operation['yaml_action'],
            'is_independent': True,
            'required_params': operation['required_params'],
            'optional_params': operation['optional_params'],
            'output_fields': operation.get('output_fields', []),
            'main_output_field': operation.get('main_output_field'),
            'item_fields': item_fields,
            'discovery_id': f"azure.{service}.{operation['yaml_action']}"
        }
    }


def main():
    logger.info("Agent 2 starting - Function Validator")
    print("=" * 80)
    print("AGENT 2: Azure SDK Function Validator")
    print("=" * 80)
    print("Maps AI requirements to actual Azure SDK operations")
    print()
    
    # Load analyzer
    logger.info("Loading Azure SDK analyzer...")
    print("Loading Azure SDK analyzer...")
    analyzer = load_analyzer()
    logger.info("Analyzer loaded")
    print("✅ Loaded")
    print()
    
    # Load requirements from Agent 1
    logger.info("Loading requirements from Agent 1...")
    print("Loading requirements_initial.json...")
    try:
        with open('output/requirements_initial.json') as f:
            requirements = json.load(f)
        logger.info(f"Loaded requirements for {len(requirements)} services")
        print(f"✅ Loaded {len(requirements)} services")
    except FileNotFoundError:
        logger.error("requirements_initial.json not found")
        print("❌ requirements_initial.json not found")
        print("Run Agent 1 first: python3 agent1_requirements_generator.py")
        sys.exit(1)
    
    print()
    
    # Validate each service
    validated_requirements = {}
    total_rules = 0
    successful = 0
    
    for service, rules in requirements.items():
        logger.info(f"Processing service: {service}")
        print(f"📦 {service}")
        
        validated_rules = []
        
        for rule in rules:
            total_rules += 1
            rule_name = rule['rule_id'].split('.')[-1]
            print(f"   {rule_name}...", end=' ')
            
            validated = validate_function(rule, analyzer)
            
            if validated.get('validated_function', {}).get('error'):
                print(f"❌ {validated['validated_function']['error']}")
                logger.error(f"Validation failed for {rule['rule_id']}")
            else:
                print(f"✅ {validated['validated_function']['azure_operation']}")
                logger.info(f"Validated {rule['rule_id']} -> {validated['validated_function']['azure_operation']}")
                successful += 1
            
            validated_rules.append(validated)
        
        validated_requirements[service] = validated_rules
        print(f"   ✅ {len(validated_rules)} rules validated")
        print()
    
    # Save
    output_file = 'output/requirements_with_functions.json'
    with open(output_file, 'w') as f:
        json.dump(validated_requirements, f, indent=2)
    
    print("=" * 80)
    print(f"✅ Validated {successful}/{total_rules} rules")
    print(f"Saved to: {output_file}")
    print("\nNext: Run Agent 3 (Field Validator)")
    print("=" * 80)
    
    logger.info(f"Agent 2 complete: {successful}/{total_rules} rules validated")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

