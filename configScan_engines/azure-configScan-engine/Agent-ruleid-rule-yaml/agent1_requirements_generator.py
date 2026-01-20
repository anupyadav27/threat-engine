"""
Agent 1: Azure Requirements Generator (AI-Powered)

Uses OpenAI GPT-4o to generate intelligent compliance requirements from Azure metadata.
"""

import yaml
import json
import os
import sys
import time
from openai import OpenAI
from agent_logger import get_logger

logger = get_logger('agent1')

# Service name mapping: metadata service name → Azure SDK catalog service name
# None means no SDK coverage - will use generic fields
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
    'front': 'network',  # Front Door is part of network
    'traffic': 'network',  # Traffic Manager is part of network
    
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
    
    # Services with approximate SDK mappings (based on resource type similarity)
    'cdn': 'network',  # CDN is network-related
    'containerregistry': 'containerservice',  # ACR relates to containers
    'databricks': 'compute',  # Databricks is compute workloads
    'elastic': 'storage',  # Elastic SAN is storage
    'hdinsight': 'compute',  # HDInsight is compute clusters
    'logic': 'web',  # Logic Apps is part of Azure Web/App Services
    'netappfiles': 'storage',  # NetApp Files is storage
    'notification': 'eventhub',  # Notification Hubs uses event patterns
    'security': 'authorization',  # Security/Defender uses authorization patterns
    'synapse': 'sql',  # Synapse Analytics is SQL-based
    'config': 'authorization',  # Azure Policy/Config uses authorization
    
    # Services with Azure SDK clients
    'billing': 'billing',  # azure-mgmt-billing
    'cost': 'costmanagement',  # azure-mgmt-costmanagement
    'data': 'datafactory',  # azure-mgmt-datafactory
    'iot': 'iothub',  # azure-mgmt-iothub
    'purview': 'purview',  # azure-mgmt-purview
    'redis': 'redis',  # azure-mgmt-redis
    'search': 'search',  # azure-mgmt-search
    
    # Services without standard Azure Resource Manager SDK (use monitor as fallback)
    'devops': None,  # Uses azure-devops SDK (not ARM pattern)
    'intune': None,  # Part of Microsoft Graph API
    'power': None,  # Power BI uses separate API
    
    # Missing services that need mappings
    'kusto': 'kusto',  # Azure Data Explorer (Kusto)
    'loganalytics': 'loganalytics',  # Log Analytics
    'managedidentity': 'managedidentity',  # Managed Identity
    'servicebus': 'servicebus',  # Service Bus
    'signalr': 'signalr',  # SignalR
    'storageaccount': 'storage',  # Storage Account (same as storage)
    'streamanalytics': 'streamanalytics',  # Stream Analytics
}

# ALL Azure services with metadata (52 services, excluding 6 completed)
SERVICES_COMPLETED = []  # No services pre-completed - process all

# Process missing services that need rule files
SERVICES_TO_PROCESS = [
    'kusto',
    'loganalytics',
    'managedidentity',
    'servicebus',
    'signalr',
    'storageaccount',
    'streamanalytics'
]


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        logger.warning(f"No metadata directory for {service}")
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('azure.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def generate_requirements_with_ai(rule_id: str, requirement: str, description: str, client, service: str, azure_data: dict):
    """
    Use OpenAI GPT-4o to generate intelligent requirements with Azure SDK field reference.
    """
    
    # Map service name to SDK catalog name
    sdk_service = SERVICE_NAME_MAPPING.get(service, service)
    
    # Handle None mapping (no SDK coverage)
    if sdk_service is None:
        logger.warning(f"Service '{service}' has no SDK mapping - using generic fields")
        sdk_service = 'monitor'  # Fallback to monitor for generic fields
    elif sdk_service != service:
        logger.info(f"Mapped service '{service}' to SDK service '{sdk_service}'")
    
    # Get Azure SDK operations for this service
    service_data = azure_data.get(sdk_service, {})
    
    # Show AI ALL available fields from ALL operations
    # Handle both dict (enhanced catalog) and list (old catalog) formats
    all_available_fields = {}
    for op in service_data.get('independent', [])[:5]:  # Show first 5 independent operations
        op_name = op['python_method']
        fields = op.get('item_fields', {})
        
        # Handle dict format from enhanced catalog
        if isinstance(fields, dict):
            field_list = list(fields.keys())
        else:
            field_list = fields if isinstance(fields, list) else []
        
        if field_list:
            all_available_fields[op_name] = field_list[:25]  # Show up to 25 fields
    
    # Format for prompt
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are an Azure compliance expert analyzing a security rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE AZURE SDK FIELDS FOR {service.upper()}:
{available_fields_summary}

CRITICAL INSTRUCTION: You MUST use ONLY field names from the list above.
The Azure Python SDK returns these exact field names - DO NOT add "properties." prefix.
If a field like "enabled" or "scopes" is in the list, use it directly.

TASK: Select the EXACT field(s) from the list above that match this compliance requirement.

FIELD RULES:
- Use ONLY fields from the AVAILABLE AZURE SDK FIELDS list above
- DO NOT invent field names - use exactly what's in the list
- Boolean checks: Use true/false values
- Status values: "Enabled", "Disabled", "Succeeded", "Failed" (capitalized)
- If no exact match exists, pick the closest semantic match from the list

EXAMPLES:

Rule about soft delete (if "enable_soft_delete" is in the list):
{{
  "fields": [{{
    "conceptual_name": "soft_delete_enabled",
    "azure_sdk_python_field": "enable_soft_delete",
    "operator": "equals",
    "azure_sdk_python_field_expected_values": true
  }}],
  "condition_logic": "single"
}}

Rule about public access (if "public_network_access" is in the list):
{{
  "fields": [{{
    "conceptual_name": "public_access_disabled",
    "azure_sdk_python_field": "public_network_access",
    "operator": "equals",
    "azure_sdk_python_field_expected_values": "Disabled"
  }}],
  "condition_logic": "single"
}}

Rule about severity (if "severity" is in the list):
{{
  "fields": [{{
    "conceptual_name": "severity_check",
    "azure_sdk_python_field": "severity",
    "operator": "in",
    "azure_sdk_python_field_expected_values": [0, 1, 2]
  }}],
  "condition_logic": "single"
}}

Rule about tags (if "tags" is in the list):
{{
  "fields": [{{
    "conceptual_name": "has_required_tags",
    "azure_sdk_python_field": "tags",
    "operator": "not_empty",
    "azure_sdk_python_field_expected_values": null
  }}],
  "condition_logic": "single"
}}

CRITICAL RULES:
- ONLY use fields from the AVAILABLE AZURE SDK FIELDS list - DO NOT invent fields
- DO NOT add "properties." prefix - use the field names EXACTLY as shown in the list
- Use correct JSON types (boolean: true/false, string: "value", number: 90)
- For existence checks, use operator "not_empty" with value null
- If no matching field exists, use the closest semantic match from the available list

Operators: equals, not_equals, exists, not_empty, gt, lt, gte, lte, contains, in

Respond with ONLY valid JSON, no markdown:
{{
  "fields": [{{...}}],
  "condition_logic": "single"
}}"""

    # Get available fields for validation (before retry loop)
    service_data = azure_data.get(sdk_service, {})
    all_available_fields_set = set()
    operation_names = set()
    
    for op in service_data.get('independent', [])[:5]:
        fields = op.get('item_fields', {})
        if isinstance(fields, dict):
            all_available_fields_set.update(fields.keys())
        elif isinstance(fields, list):
            all_available_fields_set.update(fields)
        
        # Collect operation names to filter out
        operation_names.add(op.get('operation', '').lower())
        operation_names.add(op.get('python_method', '').lower())
        operation_names.add(op.get('yaml_action', '').lower())
    
    # Retry logic for API rate limits
    max_retries = 3
    retry_delay = 5  # Increased initial retry delay
    
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                max_tokens=1000,
                temperature=0.1,
                messages=[
                    {"role": "system", "content": "You are an Azure compliance expert. Respond ONLY with valid JSON, no markdown or explanations."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            response_text = response.choices[0].message.content.strip()
            
            # Remove markdown if present
            response_text = response_text.replace('```json', '').replace('```', '').strip()
            
            # Parse JSON
            requirements = json.loads(response_text)
            
            # Clean and validate fields
            cleaned_fields = []
            fields = requirements.get('fields', [])
            
            for field_spec in fields:
                field_name = field_spec.get('azure_sdk_python_field', '')
                
                # Filter out operation names
                if field_name.lower() in operation_names:
                    logger.warning(f"Filtered out operation name '{field_name}' from fields for {rule_id}")
                    continue
                
                # Validate field exists in available fields (if we have them)
                if all_available_fields_set and field_name:
                    if field_name not in all_available_fields_set:
                        # Try fuzzy match
                        from difflib import get_close_matches
                        matches = get_close_matches(field_name, list(all_available_fields_set), n=1, cutoff=0.8)
                        if matches:
                            logger.info(f"Corrected field '{field_name}' to '{matches[0]}' for {rule_id}")
                            field_spec['azure_sdk_python_field'] = matches[0]
                            field_spec['original_field'] = field_name
                        else:
                            logger.warning(f"Field '{field_name}' not found in available fields for {rule_id}, keeping it anyway")
                
                cleaned_fields.append(field_spec)
            
            # If no valid fields after cleaning, add intelligent fallback based on requirement
            if not cleaned_fields:
                logger.warning(f"No valid fields after cleaning for {rule_id}, adding intelligent fallback")
                
                # Use requirement/description to intelligently select fields
                requirement_lower = requirement.lower()
                description_lower = description.lower()
                combined_text = f"{requirement_lower} {description_lower}"
                
                # Field selection based on requirement semantics
                field_keywords = {
                    'enabled': ['enabled', 'enable', 'status', 'state'],
                    'encryption': ['encryption', 'encrypted', 'encrypt', 'cmk', 'key'],
                    'access': ['access', 'public', 'private', 'network', 'endpoint'],
                    'rbac': ['rbac', 'role', 'permission', 'policy', 'authorization'],
                    'logging': ['logging', 'log', 'audit', 'monitor', 'diagnostic'],
                    'backup': ['backup', 'retention', 'recovery', 'restore'],
                    'tags': ['tag', 'label', 'metadata'],
                    'location': ['location', 'region', 'zone'],
                    'name': ['name', 'identifier'],
                    'type': ['type', 'kind', 'category']
                }
                
                selected_field = None
                if all_available_fields_set:
                    # Try to match requirement keywords to available fields
                    for keyword, field_candidates in field_keywords.items():
                        if any(kw in combined_text for kw in field_candidates):
                            # Look for matching fields
                            for candidate in field_candidates:
                                # Exact match
                                if candidate in all_available_fields_set:
                                    selected_field = candidate
                                    break
                                # Partial match (field contains keyword)
                                for field in all_available_fields_set:
                                    if candidate in field.lower() or field.lower() in candidate:
                                        selected_field = field
                                        break
                                if selected_field:
                                    break
                        if selected_field:
                            break
                    
                    # If no semantic match, use common meaningful fields
                    if not selected_field:
                        preferred_fields = ['enabled', 'status', 'properties', 'id', 'name', 'type', 'location']
                        for pref_field in preferred_fields:
                            if pref_field in all_available_fields_set:
                                selected_field = pref_field
                                break
                    
                    # Last resort: use first available field
                    if not selected_field and all_available_fields_set:
                        selected_field = list(all_available_fields_set)[0]
                
                # Add the selected field
                if selected_field:
                    cleaned_fields.append({
                        "conceptual_name": f"{selected_field}_check",
                        "azure_sdk_python_field": selected_field,
                        "operator": "exists",
                        "azure_sdk_python_field_expected_values": None
                    })
                else:
                    # Absolute last resort: generic 'id'
                    cleaned_fields.append({
                        "conceptual_name": "resource_exists",
                        "azure_sdk_python_field": "id",
                        "operator": "exists",
                        "azure_sdk_python_field_expected_values": None
                    })
            
            requirements['fields'] = cleaned_fields
            logger.info(f"AI generated {len(cleaned_fields)} fields for {rule_id} (after cleaning)")
            
            # Delay to avoid rate limits (increased to reduce connection errors)
            time.sleep(1.5)
            
            return requirements
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"API error for {rule_id} (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay *= 2.5  # Exponential backoff (increased multiplier)
            else:
                logger.error(f"AI generation error for {rule_id} after {max_retries} attempts: {e}")
                # Return a basic fallback with proper field
                # Try to get available fields for better fallback
                service_data = azure_data.get(sdk_service, {})
                fallback_field = "id"  # Default
                for op in service_data.get('independent', [])[:1]:
                    fields = op.get('item_fields', {})
                    if isinstance(fields, dict) and fields:
                        fallback_field = list(fields.keys())[0]
                        break
                    elif isinstance(fields, list) and fields:
                        fallback_field = fields[0]
                        break
                
                return {
                    "fields": [{
                        "conceptual_name": "basic_check",
                        "azure_sdk_python_field": fallback_field,
                        "operator": "exists",
                        "azure_sdk_python_field_expected_values": None
                    }],
                    "condition_logic": "single",
                    "error": str(e)
                }


def main():
    # Check for OpenAI API key
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        logger.error("OPENAI_API_KEY not set")
        print("❌ OPENAI_API_KEY not set")
        print("Set it with: export OPENAI_API_KEY='your-key'")
        sys.exit(1)
    
    # Strip whitespace/newlines from API key
    api_key = api_key.strip()
    client = OpenAI(api_key=api_key)
    
    # Load Azure SDK catalog
    logger.info("Loading Azure SDK catalog...")
    print("Loading Azure SDK catalog...")
    with open('azure_sdk_dependencies_with_python_names.json') as f:
        azure_data = json.load(f)
    logger.info("Azure SDK catalog loaded")
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: Azure Requirements Generator (AI-Powered with GPT-4o)")
    print("=" * 80)
    
    # Load existing requirements to resume
    output_file = 'output/requirements_initial.json'
    all_requirements = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                all_requirements = json.load(f)
            print(f"📂 Loaded existing data: {len(all_requirements)} services")
            logger.info(f"Resuming from existing file: {len(all_requirements)} services")
        except Exception as e:
            logger.warning(f"Could not load existing file: {e}")
            print(f"⚠️  Could not load existing file, starting fresh")
    
    print(f"Processing {len(SERVICES_TO_PROCESS)} services (excluding {len(SERVICES_COMPLETED)} completed)")
    print()
    
    total_rules = sum(len(all_requirements.get(s, [])) for s in all_requirements)
    total_fields = sum(sum(len(r['ai_generated_requirements'].get('fields', [])) for r in all_requirements.get(s, [])) for s in all_requirements)
    
    for service in SERVICES_TO_PROCESS:
        logger.info(f"Processing service: {service}")
        print(f"\n📦 {service}")
        
        # Check if service is already complete
        existing_rules = all_requirements.get(service, [])
        existing_rule_ids = {r['rule_id'] for r in existing_rules}
        
        if existing_rules:
            print(f"   📋 Found {len(existing_rules)} existing rules, checking for updates...")
        
        metadata_files = get_metadata_files(service)
        
        if not metadata_files:
            logger.warning(f"No metadata files found for {service}")
            print(f"   ⚠️  No metadata files")
            continue
        
        # Start with existing requirements or empty list
        service_requirements = existing_rules.copy()
        new_rules_count = 0
        
        for idx, metadata_file in enumerate(metadata_files, 1):
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            # Skip if already processed
            if rule_id in existing_rule_ids:
                continue
            
            logger.info(f"[{idx}/{len(metadata_files)}] Generating for {rule_id}")
            print(f"   [{idx}/{len(metadata_files)}] {rule_id.split('.')[-1][:40]}...", end=' ', flush=True)
            
            # Generate requirements with AI
            ai_reqs = generate_requirements_with_ai(rule_id, requirement, description, client, service, azure_data)
            
            num_fields = len(ai_reqs.get('fields', []))
            if num_fields > 0:
                print(f"✅ {num_fields} fields")
                total_fields += num_fields
            else:
                print("❌ No fields")
            
            service_requirements.append({
                'rule_id': rule_id,
                'service': service,
                'requirement': requirement,
                'description': description,
                'severity': metadata.get('severity', 'medium'),
                'ai_generated_requirements': ai_reqs
            })
            
            new_rules_count += 1
            total_rules += 1
            
            # Save incrementally after each rule (to avoid data loss)
            all_requirements[service] = service_requirements
            os.makedirs('output', exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(all_requirements, f, indent=2)
        
        all_requirements[service] = service_requirements
        if new_rules_count > 0:
            print(f"   ✅ {new_rules_count} new rules added ({len(service_requirements)} total), {sum(len(r['ai_generated_requirements'].get('fields', [])) for r in service_requirements)} total fields")
        else:
            print(f"   ✅ Service already complete: {len(service_requirements)} rules")
        logger.info(f"Service {service} complete: {len(service_requirements)} rules")
        
        # Save after each service completes
        os.makedirs('output', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ AI Generated {total_rules} requirements with {total_fields} fields")
    print(f"   Services: {len(all_requirements)}")
    print(f"   Saved to: {output_file}")
    print()
    print("Next: Run Agent 2 (Function Validator)")
    print("=" * 80)
    
    logger.info(f"Agent 1 complete: {total_rules} requirements, {total_fields} fields generated")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()
