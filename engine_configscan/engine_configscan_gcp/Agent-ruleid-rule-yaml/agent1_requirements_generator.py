"""
Agent 1: GCP Requirements Generator (AI-Powered)

Uses OpenAI GPT-4o to generate intelligent compliance requirements from GCP metadata.
Adapted from Azure agent but for GCP API structure.
"""

import yaml
import json
import os
import sys
from openai import OpenAI
from agent_logger import get_logger

logger = get_logger('agent1')

# GCP services to process (start with high-priority services)
SERVICES_TO_PROCESS = [
    # High priority
    'storage', 'compute', 'container', 'iam', 'cloudkms', 'secretmanager',
    # Medium priority
    'pubsub', 'logging', 'monitoring', 'bigquery', 'sqladmin',
    # Lower priority
    'dns', 'cloudfunctions', 'run', 'securitycenter'
]


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        logger.warning(f"No metadata directory for {service}")
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('gcp.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def generate_requirements_with_ai(rule_id: str, requirement: str, description: str, client, service: str, gcp_data: dict):
    """
    Use OpenAI GPT-4o to generate intelligent requirements with GCP API field reference.
    """
    
    # Get GCP API operations for this service
    service_data = gcp_data.get(service, {})
    
    # Show AI available fields from operations
    all_available_fields = {}
    for resource_name, resource_data in service_data.get('resources', {}).items():
        for op in resource_data.get('independent', [])[:3]:  # First 3 operations per resource
            op_name = op['python_method']
            fields = op.get('item_fields', {})
            if fields:
                # Show field names only (not full nested structure for brevity)
                field_names = list(fields.keys())[:15]
                all_available_fields[f"{resource_name}.{op_name}"] = field_names
    
    # Format for prompt
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are a GCP compliance expert analyzing a security rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE GCP API FIELDS FOR {service.upper()}:
{available_fields_summary}

TASK: Determine the EXACT field(s) to check from the GCP API list above.

GCP-SPECIFIC PATTERNS YOU MUST KNOW:
- Nested objects: Use dot notation (e.g., "iamConfiguration.publicAccessPrevention")
- Common top-level fields: kind, id, name, selfLink, labels
- Boolean checks: Use true/false (not "true"/"false" strings)
- Enum values: Often uppercase ("ENFORCED", "ENABLED", "ACTIVE")
- List responses: Usually have "items" field

EXAMPLES:

Rule about public access prevention:
{{
  "fields": [{{
    "conceptual_name": "public_access_prevented",
    "gcp_api_field": "iamConfiguration.publicAccessPrevention",
    "operator": "equals",
    "gcp_api_field_expected_values": "enforced"
  }}],
  "condition_logic": "single"
}}

Rule about encryption:
{{
  "fields": [{{
    "conceptual_name": "encryption_enabled",
    "gcp_api_field": "encryption.defaultKmsKeyName",
    "operator": "exists",
    "gcp_api_field_expected_values": null
  }}],
  "condition_logic": "single"
}}

Rule about versioning:
{{
  "fields": [{{
    "conceptual_name": "versioning_enabled",
    "gcp_api_field": "versioning.enabled",
    "operator": "equals",
    "gcp_api_field_expected_values": true
  }}],
  "condition_logic": "single"
}}

CRITICAL RULES:
- Pick REAL fields from the available fields list above
- Use dot notation for nested fields
- Use correct JSON types (boolean: true/false, string: "value", number: 90)
- For existence checks, use operator "exists" with value null
- If unsure, check if field mentions encryption, access, enabled, state

Operators: equals, not_equals, exists, not_empty, gt, lt, gte, lte, contains, in

Respond with ONLY valid JSON, no markdown:
{{
  "fields": [{{...}}],
  "condition_logic": "single"
}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1000,
            temperature=0.1,
            messages=[
                {"role": "system", "content": "You are a GCP compliance expert. Respond ONLY with valid JSON, no markdown or explanations."},
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = response.choices[0].message.content.strip()
        
        # Remove markdown if present
        response_text = response_text.replace('```json', '').replace('```', '').strip()
        
        # Parse JSON
        requirements = json.loads(response_text)
        
        logger.info(f"AI generated {len(requirements.get('fields', []))} fields for {rule_id}")
        
        return requirements
        
    except Exception as e:
        logger.error(f"AI generation error for {rule_id}: {e}")
        # Return a basic fallback
        return {
            "fields": [{
                "conceptual_name": "basic_check",
                "gcp_api_field": "id",
                "operator": "exists",
                "gcp_api_field_expected_values": null
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
    
    client = OpenAI(api_key=api_key)
    
    # Load GCP API catalog
    logger.info("Loading GCP API catalog...")
    print("Loading GCP API catalog...")
    with open('gcp_api_dependencies_fully_enhanced.json') as f:
        gcp_data = json.load(f)
    logger.info("GCP API catalog loaded")
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: GCP Requirements Generator (AI-Powered with GPT-4o)")
    print("=" * 80)
    print(f"Processing {len(SERVICES_TO_PROCESS)} services")
    print()
    
    all_requirements = {}
    total_rules = 0
    total_fields = 0
    
    for service in SERVICES_TO_PROCESS:
        logger.info(f"Processing service: {service}")
        print(f"\n📦 {service}")
        
        metadata_files = get_metadata_files(service)
        
        if not metadata_files:
            logger.warning(f"No metadata files found for {service}")
            print(f"   ⚠️  No metadata files")
            continue
        
        service_requirements = []
        
        for idx, metadata_file in enumerate(metadata_files, 1):
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            logger.info(f"[{idx}/{len(metadata_files)}] Generating for {rule_id}")
            print(f"   [{idx}/{len(metadata_files)}] {rule_id.split('.')[-1][:40]}...", end=' ', flush=True)
            
            # Generate requirements with AI
            ai_reqs = generate_requirements_with_ai(rule_id, requirement, description, client, service, gcp_data)
            
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
            
            total_rules += 1
        
        all_requirements[service] = service_requirements
        print(f"   ✅ {len(service_requirements)} rules, {sum(len(r['ai_generated_requirements'].get('fields', [])) for r in service_requirements)} total fields")
        logger.info(f"Service {service} complete: {len(service_requirements)} rules")
    
    # Save
    os.makedirs('output', exist_ok=True)
    output_file = 'output/requirements_initial.json'
    with open(output_file, 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ AI Generated {total_rules} requirements with {total_fields} fields")
    print(f"   Services: {len(all_requirements)}")
    print(f"   Saved to: {output_file}")
    print()
    print("Next: Run Agent 2 (Operation Validator)")
    print("=" * 80)
    
    logger.info(f"Agent 1 complete: {total_rules} requirements, {total_fields} fields generated")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

