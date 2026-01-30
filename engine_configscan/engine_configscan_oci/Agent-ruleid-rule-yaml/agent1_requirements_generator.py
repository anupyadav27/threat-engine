"""
Agent 1: OCI Requirements Generator (AI-Powered)

Uses OpenAI GPT-4o to generate intelligent compliance requirements from OCI metadata.
"""

import yaml
import json
import os
import sys
from openai import OpenAI
from agent_logger import get_logger

logger = get_logger('agent1')

SERVICES_TO_PROCESS = ['compute', 'object_storage', 'virtual_network', 'identity', 'block_storage', 'load_balancer', 'database']


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        logger.warning(f"No metadata directory for {service}")
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('oci.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def generate_requirements_with_ai(rule_id: str, requirement: str, description: str, client, service: str, oci_data: dict):
    """Use OpenAI GPT-4o to generate intelligent requirements with OCI SDK field reference"""
    
    service_data = oci_data.get(service, {})
    
    all_available_fields = {}
    for op in service_data.get('operations', [])[:5]:
        op_name = op['operation']
        fields = op.get('item_fields', {})
        if fields:
            all_available_fields[op_name] = list(fields.keys())[:15]
    
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are an OCI compliance expert analyzing a security rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE OCI SDK FIELDS FOR {service.upper()}:
{available_fields_summary}

TASK: Determine the EXACT field(s) to check from the OCI SDK list above.

OCI-SPECIFIC PATTERNS:
- Common fields: id (OCID), compartment_id, display_name, lifecycle_state
- Tags: freeform_tags, defined_tags
- Lifecycle states: CREATING, ACTIVE, INACTIVE, UPDATING, DELETING, DELETED, FAILED
- Boolean checks: Use true/false

RESPONSE FORMAT (JSON only):
{{
  "fields": [{{
    "conceptual_name": "field_purpose",
    "oci_sdk_field": "actual_field_name",
    "operator": "equals",
    "oci_sdk_field_expected_values": value
  }}],
  "condition_logic": "single"
}}

Operators: equals, not_equals, exists, not_empty, gt, lt, gte, lte, contains, in
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1000,
            temperature=0.1,
            messages=[
                {"role": "system", "content": "You are an OCI compliance expert. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = response.choices[0].message.content.strip().replace('```json', '').replace('```', '').strip()
        requirements = json.loads(response_text)
        logger.info(f"AI generated {len(requirements.get('fields', []))} fields for {rule_id}")
        return requirements
        
    except Exception as e:
        logger.error(f"AI generation error for {rule_id}: {e}")
        return {
            "fields": [{"conceptual_name": "basic_check", "oci_sdk_field": "id", "operator": "exists", "oci_sdk_field_expected_values": None}],
            "condition_logic": "single"
        }


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    print("Loading OCI SDK catalog...")
    with open('oci_sdk_catalog_enhanced.json') as f:
        oci_data = json.load(f)
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: OCI Requirements Generator")
    print("=" * 80)
    
    all_requirements = {}
    total_rules = 0
    total_fields = 0
    
    for service in SERVICES_TO_PROCESS:
        print(f"\n📦 {service}")
        metadata_files = get_metadata_files(service)
        
        if not metadata_files:
            print(f"   ⚠️  No metadata files")
            continue
        
        service_requirements = []
        
        for idx, metadata_file in enumerate(metadata_files, 1):
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            print(f"   [{idx}/{len(metadata_files)}] {rule_id.split('.')[-1][:40]}...", end=' ', flush=True)
            
            ai_reqs = generate_requirements_with_ai(rule_id, requirement, description, client, service, oci_data)
            num_fields = len(ai_reqs.get('fields', []))
            print(f"✅ {num_fields} fields" if num_fields > 0 else "❌ No fields")
            total_fields += num_fields
            
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
        print(f"   ✅ {len(service_requirements)} rules")
    
    os.makedirs('output', exist_ok=True)
    output_file = 'output/requirements_initial.json'
    with open(output_file, 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {total_rules} requirements with {total_fields} fields")
    print(f"   Saved to: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()
