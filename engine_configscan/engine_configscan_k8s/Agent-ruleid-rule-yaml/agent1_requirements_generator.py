"""
Agent 1: K8s Requirements Generator (AI-Powered)
"""

import yaml
import json
import os
import sys
from openai import OpenAI
from agent_logger import get_logger

logger = get_logger('agent1')

# K8s components/resources to process
RESOURCES_TO_PROCESS = ['pod', 'service', 'deployment', 'namespace', 'secret', 'configmap', 'networkpolicy', 'ingress']


def get_metadata_files(resource: str):
    """Get all metadata YAML files for a K8s resource/component"""
    # K8s uses different directory structure - check multiple locations
    possible_dirs = [
        f"../services/{resource}/metadata",
        f"../services/{resource}",
    ]
    
    for metadata_dir in possible_dirs:
        if os.path.exists(metadata_dir):
            files = []
            for file in os.listdir(metadata_dir):
                if file.endswith('.yaml') and file.startswith('k8s.'):
                    files.append(os.path.join(metadata_dir, file))
            if files:
                return files
    
    logger.warning(f"No metadata directory for {resource}")
    return []


def generate_requirements_with_ai(rule_id: str, requirement: str, description: str, client, resource: str, k8s_data: dict):
    """Use OpenAI GPT-4o to generate intelligent requirements"""
    
    resource_data = k8s_data.get(resource, {})
    all_available_fields = {}
    
    for op in resource_data.get('operations', [])[:3]:
        if op.get('operation') in ['list', 'get']:
            op_name = op['operation']
            fields = op.get('item_fields', {})
            if fields:
                all_available_fields[op_name] = list(fields.keys())[:15]
    
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are a Kubernetes compliance expert analyzing a security rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE K8S API FIELDS FOR {resource.upper()}:
{available_fields_summary}

TASK: Determine the EXACT field(s) to check from the K8s API list above.

K8S-SPECIFIC PATTERNS:
- Pod structure: spec.containers[], spec.securityContext
- Security fields: spec.hostNetwork, spec.hostPID, spec.hostIPC
- Container security: spec.containers[].securityContext.runAsNonRoot, privileged
- Common fields: metadata.name, metadata.namespace, metadata.labels

RESPONSE FORMAT (JSON only):
{{
  "fields": [{{
    "conceptual_name": "field_purpose",
    "k8s_field": "spec.hostNetwork",
    "operator": "equals",
    "k8s_field_expected_values": false
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
                {"role": "system", "content": "You are a Kubernetes compliance expert. Respond ONLY with valid JSON."},
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
            "fields": [{"conceptual_name": "basic_check", "k8s_field": "metadata.name", "operator": "exists", "k8s_field_expected_values": None}],
            "condition_logic": "single"
        }


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    print("Loading K8s API catalog...")
    with open('k8s_api_catalog_from_sdk.json') as f:
        k8s_data = json.load(f)
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: K8s Requirements Generator")
    print("=" * 80)
    
    all_requirements = {}
    total_rules = 0
    total_fields = 0
    
    for resource in RESOURCES_TO_PROCESS:
        print(f"\n📦 {resource}")
        metadata_files = get_metadata_files(resource)
        
        if not metadata_files:
            print(f"   ⚠️  No metadata files")
            continue
        
        resource_requirements = []
        
        for idx, metadata_file in enumerate(metadata_files, 1):
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            print(f"   [{idx}/{len(metadata_files)}] {rule_id.split('.')[-1][:40]}...", end=' ', flush=True)
            
            ai_reqs = generate_requirements_with_ai(rule_id, requirement, description, client, resource, k8s_data)
            num_fields = len(ai_reqs.get('fields', []))
            print(f"✅ {num_fields} fields" if num_fields > 0 else "❌ No fields")
            total_fields += num_fields
            
            resource_requirements.append({
                'rule_id': rule_id,
                'resource': resource,
                'requirement': requirement,
                'description': description,
                'severity': metadata.get('severity', 'medium'),
                'ai_generated_requirements': ai_reqs
            })
            
            total_rules += 1
        
        all_requirements[resource] = resource_requirements
        print(f"   ✅ {len(resource_requirements)} rules")
    
    os.makedirs('output', exist_ok=True)
    output_file = 'output/requirements_initial.json'
    with open(output_file, 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {total_rules} requirements with {total_fields} fields")
    print("=" * 80)


if __name__ == '__main__':
    main()
