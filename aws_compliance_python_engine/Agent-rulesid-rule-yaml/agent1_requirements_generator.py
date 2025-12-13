"""
Agent 1: Simple Requirements Generator

ONLY generates the requirement format:
{
    "rule_id": "...",
    "discovery": "...",
    "fields": [{"name": "status", "operator": "equals", "value": "ACTIVE"}],
    "condition_logic": "single"
}

AI just interprets what the rule SHOULD check based on:
- Rule name pattern
- Requirement description

Uses simple Python field naming (lowercase, underscores).
Agent 2 will map to boto3 functions.
"""

import yaml
import json
import os
import sys
from openai import OpenAI


# Missing 20 services that have metadata but no YAMLs generated
SERVICES_TO_PROCESS = ['cognito','costexplorer','directoryservice','drs','edr','eip','elastic','eventbridge','fargate','identitycenter','kinesisfirehose','kinesisvideostreams','macie','networkfirewall','parameterstore','qldb','timestream','vpc','vpcflowlogs','workflows']

# Service name mapping: metadata name -> boto3 service name
SERVICE_NAME_MAPPING = {
    'cognito': 'cognito-idp',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'workflows': 'stepfunctions',
    'parameterstore': 'ssm',
    'elastic': 'es',
    'eip': 'ec2',
    'eventbridge': 'events',
    'fargate': 'ecs',
    'kinesisfirehose': 'firehose',
    'costexplorer': 'ce',
    'directoryservice': 'ds',
    'identitycenter': 'sso',
    'macie': 'macie2',
    'networkfirewall': 'network-firewall',
}


def get_boto3_service_name(service: str) -> str:
    """Map metadata service name to boto3 service name"""
    return SERVICE_NAME_MAPPING.get(service, service)


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('aws.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def generate_requirements(rule_id: str, requirement: str, description: str, client, service: str, boto3_data: dict):
    """
    Use AI to determine requirements with boto3 field reference.
    Forces AI to provide BOTH conceptual field and actual boto3 field name.
    
    Returns format:
    {
        "fields": [{
            "conceptual_name": "status_check",
            "boto3_python_field": "status", 
            "operator": "equals",
            "value": "ACTIVE"
        }]
    }
    """
    
    # Get boto3 operations for this service (with name mapping)
    boto3_service = get_boto3_service_name(service)
    service_data = boto3_data.get(boto3_service, {})
    
    # Show AI ALL available fields from ALL operations
    all_available_fields = {}
    for op in service_data.get('independent', []) + service_data.get('dependent', []):
        op_name = op['python_method']
        fields = op.get('item_fields', [])
        if fields:
            all_available_fields[op_name] = fields[:15]  # Limit to 15 fields per operation
    
    # Format for prompt
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are analyzing an AWS {service} compliance rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE BOTO3 FIELDS FOR {service.upper()}:
{available_fields_summary}

TASK: Determine which field(s) from the list above to check.

You MUST provide for EACH field:
1. conceptual_name: Your interpretation of what this field means
2. boto3_python_field: EXACT field name from the boto3 operations list above
3. operator: The comparison operator
4. boto3_python_field_expected_values: The ACTUAL expected value(s) with CORRECT TYPE

VALUE TYPES - MUST USE CORRECT JSON TYPE:
- Status/State checks → String: "ACTIVE", "ENABLED", "Enabled", "ISSUED"
- Boolean flags → Boolean: true or false (not "true" or "false")
- Counts/Numbers → Number: 0, 1, 2048 (not "0" or "1")
- Empty checks → Empty array: [] (not "[]" or "empty")
- List checks → Array: ["value1", "value2"]
- Null/existence → null (use with "exists" operator)

EXAMPLES:

Checking if analyzer is active:
{{
  "conceptual_name": "analyzer_status",
  "boto3_python_field": "status",
  "operator": "equals",
  "boto3_python_field_expected_values": "ACTIVE"
}}

Checking for no findings (empty list):
{{
  "conceptual_name": "findings_list",
  "boto3_python_field": "findings",
  "operator": "equals",
  "boto3_python_field_expected_values": []
}}

Checking if enabled (boolean):
{{
  "conceptual_name": "is_enabled",
  "boto3_python_field": "enabled",
  "operator": "equals",
  "boto3_python_field_expected_values": true
}}

Checking minimum key length (number):
{{
  "conceptual_name": "key_length",
  "boto3_python_field": "KeyAlgorithm",
  "operator": "contains",
  "boto3_python_field_expected_values": "2048"
}}

CRITICAL RULES:
- boto3_python_field: Pick from the available fields list above
- boto3_python_field_expected_values: Use CORRECT JSON type (string/boolean/number/array)
- NO invented values like "NO_FINDINGS" - use [] for empty
- NO string representations of types - use actual types

Operators: equals, exists, gt, lt, gte, lte, contains

FINAL JSON FORMAT (no markdown, no explanations):
{{
  "fields": [
    {{
      "conceptual_name": "your_description",
      "boto3_python_field": "FieldNameFromListAbove",
      "operator": "equals",
      "boto3_python_field_expected_values": actual_typed_value
    }}
  ],
  "condition_logic": "single"
}}

Use "all" for AND logic, "any" for OR logic."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an AWS compliance expert. Respond ONLY with valid JSON, no markdown or explanations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=500
        )
        
        response_text = response.choices[0].message.content.strip()
        
        # Remove markdown if present
        response_text = response_text.replace('```json', '').replace('```', '').strip()
        
        # Parse JSON
        requirements = json.loads(response_text)
        
        # VALIDATE: Ensure all fields have expected_values
        for field in requirements.get('fields', []):
            if 'boto3_python_field_expected_values' not in field:
                # Default based on operator
                operator = field.get('operator', 'exists')
                if operator == 'exists':
                    field['boto3_python_field_expected_values'] = None
                elif operator == 'equals':
                    # Try to infer from field name
                    field_name = field.get('boto3_python_field', '').lower()
                    if 'status' in field_name or 'state' in field_name:
                        field['boto3_python_field_expected_values'] = 'ACTIVE'
                    elif 'enabled' in field_name:
                        field['boto3_python_field_expected_values'] = True
                    else:
                        field['boto3_python_field_expected_values'] = None
                else:
                    field['boto3_python_field_expected_values'] = None
        
        return requirements
        
    except Exception as e:
        print(f"      ⚠️  Error: {e}")
        return {"fields": [], "condition_logic": "unknown", "error": str(e)}


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    # Load boto3 catalog
    print("Loading boto3 catalog...")
    with open('boto3_dependencies_with_python_names.json') as f:
        boto3_data = json.load(f)
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: Requirements Generator (GPT-4o + Boto3 Fields)")
    print("=" * 80)
    print("AI picks from actual boto3 field names")
    print()
    
    all_requirements = {}
    
    for service in SERVICES_TO_PROCESS:
        print(f"\n📦 {service}")
        
        metadata_files = get_metadata_files(service)
        service_requirements = []
        
        for metadata_file in metadata_files:
            with open(metadata_file) as f:
                metadata = yaml.safe_load(f)
            
            rule_id = metadata.get('rule_id', '')
            requirement = metadata.get('requirement', '')
            description = metadata.get('description', '')
            
            print(f"   {rule_id.split('.')[-1]}...", end=' ')
            
            # Generate requirements with boto3 context
            ai_reqs = generate_requirements(rule_id, requirement, description, client, service, boto3_data)
            
            if ai_reqs.get('fields'):
                print(f"✅ {len(ai_reqs['fields'])} fields")
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
        
        all_requirements[service] = service_requirements
        print(f"   ✅ {len(service_requirements)} rules")
    
    # Save
    os.makedirs('output', exist_ok=True)
    with open('output/requirements_initial.json', 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {sum(len(r) for r in all_requirements.values())} requirements")
    print("Saved to: output/requirements_initial.json")
    print("\nNext: Run Agent 2")


if __name__ == '__main__':
    main()
