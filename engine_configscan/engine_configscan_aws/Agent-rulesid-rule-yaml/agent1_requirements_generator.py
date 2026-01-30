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
# Comprehensive mapping to handle all service name variations
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
    'edr': 'guardduty',
    'kinesisvideostreams': 'kinesisvideo',  # kinesisvideo is the boto3 service name
    'qldb': 'qldb',  # Will check if exists, may need alternative
    'timestream': 'timestream-query',  # Use query for discovery operations
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
    Use AI to determine requirements with boto3 function and field reference.
    Enhanced to suggest function name, function type, and fields.
    
    Returns format:
    {
        "suggested_function": "list_user_pools",
        "function_type": "independent",
        "fields": [{
            "conceptual_name": "status_check",
            "boto3_python_field": "status", 
            "operator": "equals",
            "boto3_python_field_expected_values": "ACTIVE"
        }]
    }
    """
    
    # Get boto3 operations for this service (with name mapping)
    boto3_service = get_boto3_service_name(service)
    service_data = boto3_data.get(boto3_service, {})
    
    # Handle different data structures
    if isinstance(service_data, dict):
        # Old structure: {'independent': [...], 'dependent': [...]}
        service_ops = service_data.get('independent', []) + service_data.get('dependent', [])
    elif isinstance(service_data, list):
        # New structure: direct list of operations
        service_ops = service_data
    else:
        return {"fields": [], "condition_logic": "unknown", "error": "No boto3 operations found"}
    
    if not service_ops:
        return {"fields": [], "condition_logic": "unknown", "error": "No boto3 operations found"}
    
    # Separate independent and dependent functions
    independent_ops = []
    dependent_ops = []
    
    for op in service_ops:
        if not isinstance(op, dict):
            continue
            
        op_name = op.get('python_method', '')
        if not op_name:
            continue
        
        required_params = op.get('required_params', [])
        is_independent = len(required_params) == 0
        
        if is_independent:
            independent_ops.append(op)
        else:
            dependent_ops.append(op)
    
    # Identify PRIMARY independent functions (LIST/GET/DESCRIBE only)
    primary_independent = []
    other_independent = []
    
    for op in independent_ops:
        op_name = op.get('python_method', '').lower()
        if op_name.startswith(('list_', 'get_', 'describe_')):
            primary_independent.append(op)
        else:
            other_independent.append(op)
    
    # Build function metadata for AI
    # Priority: Primary Independent > Other Independent > Dependent
    functions_metadata = {}
    
    # 1. Primary Independent Functions (highest priority)
    for op in primary_independent:
        op_name = op.get('python_method', '')
        op_lower = op_name.lower()
        
        func_type = 'LIST' if op_lower.startswith('list_') else \
                   'DESCRIBE' if op_lower.startswith('describe_') else \
                   'GET' if op_lower.startswith('get_') else 'UNKNOWN'
        
        functions_metadata[op_name] = {
            "priority": "PRIMARY_INDEPENDENT",
            "type": func_type,
            "independent": True,
            "required_params": [],
            "item_fields": op.get('item_fields', [])[:15],
            "description": f"Primary {func_type} function - no dependencies"
        }
    
    # 2. Other Independent Functions
    for op in other_independent:
        op_name = op.get('python_method', '')
        functions_metadata[op_name] = {
            "priority": "INDEPENDENT",
            "type": "OTHER",
            "independent": True,
            "required_params": [],
            "item_fields": op.get('item_fields', [])[:15],
            "description": "Independent function (not LIST/GET/DESCRIBE)"
        }
    
    # 3. Dependent Functions (with dependency info)
    for op in dependent_ops:
        op_name = op.get('python_method', '')
        op_lower = op_name.lower()
        required_params = op.get('required_params', [])
        
        func_type = 'LIST' if op_lower.startswith('list_') else \
                   'DESCRIBE' if op_lower.startswith('describe_') else \
                   'GET' if op_lower.startswith('get_') else 'OTHER'
        
        # Find which primary independent function could provide the required params
        # This helps AI understand the dependency path
        suggested_parent = None
        for param in required_params[:1]:  # Check first required param
            param_lower = param.lower()
            # Try to match param to primary independent function
            for primary_op in primary_independent:
                primary_name = primary_op.get('python_method', '').lower()
                primary_fields = [f.lower() for f in primary_op.get('item_fields', [])]
                
                # Check if param name matches function name or fields
                if param_lower.replace('id', '').replace('arn', '').replace('name', '') in primary_name:
                    suggested_parent = primary_op.get('python_method', '')
                    break
                # Check if param matches a field from primary function
                for field in primary_fields:
                    if param_lower.endswith(field) or field in param_lower:
                        suggested_parent = primary_op.get('python_method', '')
                        break
                if suggested_parent:
                    break
            if suggested_parent:
                break
        
        functions_metadata[op_name] = {
            "priority": "DEPENDENT",
            "type": func_type,
            "independent": False,
            "required_params": required_params[:5],
            "item_fields": op.get('item_fields', [])[:15],
            "suggested_parent_function": suggested_parent,  # Help AI understand dependency
            "description": f"Dependent {func_type} function - needs: {', '.join(required_params[:2])}"
        }
    
    # Format for prompt (grouped by priority)
    # The JSON keys are the function names - AI must use these exact names
    functions_summary = json.dumps(functions_metadata, indent=2)
    
    # Create a simple list of all function names for clarity
    all_function_names_list = list(functions_metadata.keys())
    function_names_summary = "\n".join([f"  - {name}" for name in all_function_names_list[:50]])  # Limit to 50 for token efficiency
    if len(all_function_names_list) > 50:
        function_names_summary += f"\n  ... and {len(all_function_names_list) - 50} more (see full details below)"
    
    prompt = f"""You are analyzing an AWS {service} compliance rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE BOTO3 FUNCTIONS FOR {service.upper()}:
The function names (keys in JSON below) are the EXACT names you must use:

AVAILABLE FUNCTION NAMES:
{function_names_summary}

FULL FUNCTION DETAILS (with fields, types, dependencies):
{functions_summary}

CRITICAL: You MUST select function names ONLY from the AVAILABLE FUNCTION NAMES list above. 
- Use the EXACT function name as shown (e.g., "list_user_pools", "get_rest_apis")
- Do NOT invent, guess, or modify function names
- Do NOT use variations like "listUserPools" or "list-user-pools"
- The function name must match EXACTLY one of the names in the list above

TASK: 
1. Suggest the BEST function(s) for this requirement
2. If field is in PRIMARY_INDEPENDENT function → use that directly
3. If field is in DEPENDENT function → suggest BOTH:
   - The dependent function (to get the field)
   - The primary independent function (to get required params)
4. Determine function type (independent/dependent)
5. Suggest which fields from chosen function(s) to check
6. Provide field operators and expected values

FUNCTION PRIORITY:
- PRIMARY_INDEPENDENT (LIST/GET/DESCRIBE, no dependencies) - HIGHEST PRIORITY
- INDEPENDENT (other functions, no dependencies)
- DEPENDENT (LIST/GET/DESCRIBE, needs parent function)
- Other dependent functions - LOWEST PRIORITY

IMPORTANT:
- ALWAYS prefer PRIMARY_INDEPENDENT functions when possible
- If field is only in DEPENDENT function, suggest dependency path:
  - Primary function → Dependent function → Field
- Prefer LIST/GET/DESCRIBE over UPDATE/CREATE/DELETE
- Check suggested_parent_function for dependent functions to understand dependency
- suggested_function and parent_function MUST be exact function names from the list above

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
  "suggested_function": "function_name_from_list_above",
  "function_type": "independent" or "dependent",
  "parent_function": "primary_function_name_if_dependent" or null,
  "fields": [
    {{
      "conceptual_name": "your_description",
      "boto3_python_field": "FieldNameFromChosenFunction",
      "operator": "equals",
      "boto3_python_field_expected_values": actual_typed_value
    }}
  ],
  "condition_logic": "single"
}}

CRITICAL - FUNCTION NAME VALIDATION:
- suggested_function: MUST be EXACT function name from the functions list above (check python_method field)
- parent_function: MUST be EXACT function name from the functions list above (if dependent)
- DO NOT invent function names - only use names that appear in the functions list
- If you cannot find a suitable function in the list, set suggested_function to null

OTHER REQUIREMENTS:
- function_type: "independent" if no required_params, "dependent" if needs parent
- parent_function: 
  * If function_type is "independent" → set to null
  * If function_type is "dependent" → suggest PRIMARY_INDEPENDENT function that provides required_params
  * Use suggested_parent_function from function metadata if available
  * parent_function MUST exist in the functions list above
- boto3_python_field: Must be from item_fields of suggested_function
- Use "all" for AND logic, "any" for OR logic in condition_logic

EXAMPLES:
Independent function:
{{
  "suggested_function": "list_user_pools",
  "function_type": "independent",
  "parent_function": null,
  "fields": [...]
}}

Dependent function:
{{
  "suggested_function": "describe_user_pool",
  "function_type": "dependent",
  "parent_function": "list_user_pools",
  "fields": [...]
}}"""

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
        
        # VALIDATE: Ensure suggested_function and function_type exist
        # Also validate that function names exist in our boto3 data
        all_function_names = set(functions_metadata.keys())
        
        if 'suggested_function' not in requirements:
            requirements['suggested_function'] = None
            requirements['function_type'] = 'unknown'
            requirements['parent_function'] = None
        else:
            # Validate suggested_function exists in our data
            suggested_func = requirements.get('suggested_function')
            if suggested_func and suggested_func not in all_function_names:
                print(f"      ⚠️  Invalid function name: {suggested_func}, setting to null")
                requirements['suggested_function'] = None
                requirements['function_type'] = 'unknown'
        
        if 'function_type' not in requirements:
            requirements['function_type'] = 'unknown'
        
        if 'parent_function' not in requirements:
            # Set to null if independent, keep AI suggestion if dependent
            if requirements.get('function_type') == 'independent':
                requirements['parent_function'] = None
            else:
                requirements['parent_function'] = None  # Will be validated in Agent 2
        else:
            # Validate parent_function exists in our data
            parent_func = requirements.get('parent_function')
            if parent_func and parent_func not in all_function_names:
                print(f"      ⚠️  Invalid parent function: {parent_func}, setting to null")
                requirements['parent_function'] = None
        
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
    print("AGENT 1: Enhanced Requirements Generator (GPT-4o)")
    print("=" * 80)
    print("AI suggests: function + function_type + fields")
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
                func_name = ai_reqs.get('suggested_function', 'unknown')
                func_type = ai_reqs.get('function_type', 'unknown')
                parent_func = ai_reqs.get('parent_function')
                if parent_func:
                    print(f"✅ {func_name} ({func_type}, parent: {parent_func}) - {len(ai_reqs['fields'])} fields")
                else:
                    print(f"✅ {func_name} ({func_type}) - {len(ai_reqs['fields'])} fields")
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
