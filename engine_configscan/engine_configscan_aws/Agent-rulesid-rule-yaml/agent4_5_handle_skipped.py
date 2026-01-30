"""
Agent 4.5: Handle Skipped Rules

For the 12 rules that failed validation, uses AI to find alternative approaches:
- Try different functions
- Use computed fields
- Suggest multi-step discoveries

Input: requirements_validated.json (partial/failed rules)
Output: requirements_enhanced.json (with alternatives)
"""

import json
import os
from typing import Dict, List, Any
from openai import OpenAI


def load_boto3_catalog():
    """Load complete boto3 catalog"""
    with open('boto3_dependencies_with_python_names.json') as f:
        return json.load(f)


def find_alternative_for_skipped_rule(rule: Dict, service: str, boto3_data: Dict, client) -> Dict:
    """
    Use AI to find alternative approach for failed rule.
    """
    rule_id = rule['rule_id']
    requirement = rule.get('requirement', '')
    description = rule.get('description', '')
    
    # Get failed fields
    failed_fields = []
    field_validation = rule.get('field_validation', {})
    for field_name, validation in field_validation.items():
        if not validation.get('exists'):
            failed_fields.append(field_name)
    
    # Get all service operations
    service_data = boto3_data.get(service, {})
    all_operations = []
    
    for op in service_data.get('independent', []) + service_data.get('dependent', []):
        all_operations.append({
            'function': op['python_method'],
            'fields': op.get('item_fields', [])[:15]
        })
    
    prompt = f"""A compliance rule failed validation because required fields don't exist.

Rule: {rule_id}
Requirement: {requirement}
Description: {description}

Failed fields (not found in any single function): {failed_fields}

Available boto3 operations for {service}:
{json.dumps(all_operations[:20], indent=2)}

TASK: Find an alternative approach.

Options:
1. Use different field from available fields that serves same purpose
2. Use computed field (mark as needs_computation: true)
3. Suggest multi-function approach (list → get details)

Respond ONLY with JSON:
{{
  "alternative_approach": "use_different_field|computed|multi_function",
  "fields": [
    {{
      "boto3_python_field": "actual_field_from_list",
      "operator": "equals",
      "boto3_python_field_expected_values": value,
      "needs_computation": false
    }}
  ],
  "reasoning": "Brief explanation"
}}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an AWS compliance expert. Respond ONLY with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=800
        )
        
        response_text = response.choices[0].message.content.strip()
        response_text = response_text.replace('```json', '').replace('```', '').strip()
        
        alternative = json.loads(response_text)
        return alternative
        
    except Exception as e:
        print(f"      ⚠️  AI failed: {e}")
        return None


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        return
    
    client = OpenAI(api_key=api_key)
    boto3_data = load_boto3_catalog()
    
    # Load validated requirements
    with open('output/requirements_validated.json') as f:
        data = json.load(f)
    
    print("=" * 80)
    print("AGENT 4.5: Handle Skipped Rules")
    print("=" * 80)
    print("Finding alternatives for failed validations")
    print()
    
    enhanced = {}
    total_enhanced = 0
    
    for service, rules in data.items():
        print(f"\n📦 {service}")
        
        enhanced_rules = []
        
        for rule in rules:
            if rule.get('all_fields_valid'):
                # Already valid, keep as-is
                enhanced_rules.append(rule)
            else:
                # Try to find alternative
                print(f"   {rule['rule_id'].split('.')[-1]}...", end=' ')
                
                alternative = find_alternative_for_skipped_rule(rule, service, boto3_data, client)
                
                if alternative and alternative.get('fields'):
                    rule['alternative_approach'] = alternative
                    rule['enhanced'] = True
                    print(f"✅ Alternative found")
                    total_enhanced += 1
                else:
                    print(f"❌ No alternative")
                
                enhanced_rules.append(rule)
        
        enhanced[service] = enhanced_rules
    
    # Save
    with open('output/requirements_enhanced.json', 'w') as f:
        json.dump(enhanced, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Found alternatives for {total_enhanced}/12 skipped rules")
    print("Saved to: output/requirements_enhanced.json")
    print("\nNext: Regenerate YAML with enhanced requirements")


if __name__ == '__main__':
    main()

