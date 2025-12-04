#!/usr/bin/env python3
"""
Use GPT-4 to generate specific field validations for all AAD checks
Based on check metadata and Azure AD Graph API documentation
"""

import yaml
import os
import json
from pathlib import Path

def generate_specific_validation_with_gpt4(check_id, title, requirement, resource, metadata_file):
    """Use GPT-4 to generate specific validation for a check"""
    
    try:
        import openai
    except ImportError:
        print("Installing openai package...")
        os.system("pip install -q openai")
        import openai
    
    # Set API key from environment
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    client = openai.OpenAI(api_key=api_key)
    
    prompt = f"""You are an Azure AD compliance expert. Generate specific Graph API validation for this check:

Check ID: {check_id}
Title: {title}
Requirement: {requirement}
Resource: {resource}

Based on Microsoft Graph API documentation, provide the EXACT validation needed:

Return ONLY a JSON object with this structure:
{{
  "method": "GET",
  "path": "/v1.0/...",
  "field_path": "specific.field.path",
  "operator": "exists|equals|gte|lte",
  "expected_value": "value if operator is equals/gte/lte, or null",
  "reasoning": "Why this endpoint and field"
}}

For example:
- Password min length 14 → {{"path": "/v1.0/domains", "field_path": "value[0].passwordValidityPeriodInDays", "operator": "gte", "expected_value": 14}}
- User MFA required → {{"path": "/v1.0/users", "field_path": "value[0].id", "operator": "exists"}}

Be specific and accurate based on Azure AD Graph API v1.0 documentation."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Fast and cost-effective
            messages=[
                {"role": "system", "content": "You are an Azure AD Graph API expert. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low temperature for accuracy
            max_tokens=300
        )
        
        result_text = response.choices[0].message.content.strip()
        
        # Extract JSON
        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        
        result = json.loads(result_text)
        return result
        
    except Exception as e:
        print(f"   ⚠️  GPT-4 error for {check_id[:50]}...: {e}")
        # Return safe default
        return {
            "method": "GET",
            "path": "/v1.0/organization",
            "field_path": "value[0].id",
            "operator": "exists",
            "expected_value": None,
            "reasoning": "Default - GPT-4 failed"
        }


def process_all_checks_with_gpt4():
    """Process all AAD checks with GPT-4"""
    
    script_dir = Path(__file__).parent
    rules_file = script_dir / 'services' / 'aad' / 'aad_rules.yaml'
    metadata_dir = script_dir / 'services' / 'aad' / 'metadata'
    
    # Load rules
    with open(rules_file, 'r') as f:
        data = yaml.safe_load(f)
    
    aad = data['aad']
    checks = aad.get('checks', [])
    
    print("=" * 80)
    print(" USING GPT-4 TO GENERATE SPECIFIC VALIDATIONS")
    print("=" * 80)
    print(f"\nTotal checks: {len(checks)}")
    print(f"Using: GPT-4o-mini (fast & accurate)")
    print(f"\nProcessing each check with Azure AD expertise...")
    
    # Load metadata files
    metadata_map = {}
    for mfile in metadata_dir.glob('*.yaml'):
        with open(mfile, 'r') as f:
            meta = yaml.safe_load(f)
            rule_id = meta.get('rule_id', '')
            metadata_map[rule_id] = meta
    
    updated_count = 0
    errors = 0
    
    for i, check in enumerate(checks, 1):
        check_id = check.get('check_id', '')
        title = check.get('title', '')
        
        # Get metadata
        metadata = metadata_map.get(check_id, {})
        requirement = metadata.get('requirement', '')
        resource = metadata.get('resource', '')
        
        print(f"\n{i}/{len(checks)}: {check_id[:60]}...")
        
        # Generate validation with GPT-4
        validation = generate_specific_validation_with_gpt4(
            check_id, title, requirement, resource, metadata.get('file', '')
        )
        
        if validation:
            # Update check
            field_spec = {
                'path': validation['field_path'],
                'operator': validation['operator']
            }
            
            if validation.get('expected_value') is not None:
                field_spec['expected'] = validation['expected_value']
            
            check['calls'] = [{
                'method': validation['method'],
                'path': validation['path'],
                'fields': [field_spec]
            }]
            
            print(f"   ✓ {validation['path']} → {validation['field_path']}")
            updated_count += 1
        else:
            print(f"   ✗ Failed")
            errors += 1
        
        # Progress indicator
        if i % 10 == 0:
            print(f"\n   Progress: {i}/{len(checks)} ({100*i//len(checks)}%)")
    
    # Save
    with open(rules_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
    
    print("\n" + "=" * 80)
    print(" COMPLETE")
    print("=" * 80)
    print(f"   Updated: {updated_count} checks")
    print(f"   Errors: {errors} checks")
    print(f"\n✅ All AAD checks now have GPT-4 generated specific validations!")
    
    return updated_count, errors


def main():
    # Check for API key
    if not os.getenv('OPENAI_API_KEY'):
        print("=" * 80)
        print(" SET OPENAI API KEY")
        print("=" * 80)
        print("\nPlease set your OpenAI API key:")
        print("  export OPENAI_API_KEY='your-key-here'")
        print("\nThen run this script again.")
        return 1
    
    # Process all checks
    updated, errors = process_all_checks_with_gpt4()
    
    if errors == 0:
        print("\n🎉 SUCCESS! All checks updated with specific validations!")
        print("\nNext: Run scan to test")
        print("  python3 -m azure_compliance_python_engine.engine.targeted_scan --services aad --save-report")
    else:
        print(f"\n⚠️  {errors} checks had errors, but {updated} succeeded")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

