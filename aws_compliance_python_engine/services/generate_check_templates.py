#!/usr/bin/env python3
"""
Generate check template from metadata files.
This helps quickly bootstrap {service}_checks.yaml files.
"""

import yaml
import os
from pathlib import Path
from collections import defaultdict

def load_metadata_for_service(service_path: Path):
    """Load all metadata files for a service"""
    metadata_dir = service_path / 'metadata'
    rules = []
    
    for yaml_file in metadata_dir.glob('*.yaml'):
        with open(yaml_file, 'r') as f:
            rule = yaml.safe_load(f)
            rules.append(rule)
    
    return rules

def generate_check_template(service: str, rules: list) -> dict:
    """Generate a check template from metadata"""
    
    template = {
        'version': '1.0',
        'provider': 'aws',
        'service': service,
        'discovery': [],
        'checks': []
    }
    
    # Add placeholder discovery
    template['discovery'].append({
        'discovery_id': f'aws.{service}.resources',
        'calls': [{
            'client': service,
            'action': f'list_{service}s',  # Placeholder - needs correction
            'paginate': True,
            'save_as': 'resources_list',
            'fields': ['<ResponseArray>[]']
        }],
        'emit': {
            'items_for': 'resources_list[]',
            'as': 'resource',
            'item': {
                'id': '{{ resource.<IdField> }}',
                'name': '{{ resource.<NameField> }}'
            }
        }
    })
    
    # Add placeholder for config discovery
    template['discovery'].append({
        'discovery_id': f'aws.{service}.<config_type>',
        'for_each': f'aws.{service}.resources',
        'calls': [{
            'client': service,
            'action': 'get_<config>',
            'params': {'<ResourceParam>': '{{ item.name }}'},
            'save_as': 'config_data',
            'on_error': 'continue',
            'fields': ['<ConfigPath>']
        }],
        'emit': {
            'item': {
                'resource_id': '{{ item.id }}',
                'resource_name': '{{ item.name }}',
                '<setting_name>': '{{ config_data.<Path> }}'
            }
        }
    })
    
    # Generate check for each rule
    for rule in rules[:5]:  # First 5 as examples
        check = {
            'title': rule.get('title', ''),
            'severity': rule.get('severity', 'medium'),
            'rule_id': rule.get('rule_id', ''),
            'for_each': {
                'discovery': f'aws.{service}.<config_type>',
                'as': 'config',
                'item': 'resource_id'
            },
            'conditions': {
                'var': 'config.<setting>',
                'op': 'equals',
                'value': '<expected_value>'
            },
            'remediation': rule.get('rationale', 'TODO: Add remediation steps'),
            'references': rule.get('references', [])
        }
        template['checks'].append(check)
    
    # Add comment for remaining rules
    if len(rules) > 5:
        template['_note'] = f'TODO: Add remaining {len(rules) - 5} checks following the pattern above'
    
    return template

def create_check_templates(base_path: str, services: list = None):
    """Create check template files for specified services"""
    
    print("="*80)
    print("GENERATING CHECK TEMPLATES")
    print("="*80)
    
    base_dir = Path(base_path)
    
    if services:
        service_dirs = [base_dir / s for s in services if (base_dir / s).exists()]
    else:
        service_dirs = [d for d in base_dir.iterdir() if d.is_dir() and d.name != 'SERVICE_INDEX.yaml']
    
    stats = {
        'generated': 0,
        'skipped': 0,
        'failed': 0
    }
    
    for service_dir in sorted(service_dirs):
        service = service_dir.name
        
        print(f"\n📋 Service: {service}")
        
        # Check if checks file already exists
        checks_file = service_dir / 'checks' / f'{service}_checks.yaml'
        
        if checks_file.exists():
            with open(checks_file, 'r') as f:
                content = yaml.safe_load(f)
                if content.get('checks') and len(content['checks']) > 0:
                    print(f"  ⏭️  Skipped (already has checks)")
                    stats['skipped'] += 1
                    continue
        
        try:
            # Load metadata
            rules = load_metadata_for_service(service_dir)
            
            if not rules:
                print(f"  ⚠️  No metadata files found")
                stats['failed'] += 1
                continue
            
            # Generate template
            template = generate_check_template(service, rules)
            
            # Save template
            with open(checks_file, 'w') as f:
                yaml.dump(template, f, default_flow_style=False, sort_keys=False,
                         width=120, allow_unicode=True)
            
            print(f"  ✅ Generated template with {len(template['checks'])} sample checks")
            print(f"     Total rules in metadata: {len(rules)}")
            stats['generated'] += 1
            
        except Exception as e:
            print(f"  ❌ Failed: {str(e)}")
            stats['failed'] += 1
    
    print("\n" + "="*80)
    print("TEMPLATE GENERATION SUMMARY")
    print("="*80)
    print(f"\n✅ Generated: {stats['generated']}")
    print(f"⏭️  Skipped: {stats['skipped']}")
    print(f"❌ Failed: {stats['failed']}")
    
    print("\n📝 Next Steps:")
    print("  1. Review generated templates in {service}/checks/{service}_checks.yaml")
    print("  2. Update <placeholders> with actual boto3 API calls")
    print("  3. Add proper discovery steps for each config type")
    print("  4. Complete remaining checks following the pattern")
    print("  5. Test against real AWS resources")
    
    print("\n💡 Tip: Use IMPLEMENTATION_GUIDE.md for service-specific patterns")

def main():
    import sys
    
    services = sys.argv[1:] if len(sys.argv) > 1 else None
    
    if services:
        print(f"Generating templates for: {', '.join(services)}")
    else:
        print("Generating templates for ALL services (this may take a while)")
        print("Tip: Specify services as arguments to generate specific ones")
        print("Example: python3 generate_check_templates.py s3 ec2 iam\n")
    
    create_check_templates(
        base_path='/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services',
        services=services
    )

if __name__ == '__main__':
    main()

