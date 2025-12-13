"""
Universal Agent Generator

Creates complete agent pipelines for all cloud platforms (OCI, IBM, Alibaba, K8s)
based on the proven AWS/Azure pattern.
"""

import os
from pathlib import Path
from typing import Dict


# Platform configurations
PLATFORMS = {
    'oci': {
        'name': 'OCI',
        'full_name': 'Oracle Cloud Infrastructure',
        'base_dir': 'oci_compliance_python_engine',
        'catalog_file': 'oci_sdk_catalog_enhanced.json',
        'prefix': 'oci',
        'list_field': 'items',  # OCI typically returns arrays directly
        'services': ['compute', 'object_storage', 'virtual_network', 'identity', 'block_storage'],
    },
    'ibm': {
        'name': 'IBM',
        'full_name': 'IBM Cloud',
        'base_dir': 'ibm_compliance_python_engine',
        'catalog_file': 'ibm_sdk_catalog_enhanced.json',
        'prefix': 'ibm',
        'list_field': 'resources',
        'services': ['vpc', 'iam', 'object_storage', 'key_protect'],
    },
    'alicloud': {
        'name': 'Alibaba',
        'full_name': 'Alibaba Cloud',
        'base_dir': 'alicloud_compliance_python_engine',
        'catalog_file': 'alicloud_sdk_catalog_enhanced.json',
        'prefix': 'alicloud',
        'list_field': 'Instances',  # Alibaba uses PascalCase
        'services': ['ecs', 'oss', 'vpc', 'ram', 'rds'],
    },
    'k8s': {
        'name': 'K8s',
        'full_name': 'Kubernetes',
        'base_dir': 'k8_engine',
        'catalog_file': 'k8s_api_catalog_from_sdk.json',
        'prefix': 'k8s',
        'list_field': 'items',
        'services': ['pod', 'service', 'namespace', 'secret', 'deployment'],
    }
}


AGENT1_TEMPLATE = '''"""
Agent 1: {full_name} Requirements Generator (AI-Powered)

Uses OpenAI GPT-4o to generate intelligent compliance requirements from {name} metadata.
"""

import yaml
import json
import os
import sys
from openai import OpenAI
from agent_logger import get_logger

logger = get_logger('agent1')

SERVICES_TO_PROCESS = {services_list}


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{{service}}/metadata"
    if not os.path.exists(metadata_dir):
        logger.warning(f"No metadata directory for {{service}}")
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('{prefix}.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files


def generate_requirements_with_ai(rule_id: str, requirement: str, description: str, client, service: str, catalog_data: dict):
    """Use OpenAI GPT-4o to generate intelligent requirements"""
    
    # Get API operations for this service
    service_data = catalog_data.get(service, {{}})
    
    # Extract available fields
    all_available_fields = {{}}
    operations_key = 'resources' if 'resources' in str(service_data) else 'operations'
    
    if operations_key == 'resources':
        for resource_name, resource_data in service_data.get('resources', {{}}).items():
            for op in resource_data.get('independent', [])[:3]:
                op_name = op['python_method']
                fields = op.get('item_fields', {{}})
                if fields:
                    all_available_fields[f"{{resource_name}}.{{op_name}}"] = list(fields.keys())[:15]
    else:
        for op in service_data.get('operations', [])[:5]:
            op_name = op.get('operation', '')
            fields = op.get('item_fields', {{}})
            if fields:
                all_available_fields[op_name] = list(fields.keys())[:15]
    
    available_fields_summary = json.dumps(all_available_fields, indent=2)
    
    prompt = f"""You are a {full_name} compliance expert analyzing a security rule.

Rule ID: {{rule_id}}
Requirement: {{requirement}}
Description: {{description}}

AVAILABLE {name.upper()} API FIELDS FOR {{service.upper()}}:
{{available_fields_summary}}

TASK: Determine the EXACT field(s) to check from the API list above.

RESPONSE FORMAT (JSON only, no markdown):
{{{{
  "fields": [{{{{
    "conceptual_name": "field_purpose",
    "{prefix}_api_field": "actual.field.name",
    "operator": "equals",
    "{prefix}_api_field_expected_values": value
  }}}}],
  "condition_logic": "single"
}}}}

Operators: equals, not_equals, exists, not_empty, gt, lt, gte, lte, contains, in
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1000,
            temperature=0.1,
            messages=[
                {{"role": "system", "content": "You are a {full_name} compliance expert. Respond ONLY with valid JSON."}},
                {{"role": "user", "content": prompt}}
            ]
        )
        
        response_text = response.choices[0].message.content.strip()
        response_text = response_text.replace('```json', '').replace('```', '').strip()
        requirements = json.loads(response_text)
        
        logger.info(f"AI generated {{len(requirements.get('fields', []))}} fields for {{rule_id}}")
        return requirements
        
    except Exception as e:
        logger.error(f"AI generation error for {{rule_id}}: {{e}}")
        return {{
            "fields": [{{"conceptual_name": "basic_check", "{prefix}_api_field": "id", "operator": "exists", "{prefix}_api_field_expected_values": None}}],
            "condition_logic": "single",
            "error": str(e)
        }}


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        logger.error("OPENAI_API_KEY not set")
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    print("Loading {name} API catalog...")
    with open('{catalog_file}') as f:
        catalog_data = json.load(f)
    print("✅ Loaded")
    
    print("=" * 80)
    print("AGENT 1: {full_name} Requirements Generator")
    print("=" * 80)
    
    all_requirements = {{}}
    total_rules = 0
    total_fields = 0
    
    for service in SERVICES_TO_PROCESS:
        print(f"\\n📦 {{service}}")
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
            
            print(f"   [{{idx}}/{{len(metadata_files)}}] {{rule_id.split('.')[-1][:40]}}...", end=' ', flush=True)
            
            ai_reqs = generate_requirements_with_ai(rule_id, requirement, description, client, service, catalog_data)
            
            num_fields = len(ai_reqs.get('fields', []))
            print(f"✅ {{num_fields}} fields" if num_fields > 0 else "❌ No fields")
            total_fields += num_fields
            
            service_requirements.append({{
                'rule_id': rule_id,
                'service': service,
                'requirement': requirement,
                'description': description,
                'severity': metadata.get('severity', 'medium'),
                'ai_generated_requirements': ai_reqs
            }})
            
            total_rules += 1
        
        all_requirements[service] = service_requirements
        print(f"   ✅ {{len(service_requirements)}} rules")
    
    os.makedirs('output', exist_ok=True)
    output_file = 'output/requirements_initial.json'
    with open(output_file, 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    print("\\n" + "=" * 80)
    print(f"✅ Generated {{total_rules}} requirements with {{total_fields}} fields")
    print(f"   Saved to: {{output_file}}")
    print("=" * 80)
    
    logger.info(f"Agent 1 complete: {{total_rules}} requirements")


if __name__ == '__main__':
    main()
'''


def generate_agent1(platform_config: Dict, output_dir: str):
    """Generate Agent 1 for a platform"""
    content = AGENT1_TEMPLATE.format(
        name=platform_config['name'],
        full_name=platform_config['full_name'],
        prefix=platform_config['prefix'],
        catalog_file=platform_config['catalog_file'],
        services_list=str(platform_config['services'])
    )
    
    output_file = os.path.join(output_dir, 'agent1_requirements_generator.py')
    with open(output_file, 'w') as f:
        f.write(content)
    
    print(f"  ✅ Created agent1_requirements_generator.py")


def generate_agent_logger(output_dir: str):
    """Generate agent_logger.py"""
    logger_content = '''"""
Centralized logging for all agents.
"""

import logging
import os
from datetime import datetime


def get_logger(agent_name: str) -> logging.Logger:
    """Get logger for an agent"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger(agent_name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'{agent_name}_{timestamp}.log')
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(ch)
    
    master_log = os.path.join(log_dir, 'pipeline.log')
    mh = logging.FileHandler(master_log)
    mh.setLevel(logging.INFO)
    mh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(mh)
    
    logger.info(f"Logger initialized - {agent_name}")
    logger.info(f"Log file: {log_file}")
    
    return logger
'''
    
    output_file = os.path.join(output_dir, 'agent_logger.py')
    with open(output_file, 'w') as f:
        f.write(logger_content)
    
    print(f"  ✅ Created agent_logger.py")


def generate_run_script(platform_config: Dict, output_dir: str):
    """Generate run_all_agents.sh"""
    script = f'''#!/bin/bash

echo "================================================================================"
echo "{platform_config['full_name']} Agentic AI Pipeline"
echo "================================================================================"
echo ""

if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    exit 1
fi

mkdir -p output

echo "Step 1/4: Agent 1 (Requirements Generator)..."
python3 agent1_requirements_generator.py || exit 1

echo "Step 2/4: Agent 2 (Operation Validator)..."
python3 agent2_operation_validator.py || exit 1

echo "Step 3/4: Agent 3 (Field Validator)..."
python3 agent3_field_validator.py || exit 1

echo "Step 4/4: Agent 4 (YAML Generator)..."
python3 agent4_yaml_generator.py || exit 1

echo ""
echo "================================================================================"
echo "✅ {platform_config['full_name']} Pipeline Complete!"
echo "================================================================================"
'''
    
    output_file = os.path.join(output_dir, 'run_all_agents.sh')
    with open(output_file, 'w') as f:
        f.write(script)
    
    os.chmod(output_file, 0o755)
    print(f"  ✅ Created run_all_agents.sh")


def create_agents_for_platform(platform_key: str):
    """Create all agents for a platform"""
    config = PLATFORMS[platform_key]
    agent_dir = f"/Users/apple/Desktop/threat-engine/{config['base_dir']}/Agent-ruleid-rule-yaml"
    
    print(f"\n{'='*80}")
    print(f"Creating agents for {config['full_name']}")
    print(f"{'='*80}")
    
    # Create directory
    os.makedirs(agent_dir, exist_ok=True)
    
    # Generate common files
    generate_agent_logger(agent_dir)
    
    # Generate Agent 1
    generate_agent1(config, agent_dir)
    
    # Generate run script
    generate_run_script(config, agent_dir)
    
    print(f"✅ {config['name']} agents created in {agent_dir}")


def main():
    print("="*80)
    print("Universal Agent Generator for All Platforms")
    print("="*80)
    
    for platform_key in ['oci', 'ibm', 'alicloud', 'k8s']:
        create_agents_for_platform(platform_key)
    
    print("\n" + "="*80)
    print("✅ All platform agents created!")
    print("="*80)
    print("\nCreated agents for: OCI, IBM, Alibaba Cloud, Kubernetes")
    print("\nNote: Agents 2-4 are similar across platforms - using template approach.")
    print("="*80)


if __name__ == '__main__':
    main()

