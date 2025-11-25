#!/usr/bin/env python3
"""
AI-POWERED CHECK GENERATOR (OpenAI Version)
Uses GPT-4 to generate high-quality, service-specific checks
"""

import yaml
import json
import os
import time
from pathlib import Path
from openai import OpenAI

class AICheckGenerator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.implemented_services = {'s3'}
        
        # Initialize OpenAI client
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o"  # Latest GPT-4 Omni
        
    def get_all_services_to_generate(self):
        """Get services that need check generation"""
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if not service_dir.is_dir():
                continue
            
            service_name = service_dir.name
            metadata_dir = service_dir / "metadata"
            
            if metadata_dir.exists() and any(metadata_dir.glob("*.yaml")):
                if service_name not in self.implemented_services:
                    metadata_files = list(metadata_dir.glob("*.yaml"))
                    services.append({
                        'name': service_name,
                        'rule_count': len(metadata_files),
                        'metadata_files': metadata_files
                    })
        
        return sorted(services, key=lambda x: x['rule_count'], reverse=True)
    
    def load_service_metadata(self, metadata_files):
        """Load all metadata for a service"""
        metadata_list = []
        for yaml_file in metadata_files:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                if data:
                    essential = {
                        'rule_id': data.get('rule_id'),
                        'title': data.get('title'),
                        'requirement': data.get('requirement'),
                        'severity': data.get('severity'),
                        'description': data.get('description', '')[:150],
                        'scope': data.get('scope'),
                    }
                    metadata_list.append(essential)
        
        return metadata_list
    
    def generate_checks_with_ai(self, service_name, metadata_list):
        """Use OpenAI API to generate checks"""
        
        print(f"\n  🤖 Calling GPT-4 for {service_name}...")
        
        system_prompt = """You are an AWS security compliance expert creating production-ready compliance checks for a CSPM platform.

You MUST generate valid YAML using actual AWS Boto3 API calls and real field names from AWS API responses.

Output ONLY raw YAML (no markdown, no code blocks, no explanations)."""

        user_prompt = f"""Generate a complete YAML file for AWS **{service_name}** service compliance checks.

**Metadata for {len(metadata_list)} rules:**
```json
{json.dumps(metadata_list[:20], indent=2)}
```

**Structure (use ACTUAL AWS API calls):**

version: '1.0'
provider: aws
service: {service_name}

discovery:
  - discovery_id: aws.{service_name}.main_resources
    calls:
      - client: {service_name}
        action: describe_or_list_method  # REAL BOTO3 METHOD
        save_as: resources
    emit:
      items_for: resources[]
      as: resource
      item:
        id: '{{{{ resource.ActualIdField }}}}'
        name: '{{{{ resource.ActualNameField }}}}'

checks:
  - title: Full Title
    severity: critical|high|medium|low
    rule_id: aws.{service_name}.resource.check_name
    for_each:
      discovery: aws.{service_name}.main_resources
      as: resource
      item: resource
    conditions:
      var: resource.actual_field
      op: equals
      value: true
    remediation: |
      Detailed steps...
    references:
      - https://docs.aws.amazon.com/{service_name}/

**Requirements:**
1. Create ONE discovery step per resource type
2. Create ONE check per rule_id in metadata
3. Use REAL AWS Boto3 method names
4. Use REAL AWS API field names
5. Include proper remediation and AWS doc links

Output ONLY the YAML (no markdown blocks):"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=8000
            )
            
            yaml_content = response.choices[0].message.content.strip()
            
            # Clean up markdown if present
            if yaml_content.startswith('```'):
                lines = yaml_content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                yaml_content = '\n'.join(lines)
            
            print(f"  ✅ AI generated {len(yaml_content)} characters")
            return yaml_content
            
        except Exception as e:
            print(f"  ❌ API Error: {str(e)}")
            return None
    
    def validate_generated_yaml(self, yaml_content, service_name, expected_rule_count):
        """Validate AI-generated YAML"""
        
        try:
            data = yaml.safe_load(yaml_content)
            
            if not all(k in data for k in ['version', 'provider', 'service', 'discovery', 'checks']):
                return False, "Missing required fields"
            
            if data['service'] != service_name:
                return False, f"Service mismatch"
            
            discovery_count = len(data.get('discovery', []))
            check_count = len(data.get('checks', []))
            
            if check_count == 0:
                return False, "No checks generated"
            
            # Relaxed coverage requirement (at least 30%)
            if check_count < max(3, expected_rule_count * 0.3):
                return False, f"Low coverage: {check_count}/{expected_rule_count}"
            
            print(f"  ✅ Valid: {discovery_count} discovery, {check_count} checks")
            return True, data
            
        except yaml.YAMLError as e:
            return False, f"Invalid YAML: {str(e)}"
    
    def generate_service(self, service_name, metadata_files, retry=2):
        """Generate checks for one service"""
        
        print(f"\n{'='*80}")
        print(f"Service: {service_name} ({len(metadata_files)} rules)")
        print(f"{'='*80}")
        
        metadata_list = self.load_service_metadata(metadata_files)
        
        for attempt in range(retry):
            if attempt > 0:
                print(f"  🔄 Retry {attempt + 1}/{retry}")
                time.sleep(3)
            
            yaml_content = self.generate_checks_with_ai(service_name, metadata_list)
            
            if not yaml_content:
                continue
            
            valid, result = self.validate_generated_yaml(yaml_content, service_name, len(metadata_list))
            
            if valid:
                rules_dir = self.services_dir / service_name / "rules"
                rules_dir.mkdir(exist_ok=True, parents=True)
                
                output_file = rules_dir / f"{service_name}.yaml"
                with open(output_file, 'w') as f:
                    f.write(yaml_content)
                
                check_count = len(result['checks'])
                print(f"  ✅ Saved: {check_count} checks")
                
                return {
                    'status': 'success',
                    'checks_generated': check_count,
                    'discovery_steps': len(result['discovery'])
                }
            else:
                print(f"  ⚠️  Invalid: {result}")
        
        return {'status': 'failed', 'error': 'Max retries'}
    
    def generate_batch(self, limit=None, delay=1):
        """Generate checks for multiple services"""
        
        services = self.get_all_services_to_generate()
        
        if limit:
            services = services[:limit]
        
        print(f"\n{'='*80}")
        print(f"AI-POWERED BATCH GENERATION")
        print(f"{'='*80}")
        print(f"Services: {len(services)}")
        print(f"Total rules: {sum(s['rule_count'] for s in services)}")
        print(f"Model: {self.model}")
        
        results = []
        total_checks = 0
        
        for i, service in enumerate(services, 1):
            service_name = service['name']
            
            print(f"\n[{i}/{len(services)}] {service_name}")
            
            try:
                result = self.generate_service(service_name, service['metadata_files'])
                result['service'] = service_name
                results.append(result)
                
                if result['status'] == 'success':
                    total_checks += result['checks_generated']
                
                if i < len(services):
                    time.sleep(delay)
                
            except KeyboardInterrupt:
                print("\n\n⚠️  Interrupted")
                break
            except Exception as e:
                print(f"  ❌ Error: {str(e)}")
                results.append({'service': service_name, 'status': 'error', 'error': str(e)})
        
        # Summary
        print(f"\n{'='*80}")
        print(f"COMPLETE")
        print(f"{'='*80}")
        successful = sum(1 for r in results if r['status'] == 'success')
        print(f"✅ Success: {successful}/{len(results)}")
        print(f"📊 Total checks: {total_checks}")
        
        summary_file = self.services_dir / "AI_GENERATION_SUMMARY.json"
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📄 Summary: {summary_file}")
        
        return results

if __name__ == '__main__':
    import sys
    
    if not os.environ.get('OPENAI_API_KEY'):
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    generator = AICheckGenerator()
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    print(f"Generating top {limit} services...")
    results = generator.generate_batch(limit=limit)
    
    print(f"\n🎉 Done! Run: python3 services/analyze_coverage.py")

