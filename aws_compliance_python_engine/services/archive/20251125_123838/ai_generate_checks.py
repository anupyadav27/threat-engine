#!/usr/bin/env python3
"""
AI-POWERED CHECK GENERATOR
Uses Claude API to generate high-quality, service-specific checks
"""

import yaml
import json
import os
import time
from pathlib import Path
from anthropic import Anthropic

class AICheckGenerator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.implemented_services = {'s3'}
        
        # Initialize Anthropic client
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        
        self.client = Anthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"  # Latest Sonnet
        
    def load_prompt_template(self):
        """Load the prompt template for check generation"""
        prompt_file = Path("/Users/apple/Desktop/threat-engine/prompt_templates/aws_check_generation_prompt.md")
        
        if prompt_file.exists():
            with open(prompt_file, 'r') as f:
                return f.read()
        
        # Fallback inline template
        return """You are an AWS security expert creating compliance checks for a CSPM platform.

Generate a complete YAML file for AWS {service_name} service with ALL security checks.

Input metadata: {metadata_json}

Requirements:
1. Create DISCOVERY steps using actual AWS Boto3 API calls
2. For each rule in metadata, create a CHECK with:
   - Accurate discovery reference
   - Realistic conditions based on AWS API responses
   - Detailed remediation steps
   - Proper AWS documentation references

3. Use actual AWS API structure (not generic placeholders)
4. Each check must be executable with real AWS credentials

Output ONLY valid YAML (no explanations, no markdown code blocks).

Structure:
```yaml
version: '1.0'
provider: aws
service: {service_name}

discovery:
  - discovery_id: aws.{service_name}.resource_name
    calls:
      - client: {service_name}
        action: list_resources  # actual boto3 method
        save_as: resources
        fields:
          - Resources[]
    emit:
      items_for: resources[]
      as: resource
      item:
        id: '{{{{ resource.Id }}}}'
        name: '{{{{ resource.Name }}}}'

checks:
  - title: Check Title
    severity: high|medium|low|critical
    rule_id: aws.service.resource.check_name
    for_each:
      discovery: aws.service.resource_name
      as: resource
      item: resource
    conditions:
      var: resource.field_name
      op: equals|exists|gt|contains
      value: expected_value
    remediation: |
      Detailed steps...
    references:
      - https://docs.aws.amazon.com/...
```"""
    
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
                    # Keep only essential fields for context
                    essential = {
                        'rule_id': data.get('rule_id'),
                        'title': data.get('title'),
                        'requirement': data.get('requirement'),
                        'severity': data.get('severity'),
                        'description': data.get('description', '')[:200],  # Truncate
                        'scope': data.get('scope'),
                    }
                    metadata_list.append(essential)
        
        return metadata_list
    
    def generate_checks_with_ai(self, service_name, metadata_list):
        """Use Claude API to generate checks"""
        
        print(f"\n  🤖 Calling Claude API for {service_name}...")
        
        # Prepare prompt
        prompt = f"""You are an AWS security compliance expert. Generate a complete, production-ready YAML file for AWS **{service_name}** service.

**Metadata for {len(metadata_list)} rules:**
```json
{json.dumps(metadata_list, indent=2)}
```

**Requirements:**
1. Use REAL AWS Boto3 API calls (e.g., for EC2: describe_instances, describe_security_groups)
2. Create discovery steps that fetch actual resource configurations
3. For each rule in metadata, create a check with:
   - Accurate field references from AWS API responses
   - Realistic conditions (not generic placeholders)
   - Detailed, actionable remediation steps
   - Official AWS documentation links

4. Follow this EXACT structure:

version: '1.0'
provider: aws
service: {service_name}

discovery:
  # List main resources
  - discovery_id: aws.{service_name}.resources
    calls:
      - client: {service_name}
        action: list_or_describe_method  # USE ACTUAL BOTO3 METHOD NAME
        save_as: resources
    emit:
      items_for: resources[]
      as: resource
      item:
        id: '{{{{ resource.ActualIdField }}}}'
        name: '{{{{ resource.ActualNameField }}}}'
  
  # Additional discovery for specific configs (encryption, logging, etc.)
  - discovery_id: aws.{service_name}.resource_encryption
    for_each: aws.{service_name}.resources
    calls:
      - client: {service_name}
        action: get_encryption_config  # ACTUAL METHOD
        params:
          ResourceId: '{{{{ item.id }}}}'
        save_as: encryption
        on_error: continue
    emit:
      item:
        resource_id: '{{{{ item.id }}}}'
        encryption_enabled: '{{{{ encryption.Encrypted }}}}'  # ACTUAL FIELD

checks:
  - title: {service_name.upper()} Resource Encryption Enabled
    severity: high
    rule_id: aws.{service_name}.resource.encryption_enabled
    for_each:
      discovery: aws.{service_name}.resource_encryption
      as: encryption
      item: resource
    conditions:
      var: encryption.encryption_enabled
      op: equals
      value: true
    remediation: |
      Enable encryption for {service_name}:
      1. Open {service_name.upper()} console
      2. Select the resource
      3. Go to Encryption settings
      4. Enable encryption
      5. Choose KMS key
      6. Save changes
    references:
      - https://docs.aws.amazon.com/{service_name}/latest/userguide/encryption.html

**CRITICAL:**
- Output ONLY valid YAML
- NO markdown code blocks (```yaml)
- NO explanations before or after
- Use actual AWS API field names
- Create one check per rule_id in metadata

Generate the complete YAML now:"""

        try:
            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                temperature=0.3,  # Lower for more consistent output
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            yaml_content = response.content[0].text.strip()
            
            # Clean up if AI added markdown
            if yaml_content.startswith('```'):
                lines = yaml_content.split('\n')
                yaml_content = '\n'.join(lines[1:-1]) if len(lines) > 2 else yaml_content
            
            print(f"  ✅ AI generated {len(yaml_content)} characters")
            
            return yaml_content
            
        except Exception as e:
            print(f"  ❌ AI Error: {str(e)}")
            return None
    
    def validate_generated_yaml(self, yaml_content, service_name, expected_rule_count):
        """Validate AI-generated YAML"""
        
        try:
            data = yaml.safe_load(yaml_content)
            
            # Basic structure validation
            if not all(k in data for k in ['version', 'provider', 'service', 'discovery', 'checks']):
                return False, "Missing required fields"
            
            if data['service'] != service_name:
                return False, f"Service mismatch: expected {service_name}, got {data['service']}"
            
            discovery_count = len(data.get('discovery', []))
            check_count = len(data.get('checks', []))
            
            if check_count == 0:
                return False, "No checks generated"
            
            # Check if reasonable coverage (at least 50% of metadata rules)
            if check_count < expected_rule_count * 0.5:
                return False, f"Low coverage: {check_count}/{expected_rule_count} checks"
            
            print(f"  ✅ Validation passed: {discovery_count} discovery, {check_count} checks")
            return True, data
            
        except yaml.YAMLError as e:
            return False, f"Invalid YAML: {str(e)}"
    
    def generate_service(self, service_name, metadata_files, retry=3):
        """Generate checks for one service with retries"""
        
        print(f"\n{'='*80}")
        print(f"Generating: {service_name} ({len(metadata_files)} rules)")
        print(f"{'='*80}")
        
        # Load metadata
        metadata_list = self.load_service_metadata(metadata_files)
        
        for attempt in range(retry):
            if attempt > 0:
                print(f"  🔄 Retry attempt {attempt + 1}/{retry}")
                time.sleep(2)  # Rate limiting
            
            # Generate with AI
            yaml_content = self.generate_checks_with_ai(service_name, metadata_list)
            
            if not yaml_content:
                continue
            
            # Validate
            valid, result = self.validate_generated_yaml(yaml_content, service_name, len(metadata_list))
            
            if valid:
                # Save to file
                rules_dir = self.services_dir / service_name / "rules"
                rules_dir.mkdir(exist_ok=True, parents=True)
                
                output_file = rules_dir / f"{service_name}.yaml"
                with open(output_file, 'w') as f:
                    f.write(yaml_content)
                
                check_count = len(result['checks'])
                print(f"  ✅ Saved: {output_file} ({check_count} checks)")
                
                return {
                    'status': 'success',
                    'checks_generated': check_count,
                    'discovery_steps': len(result['discovery'])
                }
            else:
                print(f"  ⚠️  Validation failed: {result}")
        
        return {
            'status': 'failed',
            'error': 'Max retries exceeded'
        }
    
    def generate_batch(self, limit=None, delay=2):
        """Generate checks for multiple services"""
        
        services = self.get_all_services_to_generate()
        
        if limit:
            services = services[:limit]
        
        print(f"\n{'='*80}")
        print(f"AI-POWERED BATCH GENERATION")
        print(f"{'='*80}")
        print(f"Services to process: {len(services)}")
        print(f"Total rules: {sum(s['rule_count'] for s in services)}")
        print(f"Model: {self.model}")
        print(f"Rate limit delay: {delay}s between services")
        
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
                
                # Rate limiting
                if i < len(services):
                    time.sleep(delay)
                
            except KeyboardInterrupt:
                print("\n\n⚠️  Generation interrupted by user")
                break
            except Exception as e:
                print(f"  ❌ Unexpected error: {str(e)}")
                results.append({
                    'service': service_name,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Summary
        print(f"\n{'='*80}")
        print(f"GENERATION COMPLETE")
        print(f"{'='*80}")
        print(f"Processed: {len(results)} services")
        print(f"Successful: {sum(1 for r in results if r['status'] == 'success')}")
        print(f"Failed: {sum(1 for r in results if r['status'] in ['failed', 'error'])}")
        print(f"Total checks: {total_checks}")
        
        # Save results
        summary_file = self.services_dir / "AI_GENERATION_SUMMARY.json"
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📄 Summary: {summary_file}")
        
        return results

if __name__ == '__main__':
    import sys
    
    # Check for API key
    if not os.environ.get('ANTHROPIC_API_KEY'):
        print("❌ Error: ANTHROPIC_API_KEY environment variable not set")
        print("\nSet it with:")
        print("  export ANTHROPIC_API_KEY='your-api-key-here'")
        sys.exit(1)
    
    generator = AICheckGenerator()
    
    # Parse arguments
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    
    if limit:
        print(f"Generating top {limit} services with AI...")
    else:
        print("Generating ALL services with AI...")
        print("⚠️  This will use significant API credits")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled.")
            sys.exit(0)
    
    results = generator.generate_batch(limit=limit)
    
    print(f"\n🎉 AI generation complete!")
    print(f"Run: python3 services/analyze_coverage.py")

