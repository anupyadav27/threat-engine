#!/usr/bin/env python3
"""
Quality-Controlled Agentic Service Generator
Uses Claude for best quality with multi-stage validation
"""

import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Tuple
import anthropic

# Quality control thresholds
QUALITY_THRESHOLDS = {
    'min_discovery_steps': 1,
    'max_discovery_steps': 20,
    'min_checks': 1,
    'max_duplicate_validations': 0.3,  # Max 30% can be identical
    'required_fields': ['version', 'provider', 'service', 'discovery', 'checks'],
    'max_api_errors_percent': 10,  # Max 10% API errors acceptable
}

class QualityValidator:
    """Validates generated rules at each step"""
    
    @staticmethod
    def validate_yaml_structure(data: Dict) -> Tuple[bool, List[str]]:
        """Validate YAML has required structure"""
        errors = []
        
        # Check required fields
        for field in QUALITY_THRESHOLDS['required_fields']:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        # Validate discovery
        discovery = data.get('discovery', [])
        if not isinstance(discovery, list):
            errors.append("Discovery must be a list")
        elif len(discovery) < QUALITY_THRESHOLDS['min_discovery_steps']:
            errors.append(f"Too few discovery steps: {len(discovery)}")
        elif len(discovery) > QUALITY_THRESHOLDS['max_discovery_steps']:
            errors.append(f"Too many discovery steps: {len(discovery)}")
        
        # Validate checks
        checks = data.get('checks', [])
        if not isinstance(checks, list):
            errors.append("Checks must be a list")
        elif len(checks) < QUALITY_THRESHOLDS['min_checks']:
            errors.append(f"Too few checks: {len(checks)}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_check_quality(checks: List[Dict]) -> Tuple[bool, List[str]]:
        """Validate individual checks for quality"""
        errors = []
        
        for i, check in enumerate(checks, 1):
            # Required fields
            if 'check_id' not in check:
                errors.append(f"Check {i}: Missing check_id")
            if 'calls' not in check or not check['calls']:
                errors.append(f"Check {i}: Missing or empty calls")
            
            # Validate calls structure
            for call in check.get('calls', []):
                if 'method' not in call:
                    errors.append(f"Check {i}: Call missing method")
                if 'path' not in call:
                    errors.append(f"Check {i}: Call missing path")
                if 'fields' not in call or not call['fields']:
                    errors.append(f"Check {i}: Call missing fields")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def detect_duplicates(checks: List[Dict]) -> Tuple[int, List[str]]:
        """Detect duplicate validations"""
        validations = {}
        duplicates = []
        
        for check in checks:
            check_id = check.get('check_id', '')
            calls = check.get('calls', [])
            
            if calls:
                # Create validation signature
                call = calls[0]
                sig = f"{call.get('path')}|{call.get('fields', [{}])[0].get('path', '')}"
                
                if sig in validations:
                    duplicates.append(f"{check_id} duplicates {validations[sig]}")
                else:
                    validations[sig] = check_id
        
        dup_percent = len(duplicates) / len(checks) if checks else 0
        
        return len(duplicates), duplicates
    
    @staticmethod
    def validate_azure_api_paths(checks: List[Dict]) -> Tuple[bool, List[str]]:
        """Validate API paths follow Azure patterns"""
        errors = []
        
        for check in checks:
            check_id = check.get('check_id', '')
            for call in check.get('calls', []):
                path = call.get('path', '')
                
                # Must start with /v1.0/ for Graph API or be resource manager
                if not (path.startswith('/v1.0/') or path.startswith('/subscriptions/')):
                    errors.append(f"{check_id}: Invalid API path: {path}")
                
                # Check for common mistakes
                if '%7B' in path or '%7D' in path:
                    errors.append(f"{check_id}: Encoded characters in path (likely wrong)")
                if path.endswith('?$filter='):
                    errors.append(f"{check_id}: Empty filter in path")
        
        return len(errors) == 0, errors


class AgenticServiceGenerator:
    """Generate service rules with quality controls"""
    
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.validator = QualityValidator()
    
    def generate_service_rules(
        self, 
        service_name: str,
        metadata_files: List[Path],
        package: str,
        client_class: str,
        reference_service: str = 'aad'
    ) -> Tuple[Dict, Dict]:
        """
        Generate service rules with quality validation
        
        Returns: (generated_rules, quality_report)
        """
        
        print(f"\n{'='*80}")
        print(f" GENERATING {service_name.upper()} SERVICE WITH QUALITY CONTROLS")
        print(f"{'='*80}")
        
        # Step 1: Load metadata
        print(f"\n📄 Step 1: Loading metadata...")
        metadata_summary = self._load_metadata_summary(metadata_files)
        print(f"   ✓ Loaded {len(metadata_files)} metadata files")
        
        # Step 2: Load reference service (AAD as template)
        print(f"\n📚 Step 2: Loading reference service ({reference_service})...")
        reference_rules = self._load_reference_service(reference_service)
        print(f"   ✓ Loaded reference with {len(reference_rules.get('checks', []))} checks")
        
        # Step 3: Generate with Claude (high quality)
        print(f"\n🤖 Step 3: Generating rules with Claude (quality mode)...")
        generated = self._generate_with_claude(
            service_name, metadata_summary, package, client_class, reference_rules
        )
        
        # Step 4: Validate structure
        print(f"\n✅ Step 4: Quality validation...")
        quality_report = self._validate_quality(generated, service_name)
        
        # Step 5: Auto-fix common issues
        if quality_report['has_issues']:
            print(f"\n🔧 Step 5: Auto-fixing detected issues...")
            generated = self._auto_fix_issues(generated, quality_report)
            # Re-validate
            quality_report = self._validate_quality(generated, service_name)
        
        return generated, quality_report
    
    def _load_metadata_summary(self, metadata_files: List[Path]) -> Dict:
        """Load and summarize metadata"""
        summary = {
            'total_files': len(metadata_files),
            'by_resource': {},
            'by_severity': {},
            'sample_checks': []
        }
        
        for mfile in metadata_files[:10]:  # Sample first 10
            with open(mfile, 'r') as f:
                meta = yaml.safe_load(f)
            
            resource = meta.get('resource', 'unknown')
            severity = meta.get('severity', 'medium')
            
            summary['by_resource'][resource] = summary['by_resource'].get(resource, 0) + 1
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            summary['sample_checks'].append({
                'rule_id': meta.get('rule_id', ''),
                'resource': resource,
                'requirement': meta.get('requirement', ''),
                'severity': severity
            })
        
        return summary
    
    def _load_reference_service(self, service_name: str) -> Dict:
        """Load reference service as template"""
        ref_file = Path('services') / service_name / f'{service_name}_rules.yaml'
        
        if not ref_file.exists():
            return {}
        
        with open(ref_file, 'r') as f:
            data = yaml.safe_load(f)
        
        return data.get(service_name, data)
    
    def _generate_with_claude(
        self,
        service_name: str,
        metadata_summary: Dict,
        package: str,
        client_class: str,
        reference_rules: Dict
    ) -> Dict:
        """Generate rules using Claude with quality prompts"""
        
        prompt = f"""You are an Azure SDK expert. Generate a complete rules YAML file for the {service_name} service.

SERVICE DETAILS:
- Service: {service_name}
- Package: {package}
- Client: {client_class}
- Total checks: {metadata_summary['total_files']}

METADATA SUMMARY:
- Resources: {json.dumps(metadata_summary['by_resource'], indent=2)}
- Sample checks: {json.dumps(metadata_summary['sample_checks'][:5], indent=2)}

REFERENCE (AAD service - use as template):
{yaml.dump(reference_rules, default_flow_style=False)[:2000]}

REQUIREMENTS:
1. Use exact same YAML structure as reference
2. Create specific discovery steps for {service_name} resources
3. Generate checks with SPECIFIC Azure SDK API calls
4. Use correct Azure Management SDK paths (not Graph API)
5. Each check must have unique validation (no duplicates!)
6. Follow pattern: calls with method, path, fields
7. Ensure all check_ids are unique

FORMAT:
{service_name}:
  version: '1.0'
  provider: azure
  service: {service_name}
  package: {package}
  client_class: {client_class}
  scope: subscription
  discovery:
    - discovery_id: azure.{service_name}.resources
      calls:
        - client: {service_name}
          action: resource_type.list_all  # Correct Azure SDK method
          save_as: resources
      ... (add more discovery steps)
  checks:
    - check_id: azure.{service_name}.resource.requirement
      title: Clear title
      severity: high/medium/low
      for_each: azure.{service_name}.resources
      calls:
        - method: GET
          path: /subscriptions/{{subscription}}/...  # Azure ARM path
          fields:
            - path: properties.specificField
              operator: exists/equals/gte/lte
              expected: value (if needed)

CRITICAL: Return ONLY valid YAML, no markdown, no explanations.
"""
        
        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",  # Best quality - Claude 4
                max_tokens=8000,
                temperature=0.1,  # Low for accuracy
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            result_text = response.content[0].text.strip()
            
            # Extract YAML
            if '```yaml' in result_text:
                result_text = result_text.split('```yaml')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            # Parse YAML
            generated = yaml.safe_load(result_text)
            
            return generated
            
        except Exception as e:
            print(f"   ✗ Claude generation error: {e}")
            return {}
    
    def _validate_quality(self, generated: Dict, service_name: str) -> Dict:
        """Comprehensive quality validation"""
        
        report = {
            'service': service_name,
            'passed': True,
            'has_issues': False,
            'errors': [],
            'warnings': [],
            'stats': {}
        }
        
        if not generated or service_name not in generated:
            report['passed'] = False
            report['errors'].append("No data generated or wrong structure")
            return report
        
        service_data = generated[service_name]
        
        # 1. Structure validation
        valid, errors = self.validator.validate_yaml_structure(service_data)
        if not valid:
            report['errors'].extend(errors)
            report['passed'] = False
        
        # 2. Check quality validation
        checks = service_data.get('checks', [])
        valid, errors = self.validator.validate_check_quality(checks)
        if not valid:
            report['errors'].extend(errors)
            report['has_issues'] = True
        
        # 3. Duplicate detection
        dup_count, dup_list = self.validator.detect_duplicates(checks)
        if dup_count > len(checks) * QUALITY_THRESHOLDS['max_duplicate_validations']:
            report['warnings'].append(f"High duplicate rate: {dup_count}/{len(checks)}")
            report['has_issues'] = True
        
        # 4. API path validation
        valid, errors = self.validator.validate_azure_api_paths(checks)
        if not valid:
            report['warnings'].extend(errors)
        
        # 5. Statistics
        report['stats'] = {
            'total_checks': len(checks),
            'discovery_steps': len(service_data.get('discovery', [])),
            'duplicate_validations': dup_count,
            'api_path_errors': len(errors) if not valid else 0
        }
        
        # Print report
        self._print_quality_report(report)
        
        return report
    
    def _print_quality_report(self, report: Dict):
        """Print quality validation report"""
        print(f"\n   📊 Quality Report:")
        print(f"      Checks: {report['stats'].get('total_checks', 0)}")
        print(f"      Discovery: {report['stats'].get('discovery_steps', 0)} steps")
        print(f"      Duplicates: {report['stats'].get('duplicate_validations', 0)}")
        print(f"      API errors: {report['stats'].get('api_path_errors', 0)}")
        
        if report['errors']:
            print(f"\n   ❌ Errors ({len(report['errors'])}):")
            for err in report['errors'][:5]:
                print(f"      - {err}")
        
        if report['warnings']:
            print(f"\n   ⚠️  Warnings ({len(report['warnings'])}):")
            for warn in report['warnings'][:5]:
                print(f"      - {warn}")
        
        if report['passed'] and not report['has_issues']:
            print(f"\n   ✅ QUALITY: EXCELLENT")
        elif report['passed']:
            print(f"\n   ✅ QUALITY: GOOD (minor warnings)")
        else:
            print(f"\n   ❌ QUALITY: NEEDS IMPROVEMENT")
    
    def _auto_fix_issues(self, generated: Dict, quality_report: Dict) -> Dict:
        """Auto-fix common issues"""
        print(f"   Auto-fixing common issues...")
        
        # Implementation: Fix known patterns
        # For now, return as-is (can add specific fixes)
        
        return generated


def generate_service_with_quality_control(
    service_name: str,
    max_iterations: int = 3
) -> Tuple[bool, Dict]:
    """
    Generate service rules with iterative quality improvement
    
    Returns: (success, final_rules)
    """
    
    # Check API key
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("❌ ANTHROPIC_API_KEY not set")
        return False, {}
    
    # Load service info
    script_dir = Path(__file__).parent
    mapping_file = script_dir / 'AZURE_SERVICE_PACKAGE_MAPPING.csv'
    
    # Get service details from mapping
    import csv
    with open(mapping_file, 'r') as f:
        reader = csv.DictReader(f)
        service_info = None
        for row in reader:
            if row['service'] == service_name:
                service_info = row
                break
    
    if not service_info:
        print(f"❌ Service {service_name} not found in mapping")
        return False, {}
    
    package = service_info['package']
    client_class = service_info['client']
    
    # Load metadata files
    metadata_dir = script_dir / 'services' / service_name / 'metadata'
    metadata_files = list(metadata_dir.glob('*.yaml'))
    
    if not metadata_files:
        print(f"❌ No metadata files found for {service_name}")
        return False, {}
    
    print(f"\n🎯 Generating {service_name} service")
    print(f"   Package: {package}")
    print(f"   Client: {client_class}")
    print(f"   Metadata files: {len(metadata_files)}")
    
    # Create generator
    generator = AgenticServiceGenerator(api_key)
    
    # Iterative generation with quality improvement
    best_quality = 0
    best_rules = None
    
    for iteration in range(1, max_iterations + 1):
        print(f"\n🔄 Iteration {iteration}/{max_iterations}")
        
        # Generate
        generated, quality_report = generator.generate_service_rules(
            service_name,
            metadata_files,
            package,
            client_class
        )
        
        # Calculate quality score
        stats = quality_report.get('stats', {})
        quality_score = (
            stats.get('total_checks', 0) 
            - stats.get('duplicate_validations', 0) * 2
            - stats.get('api_path_errors', 0) * 3
            - len(quality_report.get('errors', [])) * 10
        )
        
        print(f"   Quality score: {quality_score}")
        
        if quality_score > best_quality:
            best_quality = quality_score
            best_rules = generated
            print(f"   ✓ New best quality!")
        
        # If excellent quality, stop early
        if quality_report['passed'] and not quality_report['has_issues']:
            print(f"   ✅ Excellent quality achieved!")
            break
    
    # Save best result
    if best_rules:
        output_file = script_dir / 'services' / service_name / f'{service_name}_rules.yaml'
        with open(output_file, 'w') as f:
            yaml.dump(best_rules, f, default_flow_style=False, sort_keys=False, width=120)
        
        print(f"\n✅ Saved to: {output_file}")
        print(f"   Best quality score: {best_quality}")
        return True, best_rules
    
    return False, {}


def main():
    print("="*80)
    print(" QUALITY-CONTROLLED AGENTIC SERVICE GENERATOR")
    print(" Using Claude 3.5 Sonnet for best quality")
    print("="*80)
    
    # Check API key
    if not os.getenv('ANTHROPIC_API_KEY'):
        print("\n❌ Please set ANTHROPIC_API_KEY environment variable")
        print("   export ANTHROPIC_API_KEY='your-key'")
        return 1
    
    # Test with a service
    if len(sys.argv) > 1:
        service = sys.argv[1]
    else:
        print("\nUsage: python3 agentic_service_generator_quality_controlled.py <service_name>")
        print("\nExample:")
        print("  python3 agentic_service_generator_quality_controlled.py compute")
        print("\nTier 1 services (recommended):")
        print("  - compute, network, storage, monitor, security")
        return 1
    
    success, rules = generate_service_with_quality_control(service)
    
    if success:
        print(f"\n{'='*80}")
        print(f" ✅ SUCCESS - {service.upper()} SERVICE GENERATED")
        print(f"{'='*80}")
        print(f"\nNext: Test the service")
        print(f"  python3 -m azure_compliance_python_engine.engine.targeted_scan --services {service} --save-report")
        return 0
    else:
        print(f"\n❌ Generation failed for {service}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

