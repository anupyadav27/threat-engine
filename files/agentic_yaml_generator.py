#!/usr/bin/env python3
"""
Agentic AWS Service YAML Generator - Working Prototype
Uses Claude API to power specialized agents
"""

import json
import yaml
import os
from typing import Dict, List, Tuple
from pathlib import Path

# Note: In production, use actual Claude API
# This is a prototype showing the structure

class AWSSDKExpertAgent:
    """Agent 1: AWS SDK Expert - knows exact API response structures"""
    
    def get_operation_details(self, service: str, operation: str) -> Dict:
        """
        Query AWS SDK documentation to get exact field names and structures
        
        In production, this would:
        1. Call Claude API with AWS SDK documentation
        2. Ask for exact response structure
        3. Get example responses
        """
        
        prompt = f"""
You are an AWS SDK expert. Provide EXACT field names and structures.

Service: {service}
Operation: {operation}

Provide:
1. Exact SDK method name (snake_case)
2. Required parameters with types
3. Response structure with EXACT field names (case-sensitive)
4. Example response with real values
5. Any nested structures

Be precise - these field names will be used in code generation.
Do not guess - only provide information you're certain about.

Format response as JSON.
"""
        
        # In production: response = call_claude_api(prompt)
        # For prototype, return known structures
        
        known_responses = {
            ('s3', 'GetBucketVersioning'): {
                'sdk_method': 'get_bucket_versioning',
                'parameters': [
                    {'name': 'Bucket', 'type': 'string', 'required': True}
                ],
                'response_structure': {
                    'Status': 'string',  # NOT VersioningStatus!
                    'MFADelete': 'string'
                },
                'example_response': {
                    'Status': 'Enabled',
                    'MFADelete': 'Disabled'
                },
                'notes': 'Status can be: Enabled, Suspended'
            },
            ('s3', 'GetBucketEncryption'): {
                'sdk_method': 'get_bucket_encryption',
                'parameters': [
                    {'name': 'Bucket', 'type': 'string', 'required': True}
                ],
                'response_structure': {
                    'ServerSideEncryptionConfiguration': {
                        'Rules': 'array'
                    }
                },
                'example_response': {
                    'ServerSideEncryptionConfiguration': {
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }]
                    }
                }
            },
            ('ec2', 'DescribeInstances'): {
                'sdk_method': 'describe_instances',
                'parameters': [],
                'response_structure': {
                    'Reservations': {
                        'Instances': {
                            'State': {
                                'Name': 'string'  # running, stopped, etc.
                            },
                            'InstanceId': 'string',
                            'InstanceType': 'string'
                        }
                    }
                },
                'example_response': {
                    'Reservations': [{
                        'Instances': [{
                            'InstanceId': 'i-1234567890abcdef0',
                            'State': {
                                'Name': 'running',  # NOT "ENABLED"!
                                'Code': 16
                            }
                        }]
                    }]
                }
            }
        }
        
        key = (service, operation)
        if key in known_responses:
            return known_responses[key]
        
        # Fallback for unknown operations
        return {
            'sdk_method': self._to_snake_case(operation),
            'parameters': [],
            'response_structure': {'Status': 'string'},
            'confidence': 0.3,
            'note': 'Unknown operation - please verify manually'
        }
    
    def _to_snake_case(self, name: str) -> str:
        import re
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class MetadataAnalyzerAgent:
    """Agent 2: Analyzes metadata to understand requirements"""
    
    def analyze(self, metadata: Dict) -> Dict:
        """
        Analyze metadata file to extract key information
        
        In production: Use Claude to semantically understand requirements
        """
        
        requirement = metadata.get('requirement', '').lower()
        resource = metadata.get('resource', '')
        
        # Classify check type
        check_type = self._classify_check_type(requirement)
        
        # Extract expected field and value
        expected_field, expected_value = self._infer_expectation(
            requirement, 
            check_type
        )
        
        return {
            'rule_id': metadata.get('rule_id'),
            'service': metadata.get('service'),
            'resource': resource,
            'requirement': metadata.get('requirement'),
            'check_type': check_type,
            'expected_field': expected_field,
            'expected_value': expected_value,
            'severity': metadata.get('severity'),
            'description': metadata.get('description', '')
        }
    
    def _classify_check_type(self, requirement: str) -> str:
        """Classify what type of check this is"""
        if 'enabled' in requirement or 'disabled' in requirement:
            return 'boolean_status'
        elif 'encrypted' in requirement or 'encryption' in requirement:
            return 'encryption_check'
        elif 'versioning' in requirement:
            return 'versioning_check'
        elif 'logging' in requirement:
            return 'logging_check'
        elif 'public' in requirement:
            return 'public_access_check'
        elif 'mfa' in requirement:
            return 'mfa_check'
        elif 'multi-az' in requirement or 'multi az' in requirement:
            return 'multi_az_check'
        elif 'backup' in requirement:
            return 'backup_check'
        elif 'policy' in requirement or 'privilege' in requirement:
            return 'policy_check'
        else:
            return 'custom_check'
    
    def _infer_expectation(self, requirement: str, check_type: str) -> Tuple[str, any]:
        """Infer what field and value we're looking for"""
        field_value_map = {
            'boolean_status': ('Status', 'Enabled'),
            'encryption_check': ('ServerSideEncryptionConfiguration', 'exists'),
            'versioning_check': ('VersioningStatus', 'Enabled'),
            'logging_check': ('LoggingEnabled', True),
            'public_access_check': ('BlockPublicAccess', True),
            'mfa_check': ('MFAEnabled', True),
            'multi_az_check': ('MultiAZ', True),
            'backup_check': ('BackupRetentionPeriod', '>0'),
        }
        
        return field_value_map.get(check_type, ('Status', 'Unknown'))


class DiscoveryGeneratorAgent:
    """Agent 3: Generates discovery sections"""
    
    def generate(self, service: str, resource: str, operation: str,
                 sdk_details: Dict, for_each: str = None) -> Dict:
        """Generate discovery entry with exact field names from SDK"""
        
        discovery_id = f"aws.{service}.{sdk_details['sdk_method']}"
        
        discovery = {
            'discovery_id': discovery_id,
            'calls': [{
                'action': sdk_details['sdk_method'],
                'save_as': 'response',
                'params': {}
            }],
            'on_error': 'continue',
            'emit': {
                'item': {}
            }
        }
        
        # Add parameters
        for param in sdk_details.get('parameters', []):
            if param.get('required'):
                param_name = param['name']
                if for_each:
                    # Link parameter to previous discovery
                    discovery['calls'][0]['params'][param_name] = f"{{{{ item.{param_name} }}}}"
        
        # Add for_each if specified
        if for_each:
            discovery['for_each'] = for_each
        
        # Add emit fields from SDK response structure
        response_structure = sdk_details.get('response_structure', {})
        self._add_emit_fields(discovery['emit']['item'], response_structure, 'response')
        
        return discovery
    
    def _add_emit_fields(self, emit_dict: Dict, structure: Dict, path: str):
        """Recursively add emit fields from SDK structure"""
        for field_name, field_type in structure.items():
            if isinstance(field_type, dict):
                # Nested structure - add the whole object
                emit_dict[field_name] = f"{{{{ {path}.{field_name} }}}}"
            else:
                # Simple field
                emit_dict[field_name] = f"{{{{ {path}.{field_name} }}}}"


class CheckGeneratorAgent:
    """Agent 4: Generates check conditions"""
    
    def generate(self, metadata_analysis: Dict, sdk_details: Dict,
                 discovery_id: str, available_fields: List[str]) -> Tuple[Dict, float]:
        """
        Generate check with exact field names
        Returns: (check_dict, confidence_score)
        """
        
        check_type = metadata_analysis['check_type']
        expected_field = metadata_analysis['expected_field']
        expected_value = metadata_analysis['expected_value']
        
        # Find actual field name in SDK response
        actual_field, confidence = self._find_actual_field(
            expected_field,
            available_fields,
            sdk_details
        )
        
        # Determine operator and value
        operator, value = self._determine_operator_value(
            check_type,
            expected_value,
            sdk_details
        )
        
        check = {
            'rule_id': metadata_analysis['rule_id'],
            'for_each': discovery_id,
            'conditions': {
                'var': f'item.{actual_field}',
                'op': operator
            }
        }
        
        # Add value if needed
        if operator not in ['exists', 'not_exists']:
            check['conditions']['value'] = value
        
        # Add metadata for review
        if confidence < 0.8:
            check['_needs_review'] = True
            check['_confidence'] = confidence
            check['_note'] = f"Expected field '{expected_field}', using '{actual_field}'"
        
        return check, confidence
    
    def _find_actual_field(self, expected_field: str, available_fields: List[str],
                           sdk_details: Dict) -> Tuple[str, float]:
        """
        Find actual field name in SDK response
        Returns: (actual_field_name, confidence_score)
        """
        
        # Exact match
        if expected_field in available_fields:
            return expected_field, 1.0
        
        # Try variations
        variations = [
            expected_field,
            expected_field.replace('_', ''),
            expected_field.title().replace('_', ''),
            # Handle common patterns
            expected_field.replace('VersioningStatus', 'Status'),
            expected_field.replace('Encrypted', 'StorageEncrypted'),
        ]
        
        for variation in variations:
            if variation in available_fields:
                return variation, 0.9
        
        # Partial match
        for field in available_fields:
            if expected_field.lower() in field.lower():
                return field, 0.7
        
        # Fallback to Status
        if 'Status' in available_fields:
            return 'Status', 0.5
        
        # Last resort
        return expected_field, 0.3
    
    def _determine_operator_value(self, check_type: str, expected_value: any,
                                   sdk_details: Dict) -> Tuple[str, any]:
        """Determine correct operator and value from check type"""
        
        if check_type == 'encryption_check':
            return 'exists', None
        
        elif check_type == 'boolean_status':
            # Check if value should be boolean or string
            if isinstance(expected_value, bool):
                return 'equals', expected_value
            else:
                # Get actual format from SDK
                example = sdk_details.get('example_response', {})
                # Check actual format in example
                return 'equals', expected_value
        
        elif check_type == 'backup_check' and '>0' in str(expected_value):
            return 'gt', 0
        
        else:
            return 'equals', expected_value


class ValidatorAgent:
    """Agent 5: Validates generated YAML"""
    
    def validate(self, service_yaml: Dict, sdk_details: Dict,
                 metadata_analyses: List[Dict]) -> Dict:
        """
        Comprehensive validation of generated YAML
        """
        
        issues = []
        warnings = []
        confidence_scores = []
        
        discoveries = service_yaml.get('discovery', [])
        checks = service_yaml.get('checks', [])
        
        # Validate each check
        for check in checks:
            check_validation = self._validate_check(
                check, 
                discoveries,
                sdk_details
            )
            
            if check_validation['issues']:
                issues.extend(check_validation['issues'])
            if check_validation['warnings']:
                warnings.extend(check_validation['warnings'])
            
            confidence_scores.append(check_validation['confidence'])
        
        # Calculate overall confidence
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            'status': 'pass' if not issues else 'fail',
            'confidence_score': overall_confidence,
            'issues': issues,
            'warnings': warnings,
            'needs_review': overall_confidence < 0.8 or len(issues) > 0,
            'summary': {
                'total_checks': len(checks),
                'high_confidence': len([s for s in confidence_scores if s >= 0.8]),
                'medium_confidence': len([s for s in confidence_scores if 0.5 <= s < 0.8]),
                'low_confidence': len([s for s in confidence_scores if s < 0.5])
            }
        }
    
    def _validate_check(self, check: Dict, discoveries: List[Dict],
                       sdk_details: Dict) -> Dict:
        """Validate individual check"""
        
        issues = []
        warnings = []
        confidence = check.get('_confidence', 0.9)
        
        # Find referenced discovery
        discovery_id = check.get('for_each')
        discovery = next((d for d in discoveries if d['discovery_id'] == discovery_id), None)
        
        if not discovery:
            issues.append(f"Discovery '{discovery_id}' not found for check {check['rule_id']}")
            return {'issues': issues, 'warnings': warnings, 'confidence': 0.1}
        
        # Check if field is emitted
        var = check['conditions'].get('var', '').replace('item.', '')
        emitted_fields = discovery.get('emit', {}).get('item', {}).keys()
        
        if var not in emitted_fields:
            issues.append(f"Field '{var}' not emitted by discovery '{discovery_id}'")
            confidence = min(confidence, 0.5)
        
        # Validate operator
        valid_ops = ['equals', 'not_equals', 'exists', 'not_exists', 'gt', 'lt', 'gte', 'lte']
        op = check['conditions'].get('op')
        if op not in valid_ops:
            issues.append(f"Invalid operator '{op}' in check {check['rule_id']}")
        
        # Check for review flags
        if check.get('_needs_review'):
            warnings.append(f"Check {check['rule_id']} flagged for manual review")
        
        return {
            'issues': issues,
            'warnings': warnings,
            'confidence': confidence
        }


class OrchestratorAgent:
    """Main orchestrator that coordinates all agents"""
    
    def __init__(self):
        self.sdk_expert = AWSSDKExpertAgent()
        self.metadata_analyzer = MetadataAnalyzerAgent()
        self.discovery_generator = DiscoveryGeneratorAgent()
        self.check_generator = CheckGeneratorAgent()
        self.validator = ValidatorAgent()
    
    def generate_service_yaml(self, service: str, metadata_files: List[Dict]) -> Dict:
        """
        Main orchestration logic
        """
        
        print(f"\n{'='*80}")
        print(f"Generating YAML for {service} with agentic system")
        print(f"{'='*80}\n")
        
        # Phase 1: Analyze metadata
        print("Phase 1: Analyzing metadata...")
        metadata_analyses = []
        for metadata in metadata_files:
            analysis = self.metadata_analyzer.analyze(metadata)
            metadata_analyses.append(analysis)
        print(f"  ✓ Analyzed {len(metadata_analyses)} metadata files")
        
        # Phase 2: Get AWS SDK details
        print("\nPhase 2: Querying AWS SDK expert...")
        required_operations = self._extract_required_operations(metadata_analyses)
        sdk_details_map = {}
        for operation in required_operations:
            sdk_details = self.sdk_expert.get_operation_details(service, operation)
            sdk_details_map[operation] = sdk_details
            print(f"  ✓ Got SDK details for {operation}")
        
        # Phase 3: Generate discoveries
        print("\nPhase 3: Generating discoveries...")
        discoveries = self._generate_discoveries(
            service,
            metadata_analyses,
            sdk_details_map
        )
        print(f"  ✓ Generated {len(discoveries)} discoveries")
        
        # Phase 4: Generate checks
        print("\nPhase 4: Generating checks...")
        checks = []
        for metadata_analysis in metadata_analyses:
            discovery_id, available_fields = self._find_discovery_for_check(
                metadata_analysis,
                discoveries
            )
            
            operation = self._get_operation_for_resource(metadata_analysis)
            sdk_details = sdk_details_map.get(operation, {})
            
            check, confidence = self.check_generator.generate(
                metadata_analysis,
                sdk_details,
                discovery_id,
                available_fields
            )
            
            checks.append(check)
            status = "✓" if confidence >= 0.8 else "⚠"
            print(f"  {status} Generated check for {metadata_analysis['rule_id']} (confidence: {confidence:.2f})")
        
        # Phase 5: Assemble YAML
        service_yaml = {
            'version': '1.0',
            'provider': 'aws',
            'service': service,
            'services': {
                'client': service,
                'module': 'boto3.client'
            },
            'discovery': discoveries,
            'checks': checks
        }
        
        # Phase 6: Validate
        print("\nPhase 5: Validating...")
        validation = self.validator.validate(
            service_yaml,
            sdk_details_map,
            metadata_analyses
        )
        
        print(f"\n{'='*80}")
        print(f"VALIDATION RESULTS")
        print(f"{'='*80}")
        print(f"Status: {validation['status']}")
        print(f"Confidence: {validation['confidence_score']:.2%}")
        print(f"High confidence checks: {validation['summary']['high_confidence']}")
        print(f"Medium confidence checks: {validation['summary']['medium_confidence']}")
        print(f"Low confidence checks: {validation['summary']['low_confidence']}")
        print(f"Needs review: {validation['needs_review']}")
        
        if validation['issues']:
            print(f"\nIssues found: {len(validation['issues'])}")
            for issue in validation['issues'][:5]:
                print(f"  ❌ {issue}")
        
        if validation['warnings']:
            print(f"\nWarnings: {len(validation['warnings'])}")
            for warning in validation['warnings'][:5]:
                print(f"  ⚠️  {warning}")
        
        # Add validation to YAML
        service_yaml['_validation'] = validation
        
        return service_yaml
    
    def _extract_required_operations(self, metadata_analyses: List[Dict]) -> List[str]:
        """Extract which AWS operations are needed"""
        operations = set()
        for analysis in metadata_analyses:
            resource = analysis['resource']
            # Map resource to operation
            operation = self._resource_to_operation(resource, analysis['check_type'])
            operations.add(operation)
        return list(operations)
    
    def _resource_to_operation(self, resource: str, check_type: str) -> str:
        """Map resource and check type to AWS operation"""
        mapping = {
            ('bucket', 'versioning_check'): 'GetBucketVersioning',
            ('bucket', 'encryption_check'): 'GetBucketEncryption',
            ('bucket', 'logging_check'): 'GetBucketLogging',
            ('bucket', 'public_access_check'): 'GetPublicAccessBlock',
            ('instance', 'boolean_status'): 'DescribeInstances',
        }
        
        key = (resource, check_type)
        if key in mapping:
            return mapping[key]
        
        # Default mapping
        return f"Get{resource.title()}"
    
    def _generate_discoveries(self, service: str, metadata_analyses: List[Dict],
                             sdk_details_map: Dict) -> List[Dict]:
        """Generate all needed discoveries"""
        discoveries = []
        generated_ops = set()
        
        # Add list operation first
        list_op = f"List{service.title()}s"
        if list_op not in generated_ops:
            # Would generate list discovery here
            generated_ops.add(list_op)
        
        # Add get operations for each unique operation needed
        for operation, sdk_details in sdk_details_map.items():
            if operation not in generated_ops:
                discovery = self.discovery_generator.generate(
                    service,
                    '',  # resource
                    operation,
                    sdk_details,
                    for_each=None  # Set if chained
                )
                discoveries.append(discovery)
                generated_ops.add(operation)
        
        return discoveries
    
    def _find_discovery_for_check(self, metadata_analysis: Dict,
                                  discoveries: List[Dict]) -> Tuple[str, List[str]]:
        """Find which discovery provides data for this check"""
        operation = self._get_operation_for_resource(metadata_analysis)
        
        for discovery in discoveries:
            if operation.lower() in discovery['discovery_id'].lower():
                available_fields = list(discovery['emit']['item'].keys())
                return discovery['discovery_id'], available_fields
        
        # Fallback
        if discoveries:
            return discoveries[0]['discovery_id'], list(discoveries[0]['emit']['item'].keys())
        
        return '', []
    
    def _get_operation_for_resource(self, metadata_analysis: Dict) -> str:
        """Get operation name for a metadata check"""
        return self._resource_to_operation(
            metadata_analysis['resource'],
            metadata_analysis['check_type']
        )


# Example usage
if __name__ == "__main__":
    # Example S3 metadata
    example_metadata = [
        {
            'rule_id': 'aws.s3.bucket.versioning_enabled',
            'service': 's3',
            'resource': 'bucket',
            'requirement': 'Version Control - Versioning Enabled',
            'severity': 'medium'
        },
        {
            'rule_id': 'aws.s3.bucket.encryption_enabled',
            'service': 's3',
            'resource': 'bucket',
            'requirement': 'Data Encryption - Encryption Enabled',
            'severity': 'high'
        }
    ]
    
    # Generate with agentic system
    orchestrator = OrchestratorAgent()
    result = orchestrator.generate_service_yaml('s3', example_metadata)
    
    # Save result
    output_file = Path('/home/claude/generated_service_yamls/s3_agentic.yaml')
    output_file.parent.mkdir(exist_ok=True)
    
    # Remove validation metadata before saving
    result_clean = {k: v for k, v in result.items() if not k.startswith('_')}
    
    with open(output_file, 'w') as f:
        yaml.dump(result_clean, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n✅ Generated YAML saved to: {output_file}")
    print(f"\nValidation confidence: {result['_validation']['confidence_score']:.2%}")
