#!/usr/bin/env python3
"""
COMPREHENSIVE BOTO3 VALIDATOR
Validates all service YAML files against actual Boto3 schemas
- Verifies client names exist
- Validates method names
- Checks parameter names and structure
- Provides detailed fixing recommendations
"""

import boto3
import yaml
from pathlib import Path
import json
from datetime import datetime
from botocore.exceptions import UnknownServiceError
import logging

logging.basicConfig(level=logging.WARNING)

class ComprehensiveBoto3Validator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.session = boto3.Session()
        
        # Cache for boto3 clients and their operations
        self.client_cache = {}
        self.operation_cache = {}
        self.param_cache = {}
        
        # Validation results
        self.validation_report = {
            'timestamp': datetime.now().isoformat(),
            'services_validated': 0,
            'total_checks': 0,
            'total_discovery_steps': 0,
            'errors': {
                'invalid_client': [],
                'invalid_operation': [],
                'invalid_parameter': [],
                'missing_required_param': [],
                'invalid_field_path': []
            },
            'warnings': [],
            'services_summary': {}
        }
    
    def get_client_operations(self, service_name):
        """Get all available operations for a Boto3 service"""
        if service_name in self.operation_cache:
            return self.operation_cache[service_name]
        
        try:
            client = self.session.client(service_name, region_name='us-east-1')
            operations = [op for op in dir(client) if not op.startswith('_') and callable(getattr(client, op))]
            
            # Get detailed operation info
            service_model = client._service_model
            operation_details = {}
            
            for op_name in service_model.operation_names:
                operation_model = service_model.operation_model(op_name)
                
                # Convert to snake_case (Boto3 method name)
                method_name = self.pascal_to_snake(op_name)
                
                operation_details[method_name] = {
                    'operation_name': op_name,
                    'input_shape': None,
                    'output_shape': None,
                    'required_params': [],
                    'optional_params': []
                }
                
                # Get input parameters
                if operation_model.input_shape:
                    input_shape = operation_model.input_shape
                    operation_details[method_name]['input_shape'] = input_shape.name
                    
                    # Get required and optional parameters
                    if hasattr(input_shape, 'required_members'):
                        operation_details[method_name]['required_params'] = list(input_shape.required_members)
                    
                    if hasattr(input_shape, 'members'):
                        all_params = set(input_shape.members.keys())
                        required = set(operation_details[method_name]['required_params'])
                        operation_details[method_name]['optional_params'] = list(all_params - required)
                
                # Get output shape
                if operation_model.output_shape:
                    operation_details[method_name]['output_shape'] = operation_model.output_shape.name
            
            self.operation_cache[service_name] = operation_details
            return operation_details
            
        except UnknownServiceError:
            return None
        except Exception as e:
            print(f"  ⚠️  Error getting operations for {service_name}: {str(e)}")
            return None
    
    def pascal_to_snake(self, name):
        """Convert PascalCase to snake_case"""
        import re
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    
    def validate_service_file(self, service_name):
        """Validate a single service YAML file"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return None
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return None
            
            service_report = {
                'service_name': service_name,
                'discovery_steps': 0,
                'checks': 0,
                'errors': [],
                'warnings': [],
                'status': 'valid'
            }
            
            # Validate discovery steps
            for idx, disc_step in enumerate(data.get('discovery', [])):
                service_report['discovery_steps'] += 1
                self.validation_report['total_discovery_steps'] += 1
                
                disc_id = disc_step.get('discovery_id', f'unknown_{idx}')
                
                # Validate each call in discovery
                for call_idx, call in enumerate(disc_step.get('calls', [])):
                    client_name = call.get('client')
                    action = call.get('action')
                    params = call.get('params', {})
                    fields = call.get('fields', [])
                    
                    # Validate client
                    if client_name:
                        operations = self.get_client_operations(client_name)
                        
                        if operations is None:
                            error = {
                                'type': 'invalid_client',
                                'discovery_id': disc_id,
                                'call_index': call_idx,
                                'client': client_name,
                                'message': f"Client '{client_name}' does not exist in Boto3"
                            }
                            service_report['errors'].append(error)
                            self.validation_report['errors']['invalid_client'].append({
                                'service': service_name,
                                **error
                            })
                            service_report['status'] = 'invalid'
                            continue
                        
                        # Validate operation/action
                        if action:
                            if action not in operations:
                                # Try to find similar operations
                                similar = self.find_similar_operations(action, operations.keys())
                                
                                error = {
                                    'type': 'invalid_operation',
                                    'discovery_id': disc_id,
                                    'call_index': call_idx,
                                    'client': client_name,
                                    'action': action,
                                    'message': f"Operation '{action}' not found in '{client_name}'",
                                    'suggestions': similar[:3] if similar else []
                                }
                                service_report['errors'].append(error)
                                self.validation_report['errors']['invalid_operation'].append({
                                    'service': service_name,
                                    **error
                                })
                                service_report['status'] = 'invalid'
                            else:
                                # Validate parameters
                                operation_info = operations[action]
                                
                                # Check required parameters
                                for req_param in operation_info['required_params']:
                                    if req_param not in params:
                                        warning = {
                                            'type': 'missing_required_param',
                                            'discovery_id': disc_id,
                                            'call_index': call_idx,
                                            'client': client_name,
                                            'action': action,
                                            'parameter': req_param,
                                            'message': f"Required parameter '{req_param}' missing for '{action}'"
                                        }
                                        service_report['warnings'].append(warning)
                                        self.validation_report['warnings'].append({
                                            'service': service_name,
                                            **warning
                                        })
                                
                                # Check if provided parameters are valid
                                all_params = operation_info['required_params'] + operation_info['optional_params']
                                for param_name in params.keys():
                                    if param_name not in all_params:
                                        error = {
                                            'type': 'invalid_parameter',
                                            'discovery_id': disc_id,
                                            'call_index': call_idx,
                                            'client': client_name,
                                            'action': action,
                                            'parameter': param_name,
                                            'message': f"Parameter '{param_name}' not valid for '{action}'",
                                            'valid_params': all_params[:10]  # Show first 10
                                        }
                                        service_report['errors'].append(error)
                                        self.validation_report['errors']['invalid_parameter'].append({
                                            'service': service_name,
                                            **error
                                        })
                                        service_report['status'] = 'invalid'
            
            # Validate checks
            for check_idx, check in enumerate(data.get('checks', [])):
                service_report['checks'] += 1
                self.validation_report['total_checks'] += 1
                
                # Basic check validation (we won't validate full logic, just structure)
                rule_id = check.get('rule_id', f'unknown_check_{check_idx}')
                
                # Validate that referenced discovery IDs exist
                for_each = check.get('for_each', {})
                discovery_ref = for_each.get('discovery')
                
                if discovery_ref:
                    discovery_ids = [d.get('discovery_id') for d in data.get('discovery', [])]
                    if discovery_ref not in discovery_ids:
                        warning = {
                            'type': 'invalid_discovery_reference',
                            'rule_id': rule_id,
                            'discovery_ref': discovery_ref,
                            'message': f"Check references non-existent discovery ID '{discovery_ref}'"
                        }
                        service_report['warnings'].append(warning)
                        self.validation_report['warnings'].append({
                            'service': service_name,
                            **warning
                        })
            
            self.validation_report['services_summary'][service_name] = service_report
            return service_report
            
        except Exception as e:
            print(f"  ❌ Error validating {service_name}: {str(e)}")
            return None
    
    def find_similar_operations(self, target, operations):
        """Find similar operation names using simple similarity"""
        from difflib import SequenceMatcher
        
        similarities = []
        for op in operations:
            ratio = SequenceMatcher(None, target.lower(), op.lower()).ratio()
            if ratio > 0.5:  # At least 50% similar
                similarities.append((op, ratio))
        
        return [op for op, _ in sorted(similarities, key=lambda x: x[1], reverse=True)]
    
    def validate_all_services(self):
        """Validate all service files"""
        
        print(f"\n{'='*80}")
        print(f"COMPREHENSIVE BOTO3 VALIDATOR")
        print(f"{'='*80}\n")
        
        print("Validating all service YAML files against Boto3 schemas...\n")
        
        # Get all service directories
        service_dirs = [d for d in self.services_dir.iterdir() if d.is_dir()]
        
        for idx, service_dir in enumerate(sorted(service_dirs), 1):
            service_name = service_dir.name
            print(f"[{idx}/{len(service_dirs)}] {service_name}", end='')
            
            report = self.validate_service_file(service_name)
            
            if report:
                self.validation_report['services_validated'] += 1
                
                if report['status'] == 'valid':
                    if report['warnings']:
                        print(f"  ⚠️  {len(report['warnings'])} warnings")
                    else:
                        print(f"  ✅")
                else:
                    print(f"  ❌ {len(report['errors'])} errors")
            else:
                print(f"  ⚠️  No data")
        
        # Generate summary
        self.generate_summary_report()
    
    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        
        print(f"\n{'='*80}")
        print(f"VALIDATION SUMMARY")
        print(f"{'='*80}\n")
        
        print(f"Services validated: {self.validation_report['services_validated']}")
        print(f"Total discovery steps: {self.validation_report['total_discovery_steps']}")
        print(f"Total checks: {self.validation_report['total_checks']}\n")
        
        print("Error Breakdown:")
        for error_type, errors in self.validation_report['errors'].items():
            if errors:
                print(f"  • {error_type}: {len(errors)}")
        
        if self.validation_report['warnings']:
            print(f"\nWarnings: {len(self.validation_report['warnings'])}")
        
        # Count services by status
        valid_count = sum(1 for s in self.validation_report['services_summary'].values() if s['status'] == 'valid')
        invalid_count = sum(1 for s in self.validation_report['services_summary'].values() if s['status'] == 'invalid')
        
        print(f"\nService Status:")
        print(f"  ✅ Valid: {valid_count}")
        print(f"  ❌ Invalid: {invalid_count}")
        
        # Save detailed report
        report_file = self.services_dir / "COMPREHENSIVE_VALIDATION_REPORT.json"
        with open(report_file, 'w') as f:
            json.dump(self.validation_report, f, indent=2)
        
        print(f"\n📄 Detailed report: {report_file}")
        
        # Generate fix recommendations
        self.generate_fix_recommendations()
    
    def generate_fix_recommendations(self):
        """Generate automated fix recommendations"""
        
        recommendations = {
            'timestamp': datetime.now().isoformat(),
            'total_fixes_needed': 0,
            'fixes_by_type': {},
            'detailed_fixes': []
        }
        
        # Invalid operations with suggestions
        for error in self.validation_report['errors']['invalid_operation']:
            if error.get('suggestions'):
                fix = {
                    'service': error['service'],
                    'discovery_id': error['discovery_id'],
                    'type': 'replace_operation',
                    'current': error['action'],
                    'suggested': error['suggestions'][0],
                    'alternatives': error['suggestions'][1:],
                    'confidence': 'high' if len(error['suggestions']) == 1 else 'medium'
                }
                recommendations['detailed_fixes'].append(fix)
                recommendations['total_fixes_needed'] += 1
        
        # Invalid clients
        for error in self.validation_report['errors']['invalid_client']:
            fix = {
                'service': error['service'],
                'discovery_id': error['discovery_id'],
                'type': 'fix_client_name',
                'current': error['client'],
                'message': 'Client does not exist in Boto3',
                'confidence': 'critical'
            }
            recommendations['detailed_fixes'].append(fix)
            recommendations['total_fixes_needed'] += 1
        
        # Count by type
        for fix in recommendations['detailed_fixes']:
            fix_type = fix['type']
            recommendations['fixes_by_type'][fix_type] = recommendations['fixes_by_type'].get(fix_type, 0) + 1
        
        # Save recommendations
        rec_file = self.services_dir / "BOTO3_FIX_RECOMMENDATIONS.json"
        with open(rec_file, 'w') as f:
            json.dump(recommendations, f, indent=2)
        
        print(f"📄 Fix recommendations: {rec_file}")
        
        print(f"\n{'='*80}")
        print(f"ACTIONABLE INSIGHTS")
        print(f"{'='*80}\n")
        
        if recommendations['total_fixes_needed'] > 0:
            print(f"Total fixes needed: {recommendations['total_fixes_needed']}\n")
            
            for fix_type, count in recommendations['fixes_by_type'].items():
                print(f"  • {fix_type}: {count}")
            
            print(f"\n💡 Next: Review BOTO3_FIX_RECOMMENDATIONS.json and apply fixes")
        else:
            print("🎉 All services pass Boto3 schema validation!")

if __name__ == '__main__':
    print("🔍 Starting Comprehensive Boto3 Validation...\n")
    
    validator = ComprehensiveBoto3Validator()
    validator.validate_all_services()
    
    print(f"\n✅ Validation complete!")

