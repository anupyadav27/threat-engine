#!/usr/bin/env python3
"""
BOTO3 SCHEMA VALIDATOR & AUTO-FIXER
Validates and fixes AWS service checks using actual Boto3 schemas
"""

import boto3
import yaml
import json
from pathlib import Path
from collections import defaultdict
import botocore.loaders
from botocore import xform_name

class Boto3SchemaValidator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.boto3_session = boto3.Session()
        self.loader = botocore.loaders.Loader()
        
        # Load all available services
        self.available_services = self.boto3_session.get_available_services()
        
        # Cache for service models
        self.service_models = {}
        
        print(f"✅ Loaded {len(self.available_services)} AWS services from Boto3")
    
    def get_service_model(self, service_name):
        """Get Boto3 service model (API spec)"""
        
        if service_name in self.service_models:
            return self.service_models[service_name]
        
        try:
            # Try to create client to validate service exists
            client = self.boto3_session.client(service_name, region_name='us-east-1')
            
            # Get the service model
            api_version = client._service_model.api_version
            service_model = self.loader.load_service_model(service_name, 'service-2', api_version)
            
            self.service_models[service_name] = {
                'client': client,
                'model': service_model,
                'operations': service_model.get('operations', {}),
                'shapes': service_model.get('shapes', {})
            }
            
            return self.service_models[service_name]
            
        except Exception as e:
            print(f"  ⚠️  Service '{service_name}' not found in Boto3: {str(e)}")
            return None
    
    def get_operation_info(self, service_name, operation_name):
        """Get information about a specific operation"""
        
        model = self.get_service_model(service_name)
        
        if not model:
            return None
        
        operations = model['operations']
        
        # Try exact match
        if operation_name in operations:
            return operations[operation_name]
        
        # Try with transformed name (e.g., list_buckets -> ListBuckets)
        pascal_name = ''.join(word.capitalize() for word in operation_name.split('_'))
        if pascal_name in operations:
            return operations[pascal_name]
        
        return None
    
    def get_response_structure(self, service_name, operation_name):
        """Get the response structure for an operation"""
        
        op_info = self.get_operation_info(service_name, operation_name)
        
        if not op_info:
            return None
        
        output_shape = op_info.get('output', {}).get('shape')
        
        if not output_shape:
            return None
        
        model = self.get_service_model(service_name)
        shapes = model['shapes']
        
        if output_shape in shapes:
            return self.resolve_shape(shapes[output_shape], shapes)
        
        return None
    
    def resolve_shape(self, shape, shapes, depth=0, max_depth=3):
        """Recursively resolve shape references"""
        
        if depth > max_depth:
            return {'type': 'unknown', 'note': 'max_depth_reached'}
        
        shape_type = shape.get('type')
        
        if shape_type == 'structure':
            members = {}
            for member_name, member_info in shape.get('members', {}).items():
                member_shape_ref = member_info.get('shape')
                if member_shape_ref in shapes:
                    members[member_name] = self.resolve_shape(shapes[member_shape_ref], shapes, depth + 1)
                else:
                    members[member_name] = {'type': 'unknown'}
            return {'type': 'structure', 'members': members}
        
        elif shape_type == 'list':
            member_shape_ref = shape.get('member', {}).get('shape')
            if member_shape_ref in shapes:
                return {
                    'type': 'list',
                    'member': self.resolve_shape(shapes[member_shape_ref], shapes, depth + 1)
                }
            return {'type': 'list', 'member': {'type': 'unknown'}}
        
        elif shape_type == 'map':
            return {'type': 'map'}
        
        else:
            return {'type': shape_type or 'unknown'}
    
    def validate_discovery_step(self, service_name, discovery_step):
        """Validate a discovery step against Boto3"""
        
        issues = []
        suggestions = []
        
        disc_id = discovery_step.get('discovery_id', 'unknown')
        
        for call in discovery_step.get('calls', []):
            client_name = call.get('client')
            action = call.get('action')
            
            if not action:
                issues.append({
                    'type': 'missing_action',
                    'discovery_id': disc_id,
                    'message': 'No action specified'
                })
                continue
            
            # Check if operation exists in Boto3
            op_info = self.get_operation_info(service_name, action)
            
            if not op_info:
                issues.append({
                    'type': 'invalid_operation',
                    'discovery_id': disc_id,
                    'action': action,
                    'message': f"Operation '{action}' not found in Boto3 for service '{service_name}'"
                })
                
                # Try to suggest alternatives
                model = self.get_service_model(service_name)
                if model:
                    operations = model['operations']
                    # Find similar operations
                    similar_ops = [op for op in operations.keys() 
                                  if action.replace('_', '').lower() in op.lower()]
                    if similar_ops:
                        suggestions.append({
                            'discovery_id': disc_id,
                            'action': action,
                            'suggestions': similar_ops[:3]
                        })
            else:
                # Get response structure
                response_structure = self.get_response_structure(service_name, action)
                
                if response_structure:
                    suggestions.append({
                        'discovery_id': disc_id,
                        'action': action,
                        'response_structure': response_structure
                    })
        
        return {
            'discovery_id': disc_id,
            'issues': issues,
            'suggestions': suggestions
        }
    
    def validate_service(self, service_name):
        """Validate all discovery steps for a service"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return None
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            validation_results = {
                'service': service_name,
                'total_discovery': len(data.get('discovery', [])),
                'total_checks': len(data.get('checks', [])),
                'discovery_validations': [],
                'summary': {
                    'valid_operations': 0,
                    'invalid_operations': 0,
                    'total_operations': 0
                }
            }
            
            # Validate each discovery step
            for disc_step in data.get('discovery', []):
                validation = self.validate_discovery_step(service_name, disc_step)
                validation_results['discovery_validations'].append(validation)
                
                # Update summary
                validation_results['summary']['total_operations'] += len(disc_step.get('calls', []))
                validation_results['summary']['invalid_operations'] += len(validation['issues'])
            
            validation_results['summary']['valid_operations'] = (
                validation_results['summary']['total_operations'] - 
                validation_results['summary']['invalid_operations']
            )
            
            return validation_results
            
        except Exception as e:
            return {
                'service': service_name,
                'error': str(e)
            }
    
    def validate_all_services(self):
        """Validate all services"""
        
        print(f"\n{'='*80}")
        print(f"BOTO3 SCHEMA VALIDATION")
        print(f"{'='*80}\n")
        
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if service_dir.is_dir():
                rules_file = service_dir / "rules" / f"{service_dir.name}.yaml"
                if rules_file.exists():
                    services.append(service_dir.name)
        
        print(f"Validating {len(services)} services...\n")
        
        all_validations = []
        total_valid = 0
        total_invalid = 0
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] {service_name}")
            
            validation = self.validate_service(service_name)
            
            if validation and 'error' not in validation:
                all_validations.append(validation)
                
                valid = validation['summary']['valid_operations']
                invalid = validation['summary']['invalid_operations']
                total = validation['summary']['total_operations']
                
                total_valid += valid
                total_invalid += invalid
                
                if invalid == 0:
                    print(f"  ✅ {valid}/{total} operations valid")
                else:
                    print(f"  ⚠️  {valid}/{total} valid, {invalid} invalid")
            else:
                print(f"  ❌ Error: {validation.get('error', 'Unknown')}")
        
        # Summary
        print(f"\n{'='*80}")
        print(f"VALIDATION SUMMARY")
        print(f"{'='*80}")
        print(f"Services validated: {len(all_validations)}")
        print(f"Total operations: {total_valid + total_invalid}")
        print(f"Valid operations: {total_valid} ({total_valid/(total_valid+total_invalid)*100:.1f}%)")
        print(f"Invalid operations: {total_invalid} ({total_invalid/(total_valid+total_invalid)*100:.1f}%)")
        
        # Save results
        output_file = self.services_dir / "BOTO3_VALIDATION_RESULTS.json"
        with open(output_file, 'w') as f:
            json.dump(all_validations, f, indent=2)
        
        print(f"\n📄 Detailed results: {output_file}")
        
        # Generate fix recommendations
        self.generate_fix_recommendations(all_validations)
        
        return all_validations
    
    def generate_fix_recommendations(self, all_validations):
        """Generate recommendations for fixing invalid operations"""
        
        print(f"\n{'='*80}")
        print(f"FIX RECOMMENDATIONS")
        print(f"{'='*80}\n")
        
        services_needing_fixes = [v for v in all_validations 
                                  if v['summary']['invalid_operations'] > 0]
        
        print(f"Services needing fixes: {len(services_needing_fixes)}\n")
        
        recommendations = []
        
        for validation in services_needing_fixes[:10]:  # Top 10
            service = validation['service']
            
            print(f"## {service}")
            
            for disc_val in validation['discovery_validations']:
                for issue in disc_val['issues']:
                    if issue['type'] == 'invalid_operation':
                        print(f"  ❌ {issue['action']}")
                        
                        # Find suggestions
                        for sugg in disc_val['suggestions']:
                            if sugg.get('action') == issue['action'] and 'suggestions' in sugg:
                                print(f"     Suggestions: {', '.join(sugg['suggestions'])}")
                                
                                recommendations.append({
                                    'service': service,
                                    'discovery_id': issue['discovery_id'],
                                    'invalid_action': issue['action'],
                                    'suggested_actions': sugg['suggestions']
                                })
            print()
        
        # Save recommendations
        rec_file = self.services_dir / "FIX_RECOMMENDATIONS.json"
        with open(rec_file, 'w') as f:
            json.dump(recommendations, f, indent=2)
        
        print(f"📄 Fix recommendations: {rec_file}")

if __name__ == '__main__':
    print("🚀 Starting Boto3 Schema Validation...\n")
    
    validator = Boto3SchemaValidator()
    results = validator.validate_all_services()
    
    print(f"\n🎉 Validation complete!")
    print(f"\nNext steps:")
    print(f"1. Review BOTO3_VALIDATION_RESULTS.json")
    print(f"2. Review FIX_RECOMMENDATIONS.json")
    print(f"3. Run auto-fixer to correct invalid operations")

