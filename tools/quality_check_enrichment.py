#!/usr/bin/env python3
"""
Quality check for enum enrichment - validates that enum values are correct
by comparing with actual boto3 SDK service models.
"""

import json
import boto3
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from botocore.model import Shape
from collections import defaultdict

class EnrichmentQualityChecker:
    """Validate enum enrichment quality"""
    
    def __init__(self):
        self.stats = {
            'services_checked': 0,
            'fields_validated': 0,
            'fields_correct': 0,
            'fields_incorrect': 0,
            'fields_missing': 0,
            'fields_extra': 0,
            'errors': []
        }
        self.issues = []
    
    def extract_enum_from_shape(self, shape: Shape) -> Optional[List[str]]:
        """Extract enum values from a boto3 shape"""
        if shape is None:
            return None
        
        if hasattr(shape, 'enum') and shape.enum:
            return sorted(list(shape.enum))
        
        if shape.type_name == 'string':
            if hasattr(shape, 'metadata') and shape.metadata:
                enum_vals = shape.metadata.get('enum')
                if enum_vals:
                    return sorted(list(enum_vals))
        
        return None
    
    def find_field_in_shape(self, shape: Shape, field_path: str) -> Optional[Shape]:
        """Find a field in a shape by path"""
        if not shape:
            return None
        
        parts = field_path.split('.')
        current_shape = shape
        
        for part in parts:
            if current_shape.type_name == 'structure':
                if part in current_shape.members:
                    current_shape = current_shape.members[part]
                else:
                    return None
            elif current_shape.type_name == 'list':
                current_shape = current_shape.member
                if current_shape and current_shape.type_name == 'structure':
                    if part in current_shape.members:
                        current_shape = current_shape.members[part]
                    else:
                        return None
                else:
                    return None
            else:
                return None
        
        return current_shape
    
    def validate_operation_fields(self, service_name: str, operation_name: str,
                                 enriched_data: Dict) -> Dict[str, Any]:
        """Validate enum values for an operation"""
        
        validation_results = {
            'correct': [],
            'incorrect': [],
            'missing': [],
            'extra': []
        }
        
        try:
            client = boto3.client(service_name, region_name='us-east-1')
            service_model = client._service_model
            
            if operation_name not in service_model.operation_names:
                return validation_results
            
            op_model = service_model.operation_model(operation_name)
            output_shape = op_model.output_shape
            
            if not output_shape:
                return validation_results
            
            # Validate output_fields
            if 'output_fields' in enriched_data:
                for field_name, field_data in enriched_data['output_fields'].items():
                    field_shape = self.find_field_in_shape(output_shape, field_name)
                    actual_enum = self.extract_enum_from_shape(field_shape) if field_shape else None
                    
                    if 'possible_values' in field_data:
                        enriched_enum = sorted(field_data['possible_values'])
                        
                        if actual_enum:
                            if enriched_enum == actual_enum:
                                validation_results['correct'].append(field_name)
                                self.stats['fields_correct'] += 1
                            else:
                                validation_results['incorrect'].append({
                                    'field': field_name,
                                    'enriched': enriched_enum,
                                    'actual': actual_enum
                                })
                                self.stats['fields_incorrect'] += 1
                        else:
                            # Field has enum in enriched but not in actual (might be valid if nested)
                            validation_results['extra'].append(field_name)
                            self.stats['fields_extra'] += 1
                    elif actual_enum:
                        # Field has enum in actual but not in enriched
                        validation_results['missing'].append({
                            'field': field_name,
                            'actual': actual_enum
                        })
                        self.stats['fields_missing'] += 1
            
            # Validate item_fields
            if 'item_fields' in enriched_data:
                main_output_field = enriched_data.get('main_output_field', '')
                
                if main_output_field and main_output_field in output_shape.members:
                    list_shape = output_shape.members[main_output_field]
                    
                    if list_shape.type_name == 'list':
                        item_shape = list_shape.member
                        
                        if item_shape and item_shape.type_name == 'structure':
                            for field_name, field_data in enriched_data['item_fields'].items():
                                if field_name in item_shape.members:
                                    field_shape = item_shape.members[field_name]
                                    actual_enum = self.extract_enum_from_shape(field_shape)
                                    
                                    if 'possible_values' in field_data:
                                        enriched_enum = sorted(field_data['possible_values'])
                                        
                                        if actual_enum:
                                            if enriched_enum == actual_enum:
                                                validation_results['correct'].append(f"item.{field_name}")
                                                self.stats['fields_correct'] += 1
                                            else:
                                                validation_results['incorrect'].append({
                                                    'field': f"item.{field_name}",
                                                    'enriched': enriched_enum,
                                                    'actual': actual_enum
                                                })
                                                self.stats['fields_incorrect'] += 1
                                        else:
                                            validation_results['extra'].append(f"item.{field_name}")
                                            self.stats['fields_extra'] += 1
                                    elif actual_enum:
                                        validation_results['missing'].append({
                                            'field': f"item.{field_name}",
                                            'actual': actual_enum
                                        })
                                        self.stats['fields_missing'] += 1
            
            self.stats['fields_validated'] += len(validation_results['correct']) + \
                                               len(validation_results['incorrect']) + \
                                               len(validation_results['missing']) + \
                                               len(validation_results['extra'])
            
        except Exception as e:
            error_msg = f"Error validating {service_name}.{operation_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            self.issues.append({
                'service': service_name,
                'operation': operation_name,
                'error': str(e)
            })
        
        return validation_results
    
    def get_boto3_service_name(self, service_name: str) -> str:
        """Map service name to boto3 service name"""
        mappings = {
            'cognito': 'cognito-idp',
            'vpc': 'ec2',
            'vpcflowlogs': 'ec2',
            'workflows': 'stepfunctions',
            'parameterstore': 'ssm',
            'elastic': 'es',
            'eip': 'ec2',
            'eventbridge': 'events',
            'fargate': 'ecs',
            'kinesisfirehose': 'firehose',
            'costexplorer': 'ce',
            'directoryservice': 'ds',
            'identitycenter': 'sso',
            'macie': 'macie2',
            'networkfirewall': 'network-firewall',
            'edr': 'guardduty',
            'kinesisvideostreams': 'kinesisvideo',
            'timestream': 'timestream-query',
        }
        return mappings.get(service_name, service_name)
    
    def check_service(self, service_path: Path, sample_ops: int = 5) -> Dict[str, Any]:
        """Check a single service"""
        
        enriched_file = service_path / "boto3_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return {'error': 'File not found'}
        
        try:
            with open(enriched_file) as f:
                data = json.load(f)
            
            service_name = service_path.name
            boto3_service_name = self.get_boto3_service_name(service_name)
            
            results = {
                'service': service_name,
                'correct': 0,
                'incorrect': 0,
                'missing': 0,
                'extra': 0,
                'errors': []
            }
            
            # Check independent operations (sample first N)
            if service_name in data and 'independent' in data[service_name]:
                ops_to_check = data[service_name]['independent'][:sample_ops]
                for op_data in ops_to_check:
                    validation = self.validate_operation_fields(
                        boto3_service_name,
                        op_data['operation'],
                        op_data
                    )
                    results['correct'] += len(validation['correct'])
                    results['incorrect'] += len(validation['incorrect'])
                    results['missing'] += len(validation['missing'])
                    results['extra'] += len(validation['extra'])
                    
                    if validation['incorrect']:
                        results['errors'].extend(validation['incorrect'])
            
            self.stats['services_checked'] += 1
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_sample_services(self, root_path: Path, sample_size: int = 20):
        """Check a sample of services"""
        
        print(f"\n{'='*70}")
        print(f"QUALITY CHECK: ENUM ENRICHMENT VALIDATION")
        print(f"{'='*70}\n")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        # Sample services (prioritize common ones)
        priority_services = ['acm', 's3', 'iam', 'ec2', 'rds', 'lambda', 'cloudformation']
        sample_services = []
        
        for svc in priority_services:
            svc_path = root_path / svc
            if svc_path in service_dirs:
                sample_services.append(svc_path)
        
        # Add random samples
        remaining = [s for s in service_dirs if s not in sample_services]
        sample_services.extend(remaining[:sample_size - len(sample_services)])
        
        print(f"Checking {len(sample_services)} services...\n")
        
        for i, service_path in enumerate(sample_services, 1):
            service_name = service_path.name
            print(f"[{i}/{len(sample_services)}] {service_name}...", end=" ")
            
            result = self.check_service(service_path)
            
            if 'error' in result:
                print(f"❌ {result['error']}")
            else:
                total = result['correct'] + result['incorrect'] + result['missing'] + result['extra']
                if total > 0:
                    accuracy = (result['correct'] / total * 100) if total > 0 else 0
                    print(f"✓ {result['correct']}/{total} correct ({accuracy:.1f}%)")
                    if result['incorrect'] > 0:
                        print(f"    ⚠️  {result['incorrect']} incorrect, {result['missing']} missing")
                else:
                    print("✓ (no enum fields to validate)")
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"QUALITY CHECK SUMMARY")
        print(f"{'='*70}")
        print(f"Services checked: {self.stats['services_checked']}")
        print(f"Fields validated: {self.stats['fields_validated']}")
        print(f"Fields correct: {self.stats['fields_correct']}")
        print(f"Fields incorrect: {self.stats['fields_incorrect']}")
        print(f"Fields missing: {self.stats['fields_missing']}")
        print(f"Fields extra: {self.stats['fields_extra']}")
        
        if self.stats['fields_validated'] > 0:
            accuracy = (self.stats['fields_correct'] / self.stats['fields_validated'] * 100)
            print(f"\nOverall Accuracy: {accuracy:.1f}%")
        
        if self.stats['fields_incorrect'] > 0 or self.stats['fields_missing'] > 0:
            print(f"\n⚠️  Issues found:")
            print(f"   - {self.stats['fields_incorrect']} fields with incorrect enum values")
            print(f"   - {self.stats['fields_missing']} fields missing enum values")
        
        if self.stats['errors']:
            print(f"\n❌ Errors: {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:
                print(f"   - {error}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Quality check enum enrichment'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/aws',
        help='Root path for services'
    )
    parser.add_argument(
        '--sample',
        type=int,
        default=20,
        help='Number of services to sample (default: 20)'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    checker = EnrichmentQualityChecker()
    checker.check_sample_services(root_path, args.sample)


if __name__ == '__main__':
    main()

