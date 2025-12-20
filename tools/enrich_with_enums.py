#!/usr/bin/env python3
"""
Enrich boto3_dependencies_with_python_names_fully_enriched.json with possible values
extracted from boto3 SDK service models.
"""

import json
import boto3
from pathlib import Path
from typing import Dict, List, Any, Optional
from botocore.model import Shape
import sys

class Boto3EnumExtractor:
    """Extract enum values from boto3 service models"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
    
    def extract_enum_from_shape(self, shape: Shape) -> Optional[List[str]]:
        """Extract enum values from a boto3 shape"""
        if shape is None:
            return None
        
        # Direct enum attribute
        if hasattr(shape, 'enum') and shape.enum:
            return sorted(list(shape.enum))  # Sort for consistency
        
        # Check if it's a string type that might have enum
        if shape.type_name == 'string':
            # Some shapes have enum in metadata
            if hasattr(shape, 'metadata') and shape.metadata:
                enum_vals = shape.metadata.get('enum')
                if enum_vals:
                    return sorted(list(enum_vals))  # Sort for consistency
        
        return None
    
    def extract_field_enums(self, service_name: str, operation_name: str, 
                           field_path: str, shape: Shape) -> Optional[List[str]]:
        """Extract enum values for a specific field"""
        
        # Handle nested paths (e.g., "Certificate.Status")
        if '.' in field_path:
            parts = field_path.split('.')
            current_shape = shape
            
            for part in parts:
                if current_shape and current_shape.type_name == 'structure':
                    if part in current_shape.members:
                        current_shape = current_shape.members[part]
                    else:
                        return None
                else:
                    return None
            
            return self.extract_enum_from_shape(current_shape)
        else:
            # Direct field
            if shape and shape.type_name == 'structure':
                if field_path in shape.members:
                    return self.extract_enum_from_shape(shape.members[field_path])
        
        return None
    
    def enrich_operation_fields(self, service_name: str, operation_name: str,
                               enriched_data: Dict) -> Dict:
        """Enrich operation fields with enum values from boto3"""
        
        try:
            client = boto3.client(service_name, region_name='us-east-1')
            service_model = client._service_model
            
            if operation_name not in service_model.operation_names:
                return enriched_data
            
            op_model = service_model.operation_model(operation_name)
            output_shape = op_model.output_shape
            
            if not output_shape:
                return enriched_data
            
            # Enrich output_fields
            if 'output_fields' in enriched_data:
                for field_name, field_data in enriched_data['output_fields'].items():
                    enum_values = self.extract_field_enums(
                        service_name, operation_name, field_name, output_shape
                    )
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
            
            # Enrich item_fields (from list items)
            if 'item_fields' in enriched_data:
                # Find the list field in output
                main_output_field = enriched_data.get('main_output_field', '')
                
                if main_output_field and main_output_field in output_shape.members:
                    list_shape = output_shape.members[main_output_field]
                    
                    # If it's a list, get the member shape
                    if list_shape.type_name == 'list':
                        item_shape = list_shape.member
                        
                        # If item is a structure, extract fields
                        if item_shape and item_shape.type_name == 'structure':
                            for field_name, field_data in enriched_data['item_fields'].items():
                                if field_name in item_shape.members:
                                    enum_values = self.extract_enum_from_shape(
                                        item_shape.members[field_name]
                                    )
                                    if enum_values:
                                        field_data['enum'] = True
                                        field_data['possible_values'] = enum_values
                                        self.stats['enums_found'] += 1
                                        self.stats['fields_enriched'] += 1
                
                # Also try to find item fields in nested structures
                # Some operations return structures directly (not lists)
                for field_name, field_data in enriched_data['item_fields'].items():
                    # Skip if already enriched
                    if 'possible_values' in field_data:
                        continue
                    
                    # Try to find in output shape members
                    if output_shape.type_name == 'structure':
                        # Check if field exists directly
                        if field_name in output_shape.members:
                            enum_values = self.extract_enum_from_shape(
                                output_shape.members[field_name]
                            )
                            if enum_values:
                                field_data['enum'] = True
                                field_data['possible_values'] = enum_values
                                self.stats['enums_found'] += 1
                                self.stats['fields_enriched'] += 1
                        else:
                            # Try nested structures
                            for member_name, member_shape in output_shape.members.items():
                                if member_shape.type_name == 'structure':
                                    if field_name in member_shape.members:
                                        enum_values = self.extract_enum_from_shape(
                                            member_shape.members[field_name]
                                        )
                                        if enum_values:
                                            field_data['enum'] = True
                                            field_data['possible_values'] = enum_values
                                            self.stats['enums_found'] += 1
                                            self.stats['fields_enriched'] += 1
                                            break
            
            self.stats['operations_processed'] += 1
            
        except Exception as e:
            error_msg = f"Error enriching {service_name}.{operation_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            # Don't print for every error to avoid spam
        
        return enriched_data
    
    def get_boto3_service_name(self, service_name: str) -> str:
        """Map service name to boto3 service name"""
        # Service name mappings
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
            'amplifyuibuilder': 'amplifyuibuilder',
        }
        return mappings.get(service_name, service_name)
    
    def enrich_service_file(self, service_path: Path) -> bool:
        """Enrich a single service's enriched dependencies file"""
        
        enriched_file = service_path / "boto3_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return False
        
        try:
            with open(enriched_file, 'r') as f:
                data = json.load(f)
            
            service_name = service_path.name
            
            # Get boto3 service name (handle mappings)
            boto3_service_name = self.get_boto3_service_name(service_name)
            
            fields_before = self.stats['fields_enriched']
            
            # Process independent operations
            if service_name in data and 'independent' in data[service_name]:
                for op_data in data[service_name]['independent']:
                    op_data = self.enrich_operation_fields(
                        boto3_service_name,
                        op_data['operation'],
                        op_data
                    )
            
            # Process dependent operations
            if service_name in data and 'dependent' in data[service_name]:
                for op_data in data[service_name]['dependent']:
                    op_data = self.enrich_operation_fields(
                        boto3_service_name,
                        op_data['operation'],
                        op_data
                    )
            
            # Save enriched file
            with open(enriched_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            fields_added = self.stats['fields_enriched'] - fields_before
            self.stats['services_processed'] += 1
            
            if fields_added > 0:
                print(f"  ✓ {service_name}: Added {fields_added} enum values")
            
            return True
            
        except Exception as e:
            error_msg = f"Error processing {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"  ❌ {service_name}: {str(e)}")
            return False
    
    def enrich_all_services(self, root_path: Path):
        """Enrich all service files"""
        
        print(f"\n{'='*70}")
        print(f"ENRICHING BOTO3 DEPENDENCIES WITH ENUM VALUES")
        print(f"{'='*70}\n")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        print(f"Found {len(service_dirs)} services to enrich\n")
        
        for i, service_path in enumerate(sorted(service_dirs), 1):
            service_name = service_path.name
            print(f"[{i}/{len(service_dirs)}] {service_name}", end=" ... ")
            
            self.enrich_service_file(service_path)
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"ENRICHMENT SUMMARY")
        print(f"{'='*70}")
        print(f"Services processed: {self.stats['services_processed']}")
        print(f"Operations processed: {self.stats['operations_processed']}")
        print(f"Fields enriched: {self.stats['fields_enriched']}")
        print(f"Enums found: {self.stats['enums_found']}")
        print(f"Errors: {len(self.stats['errors'])}")
        
        if self.stats['errors']:
            print(f"\nFirst 10 errors:")
            for error in self.stats['errors'][:10]:
                print(f"  - {error}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enrich boto3 dependencies with enum values from boto3 SDK'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/aws',
        help='Root path for services (default: pythonsdk-database/aws)'
    )
    parser.add_argument(
        '--service',
        help='Enrich single service only'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    extractor = Boto3EnumExtractor()
    
    if args.service:
        # Single service
        service_path = root_path / args.service
        if service_path.exists():
            extractor.enrich_service_file(service_path)
            print(f"\n✓ Enrichment complete for {args.service}")
        else:
            print(f"Error: Service path not found: {service_path}")
            sys.exit(1)
    else:
        # All services
        extractor.enrich_all_services(root_path)


if __name__ == '__main__':
    main()

