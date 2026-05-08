#!/usr/bin/env python3
"""
SDK Database Audit and Enrichment Script

This script:
1. Audits all SDK databases to check enrichment completeness
2. Identifies missing fields compared to AWS format
3. Enriches databases to match AWS enrichment standards
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import re

class DatabaseAuditor:
    """Audit SDK databases for completeness"""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.aws_format = {
            'required_fields': ['service', 'total_operations', 'independent', 'dependent'],
            'operation_fields': [
                'operation', 'python_method', 'yaml_action',
                'required_params', 'optional_params', 'total_optional',
                'output_fields', 'main_output_field', 'item_fields'
            ],
            'item_field_metadata': [
                'type', 'description', 'compliance_category', 'operators'
            ]
        }
        self.audit_results = defaultdict(dict)
    
    def audit_database(self, file_path: Path, provider: str) -> Dict[str, Any]:
        """Audit a single database file"""
        print(f"\n📊 Auditing: {file_path.name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}
        
        results = {
            'file': str(file_path.relative_to(self.base_dir)),
            'provider': provider,
            'services': len(data),
            'missing_fields': [],
            'operations_stats': {
                'total': 0,
                'with_required_params': 0,
                'with_optional_params': 0,
                'with_output_fields': 0,
                'with_item_fields': 0,
                'with_enriched_item_fields': 0
            },
            'enrichment_score': 0
        }
        
        # Check each service
        for service_name, service_data in data.items():
            # Check service-level fields
            if 'total_operations' not in service_data:
                results['missing_fields'].append(f"{service_name}: missing 'total_operations'")
            
            # Check operations structure
            operations = []
            if 'independent' in service_data:
                operations.extend(service_data['independent'])
            if 'dependent' in service_data:
                operations.extend(service_data['dependent'])
            if 'operations' in service_data:
                operations.extend(service_data['operations'])
            
            results['operations_stats']['total'] += len(operations)
            
            # Check each operation
            for op in operations:
                # Check required operation fields
                if 'required_params' in op:
                    results['operations_stats']['with_required_params'] += 1
                if 'optional_params' in op:
                    results['operations_stats']['with_optional_params'] += 1
                if 'output_fields' in op:
                    results['operations_stats']['with_output_fields'] += 1
                if 'item_fields' in op and op['item_fields']:
                    results['operations_stats']['with_item_fields'] += 1
                    
                    # Check if item_fields are enriched
                    if isinstance(op['item_fields'], dict):
                        sample_field = next(iter(op['item_fields'].values()), {})
                        if isinstance(sample_field, dict) and 'type' in sample_field:
                            results['operations_stats']['with_enriched_item_fields'] += 1
        
        # Calculate enrichment score
        total_ops = results['operations_stats']['total']
        if total_ops > 0:
            score = (
                (results['operations_stats']['with_required_params'] / total_ops * 0.2) +
                (results['operations_stats']['with_optional_params'] / total_ops * 0.2) +
                (results['operations_stats']['with_output_fields'] / total_ops * 0.3) +
                (results['operations_stats']['with_enriched_item_fields'] / total_ops * 0.3)
            ) * 100
            results['enrichment_score'] = round(score, 2)
        
        return results
    
    def audit_all(self) -> Dict[str, Any]:
        """Audit all databases"""
        print("=" * 80)
        print("SDK Database Audit")
        print("=" * 80)
        
        all_results = {}
        
        # Find all fully_enriched.json files
        for provider_dir in self.base_dir.iterdir():
            if not provider_dir.is_dir():
                continue
            
            provider = provider_dir.name
            print(f"\n🔍 Checking {provider}...")
            
            # Find main consolidated file
            main_file = provider_dir / f"{provider}_dependencies_with_python_names_fully_enriched.json"
            if main_file.exists():
                results = self.audit_database(main_file, provider)
                all_results[provider] = results
            
            # Also check per-service files
            service_files = list(provider_dir.rglob("*fully_enriched.json"))
            if len(service_files) > 1:  # More than just the main file
                print(f"  Found {len(service_files)} files (including per-service)")
        
        return all_results
    
    def print_summary(self, results: Dict[str, Any]):
        """Print audit summary"""
        print("\n" + "=" * 80)
        print("AUDIT SUMMARY")
        print("=" * 80)
        
        for provider, result in results.items():
            if 'error' in result:
                print(f"\n❌ {provider}: {result['error']}")
                continue
            
            print(f"\n📦 {provider.upper()}")
            print(f"   Services: {result['services']}")
            print(f"   Total Operations: {result['operations_stats']['total']:,}")
            print(f"   Enrichment Score: {result['enrichment_score']:.1f}%")
            print(f"   Operations with required_params: {result['operations_stats']['with_required_params']:,}")
            print(f"   Operations with optional_params: {result['operations_stats']['with_optional_params']:,}")
            print(f"   Operations with output_fields: {result['operations_stats']['with_output_fields']:,}")
            print(f"   Operations with enriched item_fields: {result['operations_stats']['with_enriched_item_fields']:,}")
            
            if result['missing_fields']:
                print(f"   ⚠️  Missing fields: {len(result['missing_fields'])}")


class DatabaseEnricher:
    """Enrich SDK databases to match AWS format"""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.compliance_categories = {
            'identity': ['id', 'arn', 'name', 'user', 'role', 'principal', 'account'],
            'security': ['encryption', 'key', 'secret', 'password', 'token', 'credential', 'auth'],
            'network': ['network', 'vpc', 'subnet', 'security_group', 'firewall', 'acl', 'endpoint'],
            'availability': ['region', 'zone', 'availability', 'redundancy', 'backup'],
            'general': []  # Default
        }
    
    def infer_compliance_category(self, field_name: str) -> str:
        """Infer compliance category from field name"""
        field_lower = field_name.lower()
        
        for category, keywords in self.compliance_categories.items():
            if category == 'general':
                continue
            if any(keyword in field_lower for keyword in keywords):
                return category
        
        return 'general'
    
    def infer_field_type(self, field_name: str, field_value: Any = None) -> str:
        """Infer field type from name and value"""
        field_lower = field_name.lower()
        
        # Check value if available
        if field_value is not None:
            if isinstance(field_value, bool):
                return 'boolean'
            elif isinstance(field_value, int):
                return 'integer'
            elif isinstance(field_value, float):
                return 'number'
            elif isinstance(field_value, list):
                return 'array'
            elif isinstance(field_value, dict):
                return 'object'
        
        # Infer from name
        if any(x in field_lower for x in ['time', 'date', 'created', 'updated', 'modified']):
            return 'string'  # date-time format
        elif any(x in field_lower for x in ['count', 'size', 'number', 'id']):
            return 'integer'
        elif any(x in field_lower for x in ['enabled', 'active', 'is_', 'has_']):
            return 'boolean'
        elif any(x in field_lower for x in ['tags', 'list', 'items', 'array']):
            return 'array'
        
        return 'string'
    
    def get_operators_for_type(self, field_type: str) -> List[str]:
        """Get appropriate operators for field type"""
        base_operators = ['equals', 'not_equals', 'contains', 'in', 'exists']
        
        if field_type in ['integer', 'number']:
            return base_operators + ['gt', 'lt', 'gte', 'lte']
        elif field_type == 'array':
            return ['contains', 'not_empty', 'exists']
        elif field_type == 'boolean':
            return ['equals', 'not_equals', 'exists']
        
        return base_operators
    
    def enrich_item_field(self, field_name: str, field_value: Any = None) -> Dict[str, Any]:
        """Enrich a single item field"""
        field_type = self.infer_field_type(field_name, field_value)
        compliance_category = self.infer_compliance_category(field_name)
        operators = self.get_operators_for_type(field_type)
        
        description = field_name.replace('_', ' ').replace('-', ' ').title()
        
        # Special handling for common fields
        if 'id' in field_name.lower() and 'arn' not in field_name.lower():
            description = "Resource identifier"
        elif 'arn' in field_name.lower():
            description = "Amazon Resource Name (ARN)" if 'aws' in str(self.base_dir).lower() else "Resource ARN"
        elif 'name' in field_name.lower():
            description = "Resource name"
        elif 'status' in field_name.lower():
            description = "Resource status"
        elif 'time' in field_name.lower() or 'date' in field_name.lower():
            description = "Timestamp"
            field_type = 'string'  # Will be date-time format
        
        enriched = {
            'type': field_type,
            'description': description,
            'compliance_category': compliance_category,
            'operators': operators
        }
        
        # Add format for date-time fields
        if 'time' in field_name.lower() or 'date' in field_name.lower():
            enriched['format'] = 'date-time'
        
        return enriched
    
    def enrich_item_fields(self, item_fields: Any) -> Dict[str, Any]:
        """Enrich item_fields dictionary"""
        if not item_fields:
            return {}
        
        if isinstance(item_fields, dict):
            enriched = {}
            for field_name, field_value in item_fields.items():
                # If already enriched, preserve it
                if isinstance(field_value, dict) and 'type' in field_value:
                    enriched[field_name] = field_value
                else:
                    enriched[field_name] = self.enrich_item_field(field_name, field_value)
            return enriched
        
        # If item_fields is a list, convert to dict
        if isinstance(item_fields, list):
            enriched = {}
            for field_name in item_fields:
                enriched[field_name] = self.enrich_item_field(field_name)
            return enriched
        
        return {}
    
    def infer_params_from_operation(self, operation: Dict[str, Any], service_name: str) -> tuple:
        """Infer required and optional parameters from operation"""
        op_name = operation.get('operation', '').lower()
        python_method = operation.get('python_method', '').lower()
        
        required_params = []
        optional_params = []
        
        # If operation already has params, use them
        if 'required_params' in operation:
            required_params = operation['required_params'] if isinstance(operation['required_params'], list) else []
        if 'optional_params' in operation:
            if isinstance(operation['optional_params'], list):
                optional_params = operation['optional_params']
            elif isinstance(operation['optional_params'], dict):
                optional_params = list(operation['optional_params'].keys())
        
        # If no params found, infer from operation name
        if not required_params and not optional_params:
            # List/Describe operations typically have no required params
            if any(x in op_name for x in ['list', 'describe', 'get_all', 'enumerate']):
                required_params = []
                optional_params = ['filter', 'max_results', 'page_token', 'next_token']
            # Get operations typically need an ID
            elif 'get' in op_name or 'describe' in op_name:
                # Try to infer ID parameter name
                resource_name = op_name.replace('get_', '').replace('describe_', '').replace('_', '_')
                if resource_name:
                    required_params = [f"{resource_name}_id", "id"]
                optional_params = ['expand', 'select']
            # Create operations typically need a body/parameters
            elif 'create' in op_name:
                required_params = ['body', 'parameters']
                optional_params = []
            # Update operations need ID and body
            elif 'update' in op_name or 'modify' in op_name:
                required_params = ['id', 'body']
                optional_params = []
            # Delete operations need ID
            elif 'delete' in op_name or 'remove' in op_name:
                required_params = ['id']
                optional_params = []
        
        return required_params, optional_params
    
    def infer_output_fields(self, operation: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Infer output_fields from operation"""
        op_name = operation.get('operation', '').lower()
        
        # If output_fields already exist, use them
        if 'output_fields' in operation and operation['output_fields']:
            if isinstance(operation['output_fields'], dict):
                return operation['output_fields']
            elif isinstance(operation['output_fields'], list):
                # Convert list to dict format
                return {
                    field: {
                        'type': 'string',
                        'description': f"{field.replace('_', ' ').title()}",
                        'compliance_category': self.infer_compliance_category(field),
                        'operators': self.get_operators_for_type('string')
                    }
                    for field in operation['output_fields']
                }
        
        # Infer from operation type
        output_fields = {}
        main_output_field = None
        
        if any(x in op_name for x in ['list', 'describe', 'get_all']):
            # List operations typically return a list
            list_field = 'items' if 'items' not in op_name else 'resources'
            output_fields[list_field] = {
                'type': 'array',
                'description': f"List of {service_name} resources",
                'compliance_category': 'general',
                'operators': ['contains', 'not_empty', 'exists']
            }
            main_output_field = list_field
            
            # Add pagination fields
            output_fields['next_token'] = {
                'type': 'string',
                'description': 'Pagination token for next results',
                'compliance_category': 'general',
                'operators': ['equals', 'not_equals', 'contains'],
                'security_impact': 'high'
            }
        elif 'get' in op_name or 'describe' in op_name:
            # Get operations return a single item
            item_field = 'item' if 'item' not in op_name else 'resource'
            output_fields[item_field] = {
                'type': 'object',
                'description': f"{service_name} resource details",
                'compliance_category': 'general',
                'operators': ['exists']
            }
            main_output_field = item_field
        
        return output_fields
    
    def enrich_operation(self, operation: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Enrich a single operation"""
        enriched = operation.copy()
        
        # Ensure required fields exist
        if 'yaml_action' not in enriched:
            enriched['yaml_action'] = enriched.get('python_method', '').replace('_', '-')
        
        # Infer and add required_params and optional_params
        required_params, optional_params = self.infer_params_from_operation(enriched, service_name)
        if 'required_params' not in enriched or not enriched['required_params']:
            enriched['required_params'] = required_params
        if 'optional_params' not in enriched or not enriched['optional_params']:
            if isinstance(enriched.get('optional_params'), dict):
                # Keep dict format if it exists
                pass
            else:
                enriched['optional_params'] = optional_params
        if 'total_optional' not in enriched:
            opt_count = len(optional_params) if isinstance(optional_params, list) else len(optional_params) if isinstance(optional_params, dict) else 0
            enriched['total_optional'] = opt_count
        
        # Infer and add output_fields
        if 'output_fields' not in enriched or not enriched['output_fields']:
            enriched['output_fields'] = self.infer_output_fields(enriched, service_name)
        
        # Infer main_output_field
        if 'main_output_field' not in enriched or not enriched['main_output_field']:
            if enriched.get('output_fields'):
                # Use first output field as main
                main_field = next(iter(enriched['output_fields'].keys()), None)
                enriched['main_output_field'] = main_field
        
        # Enrich item_fields if they exist
        if 'item_fields' in enriched:
            enriched['item_fields'] = self.enrich_item_fields(enriched['item_fields'])
        
        # If item_fields is empty dict, try to infer from operation name
        if 'item_fields' in enriched and not enriched['item_fields']:
            # Try to add common fields based on operation type
            op_name = enriched.get('operation', '').lower()
            if 'list' in op_name or 'describe' in op_name or 'get' in op_name:
                # Add common fields
                common_fields = ['id', 'name', 'arn', 'status', 'created_at', 'tags']
                enriched['item_fields'] = {
                    field: self.enrich_item_field(field) 
                    for field in common_fields
                }
        
        return enriched
    
    def enrich_service(self, service_data: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Enrich a service's data"""
        enriched = service_data.copy()
        
        # Count operations
        operations = []
        if 'independent' in enriched:
            operations.extend(enriched['independent'])
        if 'dependent' in enriched:
            operations.extend(enriched['dependent'])
        if 'operations' in enriched:
            operations.extend(enriched['operations'])
        
        # Handle GCP-style nested resources
        if 'resources' in enriched:
            for resource_name, resource_data in enriched['resources'].items():
                if 'independent' in resource_data:
                    operations.extend(resource_data['independent'])
                if 'dependent' in resource_data:
                    operations.extend(resource_data['dependent'])
        
        # Update total_operations
        enriched['total_operations'] = len(operations)
        
        # Enrich operations
        if 'independent' in enriched:
            enriched['independent'] = [
                self.enrich_operation(op, service_name) 
                for op in enriched['independent']
            ]
        
        if 'dependent' in enriched:
            enriched['dependent'] = [
                self.enrich_operation(op, service_name) 
                for op in enriched['dependent']
            ]
        
        if 'operations' in enriched:
            enriched['operations'] = [
                self.enrich_operation(op, service_name) 
                for op in enriched['operations']
            ]
        
        # Handle GCP-style nested resources
        if 'resources' in enriched:
            for resource_name, resource_data in enriched['resources'].items():
                if 'independent' in resource_data:
                    resource_data['independent'] = [
                        self.enrich_operation(op, service_name) 
                        for op in resource_data['independent']
                    ]
                if 'dependent' in resource_data:
                    resource_data['dependent'] = [
                        self.enrich_operation(op, service_name) 
                        for op in resource_data['dependent']
                    ]
        
        return enriched
    
    def enrich_database(self, file_path: Path, backup: bool = True) -> bool:
        """Enrich a database file"""
        print(f"\n🔧 Enriching: {file_path.name}")
        
        try:
            # Load data
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"   ❌ Error loading file: {e}")
            return False
        
        # Backup if requested
        if backup:
            backup_path = file_path.with_suffix('.json.backup')
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"   💾 Backup created: {backup_path.name}")
        
        # Enrich each service
        enriched_data = {}
        for service_name, service_data in data.items():
            enriched_data[service_name] = self.enrich_service(service_data, service_name)
        
        # Save enriched data
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(enriched_data, f, indent=2, ensure_ascii=False)
        
        print(f"   ✅ Enriched {len(enriched_data)} services")
        return True


def main():
    """Main execution"""
    base_dir = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database")
    
    print("=" * 80)
    print("SDK Database Audit and Enrichment Tool")
    print("=" * 80)
    
    # Step 1: Audit
    auditor = DatabaseAuditor(base_dir)
    audit_results = auditor.audit_all()
    auditor.print_summary(audit_results)
    
    # Step 2: Ask for enrichment
    print("\n" + "=" * 80)
    print("ENRICHMENT")
    print("=" * 80)
    
    enricher = DatabaseEnricher(base_dir)
    
    # Enrich providers with low scores
    for provider, result in audit_results.items():
        if 'error' in result:
            continue
        
        if result['enrichment_score'] < 80:
            print(f"\n🔧 {provider} needs enrichment (score: {result['enrichment_score']:.1f}%)")
            
            # Find the file
            provider_dir = base_dir / provider
            main_file = provider_dir / f"{provider}_dependencies_with_python_names_fully_enriched.json"
            
            if main_file.exists():
                enricher.enrich_database(main_file, backup=True)
    
    print("\n" + "=" * 80)
    print("✅ Complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()

