#!/usr/bin/env python3
"""
Find missing GCP services and enrich existing services with comprehensive field metadata.

This script:
1. Finds missing services by trying alternative versions/names
2. Enriches all existing services with comprehensive field metadata
3. Updates the consolidated database
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

try:
    from googleapiclient.discovery import build
    DISCOVERY_API_AVAILABLE = True
except ImportError:
    DISCOVERY_API_AVAILABLE = False

try:
    from enrich_gcp_api_fields import GCPAPIFieldEnricher
except ImportError:
    GCPAPIFieldEnricher = None


class GCPServiceFinder:
    """Find missing GCP services"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent.parent
        self.output_dir = self.base_dir / 'pythonsdk-database' / 'gcp'
        self.missing_services = []
        self.found_services = {}
        
    def find_missing_services(self, existing_services: List[str]) -> Dict[str, str]:
        """Find missing services by trying alternative versions"""
        if not DISCOVERY_API_AVAILABLE:
            return {}
        
        print("=" * 80)
        print("Finding Missing Services")
        print("=" * 80)
        print()
        
        # Services that should exist but might be missing
        target_services = {
            'iam': ['iam', 'iam-admin', 'iamcredentials', 'iamcredentials_v1'],
            'kms': ['cloudkms', 'kms'],
            'secretmanager': ['secretmanager', 'cloudsecretmanager'],
            'cloudfunctions': ['cloudfunctions', 'functions'],
            'cloudbuild': ['cloudbuild', 'build'],
            'container': ['container', 'gke', 'kubernetes', 'gkehub', 'gkeonprem'],
            'sqladmin': ['sqladmin', 'cloudsql', 'sql'],
            'servicedirectory': ['servicedirectory', 'servicedirectory_v1'],
            'artifactregistry': ['artifactregistry', 'artifacts'],
            'apigateway': ['apigateway', 'gateway'],
            'certificatemanager': ['certificatemanager', 'certificate'],
            'workflows': ['workflows', 'workflowexecutions'],
            'run': ['run', 'cloudrun', 'runtimeconfig'],
            'gkebackup': ['gkebackup', 'gke-backup']
        }
        
        discovery_service = build('discovery', 'v1', cache_discovery=False)
        request = discovery_service.apis().list(preferred=True)
        response = request.execute()
        all_apis = response.get('items', [])
        
        found = {}
        
        for target_name, alternatives in target_services.items():
            if target_name in existing_services:
                continue
                
            print(f"  🔍 Looking for {target_name}...", end=' ')
            
            # Try each alternative
            for alt in alternatives:
                for api in all_apis:
                    api_name = api.get('name', '').lower()
                    if alt.lower() in api_name or api_name in alt.lower():
                        version = api.get('version', 'v1')
                        # Handle version format (remove double 'v')
                        if version.startswith('v') and len(version) > 2 and version[1] == 'v':
                            version = version[1:]
                        # Try to get the discovery document
                        try:
                            doc_request = discovery_service.apis().getRest(api=api['name'], version=version)
                            doc = doc_request.execute()
                            found[target_name] = {
                                'name': api['name'],
                                'version': version,
                                'doc': doc
                            }
                            print(f"✅ Found as {api['name']} {version}")
                            break
                        except Exception as e:
                            # Try with 'v' prefix if it failed
                            if not version.startswith('v'):
                                try:
                                    doc_request = discovery_service.apis().getRest(api=api['name'], version=f'v{version}')
                                    doc = doc_request.execute()
                                    found[target_name] = {
                                        'name': api['name'],
                                        'version': f'v{version}',
                                        'doc': doc
                                    }
                                    print(f"✅ Found as {api['name']} v{version}")
                                    break
                                except Exception:
                                    continue
                            continue
                if target_name in found:
                    break
            
            if target_name not in found:
                print("❌ Not found")
        
        return found
    
    def get_service_info(self, service_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Get service discovery document"""
        if not DISCOVERY_API_AVAILABLE:
            return None
        
        try:
            discovery_service = build('discovery', 'v1', cache_discovery=False)
            request = discovery_service.apis().getRest(api=service_name, version=version)
            return request.execute()
        except Exception:
            return None


class GCPFieldEnricher:
    """Comprehensive field enricher for GCP services"""
    
    def __init__(self):
        self.base_enricher = GCPAPIFieldEnricher() if GCPAPIFieldEnricher else None
        
    def detect_field_type(self, field_name: str, field_value: Any = None) -> str:
        """Detect field type from name and value"""
        field_lower = field_name.lower()
        
        # Boolean patterns
        if any(pattern in field_lower for pattern in ['enabled', 'disabled', 'is_', 'has_', 'can_', 'allow_']):
            return 'boolean'
        
        # Integer patterns
        if any(pattern in field_lower for pattern in ['count', 'size', 'port', 'timeout', 'limit', 'max', 'min', 'age', 'period']):
            return 'integer'
        
        # Enum/status patterns
        if any(pattern in field_lower for pattern in ['status', 'state', 'type', 'tier', 'level', 'mode']):
            return 'string'  # Will be marked as enum if needed
        
        # Date/time patterns
        if any(pattern in field_lower for pattern in ['time', 'date', 'timestamp', 'created', 'updated', 'expires']):
            return 'string'  # With format: date-time
        
        # Default to string
        return 'string'
    
    def detect_compliance_category(self, field_name: str) -> str:
        """Detect compliance category from field name"""
        field_lower = field_name.lower()
        
        # Security fields
        if any(pattern in field_lower for pattern in [
            'encryption', 'key', 'secret', 'password', 'token', 'certificate',
            'ssl', 'tls', 'auth', 'permission', 'role', 'policy', 'firewall',
            'public', 'private', 'access', 'security', 'iam'
        ]):
            return 'security'
        
        # Identity fields
        if any(pattern in field_lower for pattern in [
            'id', 'name', 'arn', 'uri', 'url', 'email', 'user', 'account',
            'principal', 'identity', 'owner'
        ]):
            return 'identity'
        
        # Network fields
        if any(pattern in field_lower for pattern in [
            'network', 'subnet', 'ip', 'address', 'port', 'endpoint',
            'vpc', 'dns', 'gateway', 'route'
        ]):
            return 'network'
        
        # Data protection fields
        if any(pattern in field_lower for pattern in [
            'backup', 'restore', 'retention', 'snapshot', 'replication',
            'redundancy', 'delete', 'purge'
        ]):
            return 'data_protection'
        
        # Availability fields
        if any(pattern in field_lower for pattern in [
            'zone', 'region', 'location', 'availability', 'redundancy'
        ]):
            return 'availability'
        
        return 'general'
    
    def get_operators_for_type(self, field_type: str, compliance_category: str) -> List[str]:
        """Get appropriate operators for field type"""
        base_operators = {
            'string': ['equals', 'not_equals', 'contains', 'in', 'not_in'],
            'integer': ['equals', 'not_equals', 'greater_than', 'less_than', 'in_range'],
            'boolean': ['equals', 'not_equals'],
        }
        
        operators = base_operators.get(field_type, base_operators['string'])
        
        # Add identity/security specific operators
        if compliance_category in ['identity', 'security']:
            operators.extend(['exists', 'not_exists'])
        
        return operators
    
    def enrich_field(self, field_name: str, field_value: Any = None) -> Dict[str, Any]:
        """Enrich a single field with comprehensive metadata"""
        field_type = self.detect_field_type(field_name, field_value)
        compliance_category = self.detect_compliance_category(field_name)
        operators = self.get_operators_for_type(field_type, compliance_category)
        
        metadata = {
            'type': field_type,
            'description': field_name.replace('_', ' ').replace('-', ' ').title(),
            'compliance_category': compliance_category,
            'operators': operators
        }
        
        # Add format for date-time fields
        if 'time' in field_name.lower() or 'date' in field_name.lower():
            metadata['format'] = 'date-time'
        
        # Add security impact for security fields
        if compliance_category == 'security':
            if any(kw in field_name.lower() for kw in ['encryption', 'key', 'secret', 'certificate', 'auth']):
                metadata['security_impact'] = 'high'
            else:
                metadata['security_impact'] = 'medium'
        
        # Mark as enum if it's a status/state/type field
        if any(kw in field_name.lower() for kw in ['status', 'state', 'type', 'tier', 'level']):
            metadata['enum'] = True
        
        return metadata
    
    def enrich_operation_fields(self, operation: Dict[str, Any], service_name: str, resource_name: str) -> Dict[str, Any]:
        """Enrich operation with comprehensive field metadata"""
        # Start with base enricher if available
        if self.base_enricher:
            base_fields = self.base_enricher.get_resource_fields(service_name, resource_name)
        else:
            base_fields = {}
        
        # Enhance each field with additional metadata
        enriched_fields = {}
        for field_name, field_data in base_fields.items():
            if isinstance(field_data, dict):
                # Already enriched, enhance it
                enriched_fields[field_name] = field_data.copy()
                # Ensure operators are present
                if 'operators' not in enriched_fields[field_name]:
                    enriched_fields[field_name]['operators'] = self.get_operators_for_type(
                        enriched_fields[field_name].get('type', 'string'),
                        enriched_fields[field_name].get('compliance_category', 'general')
                    )
            else:
                # Not enriched, enrich it
                enriched_fields[field_name] = self.enrich_field(field_name, field_data)
        
        # Add common fields if not present
        common_fields = {
            'name': self.enrich_field('name'),
            'id': self.enrich_field('id'),
            'selfLink': self.enrich_field('selfLink'),
            'creationTimestamp': self.enrich_field('creationTimestamp'),
            'labels': self.enrich_field('labels')
        }
        
        for field_name, field_metadata in common_fields.items():
            if field_name not in enriched_fields:
                enriched_fields[field_name] = field_metadata
        
        return enriched_fields
    
    def enrich_service(self, service_data: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Enrich all operations in a service"""
        enriched = service_data.copy()
        
        if 'resources' in service_data:
            enriched_resources = {}
            for resource_name, resource_data in service_data['resources'].items():
                enriched_resource = resource_data.copy()
                
                # Enrich independent operations
                if 'independent' in resource_data:
                    enriched_ops = []
                    for op in resource_data['independent']:
                        enriched_op = op.copy()
                        enriched_op['item_fields'] = self.enrich_operation_fields(
                            op, service_name, resource_name
                        )
                        enriched_ops.append(enriched_op)
                    enriched_resource['independent'] = enriched_ops
                
                # Enrich dependent operations (get operations)
                if 'dependent' in resource_data:
                    enriched_ops = []
                    for op in resource_data['dependent']:
                        enriched_op = op.copy()
                        # Only enrich get operations
                        if 'get' in op.get('operation', '').lower():
                            enriched_op['item_fields'] = self.enrich_operation_fields(
                                op, service_name, resource_name
                            )
                        else:
                            enriched_op['item_fields'] = {}
                        enriched_ops.append(enriched_op)
                    enriched_resource['dependent'] = enriched_ops
                
                enriched_resources[resource_name] = enriched_resource
            
            enriched['resources'] = enriched_resources
        
        return enriched


def parse_discovery_document(service_name: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Discovery API document (reuse from generate script)"""
    resources = {}
    total_operations = 0
    
    api_info = {
        'service': service_name,
        'version': doc.get('version', 'v1'),
        'title': doc.get('title', ''),
        'description': doc.get('description', ''),
        'base_url': doc.get('baseUrl', ''),
        'total_operations': 0,
        'resources': {}
    }
    
    # Parse resources and methods
    api_resources = doc.get('resources', {})
    
    for resource_name, resource_def in api_resources.items():
        resource_ops = {
            'independent': [],
            'dependent': []
        }
        
        methods = resource_def.get('methods', {})
        for method_name, method_def in methods.items():
            # Extract parameters
            parameters = method_def.get('parameters', {})
            required_params = []
            optional_params = {}
            
            for param_name, param_def in parameters.items():
                if param_def.get('required', False):
                    required_params.append(param_name)
                else:
                    optional_params[param_name] = {
                        'type': param_def.get('type', 'string'),
                        'description': param_def.get('description', '')
                    }
            
            op = {
                'operation': method_name,
                'python_method': method_name.lower().replace('_', ''),
                'yaml_action': method_name.lower(),
                'http_method': method_def.get('httpMethod', 'GET').upper(),
                'path': method_def.get('path', ''),
                'required_params': required_params,
                'optional_params': optional_params,
                'total_optional': len(optional_params),
                'description': method_def.get('description', ''),
                'item_fields': {}
            }
            
            # Categorize
            if any(kw in method_name.lower() for kw in ['list', 'get', 'describe']):
                resource_ops['independent'].append(op)
            else:
                resource_ops['dependent'].append(op)
            
            total_operations += 1
        
        if resource_ops['independent'] or resource_ops['dependent']:
            api_info['resources'][resource_name] = resource_ops
    
    api_info['total_operations'] = total_operations
    return api_info


def main():
    """Main execution"""
    print("=" * 80)
    print("GCP Service Finder and Enricher")
    print("=" * 80)
    print()
    
    base_dir = Path(__file__).parent.parent.parent
    output_dir = base_dir / 'pythonsdk-database' / 'gcp'
    catalog_file = output_dir / 'gcp_dependencies_with_python_names_fully_enriched.json'
    
    # Load existing catalog
    print("Loading existing catalog...")
    with open(catalog_file) as f:
        catalog = json.load(f)
    
    print(f"✅ Loaded {len(catalog)} services")
    
    # Step 1: Find missing services
    finder = GCPServiceFinder()
    existing_services = list(catalog.keys())
    missing_found = finder.find_missing_services(existing_services)
    
    # Add missing services to catalog
    if missing_found:
        print(f"\n📦 Adding {len(missing_found)} missing services...")
        for target_name, service_info in missing_found.items():
            service_catalog = parse_discovery_document(service_info['name'], service_info['doc'])
            catalog[target_name] = service_catalog
            print(f"  ✅ Added {target_name} ({service_catalog['total_operations']} operations)")
    
    # Step 2: Enrich all services
    print("\n" + "=" * 80)
    print("Enriching All Services with Field Metadata")
    print("=" * 80)
    print()
    
    enricher = GCPFieldEnricher()
    enriched_catalog = {}
    
    for service_name, service_data in catalog.items():
        print(f"  Enriching {service_name}...", end=' ')
        enriched_service = enricher.enrich_service(service_data, service_name)
        enriched_catalog[service_name] = enriched_service
        
        # Count enriched fields
        total_fields = 0
        for resource_data in enriched_service.get('resources', {}).values():
            for op in resource_data.get('independent', []) + resource_data.get('dependent', []):
                total_fields += len(op.get('item_fields', {}))
        
        print(f"✅ ({total_fields} fields)")
    
    # Save enriched catalog
    print(f"\n💾 Saving enriched catalog...")
    backup_file = catalog_file.with_suffix('.json.backup')
    if catalog_file.exists():
        import shutil
        shutil.copy2(catalog_file, backup_file)
        print(f"  📦 Backed up to {backup_file.name}")
    
    with open(catalog_file, 'w', encoding='utf-8') as f:
        json.dump(enriched_catalog, f, indent=2, sort_keys=True, ensure_ascii=False)
    
    print(f"  ✅ Saved to {catalog_file}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Services: {len(enriched_catalog)}")
    print(f"  - Existing: {len(existing_services)}")
    print(f"  - Added: {len(missing_found)}")
    print(f"Total operations: {sum(s.get('total_operations', 0) for s in enriched_catalog.values()):,}")
    print("=" * 80)


if __name__ == '__main__':
    main()

