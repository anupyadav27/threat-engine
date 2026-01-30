#!/usr/bin/env python3
"""
Generate GCP SDK database from Discovery API

Discovers ALL available GCP services from Google Discovery API and generates
comprehensive enriched database matching AWS/Azure structure.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
# Check at runtime
def check_discovery_api():
    try:
        from googleapiclient.discovery import build
        return True
    except ImportError:
        return False

DISCOVERY_API_AVAILABLE = check_discovery_api()

# Try to import enrichment utilities
try:
    from enrich_gcp_api_fields import GCPAPIFieldEnricher
except ImportError:
    print("⚠️  enrich_gcp_api_fields.py not found, will use basic enrichment")
    GCPAPIFieldEnricher = None


class GCPDiscoveryAPIGenerator:
    """Generate GCP catalog from Discovery API"""
    
    def __init__(self):
        self.field_enricher = GCPAPIFieldEnricher() if GCPAPIFieldEnricher else None
        # Calculate path to threat-engine root
        # Script is in: gcp_compliance_python_engine/Agent-ruleid-rule-yaml/
        # Need to go to: threat-engine root
        script_dir = Path(__file__).resolve().parent
        # Try different path calculations
        possible_bases = [
            script_dir.parent.parent.parent,  # gcp_compliance_python_engine/Agent-ruleid-rule-yaml -> threat-engine
            script_dir.parent.parent.parent.parent,  # Extra level if needed
            Path('/Users/apple/Desktop/threat-engine'),  # Absolute fallback
        ]
        
        # Find the correct base - look for threat-engine directory containing pythonsdk-database
        self.base_dir = None
        for base in possible_bases:
            # Check if this is the threat-engine root (has pythonsdk-database and gcp_compliance_python_engine)
            if (base / 'pythonsdk-database' / 'gcp').exists() and (base / 'gcp_compliance_python_engine').exists():
                self.base_dir = base
                break
        
        if not self.base_dir:
            # Default to absolute path
            self.base_dir = Path('/Users/apple/Desktop/threat-engine')
        
        self.output_dir = self.base_dir / 'pythonsdk-database' / 'gcp'
        print(f"📁 Output directory: {self.output_dir}")
        print(f"📁 Base directory: {self.base_dir}")
        self.discovered_services = {}
        self.errors = []
        
    def discover_all_services(self) -> List[Dict[str, Any]]:
        """Discover all available GCP services from Discovery API"""
        print("=" * 80)
        print("Discovering GCP Services from Discovery API")
        print("=" * 80)
        print()
        
        try:
            from googleapiclient.discovery import build
            
            # Get all available APIs
            print("  🔍 Querying Discovery API for all services...")
            discovery_service = build('discovery', 'v1', cache_discovery=False)
            
            # List all APIs
            request = discovery_service.apis().list(preferred=True)
            response = request.execute()
            
            apis = response.get('items', [])
            print(f"  ✅ Found {len(apis)} available APIs")
            
            # Filter for Google Cloud APIs
            gcp_apis = []
            for api in apis:
                name = api.get('name', '')
                # Filter for GCP services (exclude non-cloud APIs)
                if any(indicator in name.lower() for indicator in [
                    'cloud', 'compute', 'storage', 'bigquery', 'bigtable',
                    'container', 'dns', 'iam', 'kms', 'logging', 'monitoring',
                    'dataproc', 'dataflow', 'spanner', 'firestore', 'functions',
                    'appengine', 'cloudbuild', 'identity', 'secret', 'security',
                    'recommender', 'service', 'artifact', 'access', 'api',
                    'certificate', 'scheduler', 'dlp', 'healthcare', 'notebook',
                    'run', 'workflow'
                ]) or api.get('preferred', False):
                    gcp_apis.append(api)
            
            print(f"  📦 Filtered to {len(gcp_apis)} GCP services")
            
            return gcp_apis
            
        except ImportError as e:
            print(f"  ⚠️  Discovery API client not available: {e}")
            print("  📋 Using known GCP services list")
            return self.get_known_gcp_services()
        except Exception as e:
            print(f"  ❌ Error discovering services: {e}")
            import traceback
            traceback.print_exc()
            self.errors.append(str(e))
            print(f"  📋 Falling back to known GCP services list")
            # Fallback: return known GCP services
            return self.get_known_gcp_services()
    
    def get_known_gcp_services(self) -> List[Dict[str, Any]]:
        """Fallback list of known GCP services if Discovery API fails"""
        known_services = [
            {'name': 'compute', 'version': 'v1'},
            {'name': 'storage', 'version': 'v1'},
            {'name': 'bigquery', 'version': 'v2'},
            {'name': 'container', 'version': 'v1'},
            {'name': 'dns', 'version': 'v1'},
            {'name': 'iam', 'version': 'v1'},
            {'name': 'kms', 'version': 'v1'},
            {'name': 'logging', 'version': 'v2'},
            {'name': 'monitoring', 'version': 'v3'},
            {'name': 'cloudresourcemanager', 'version': 'v3'},
            {'name': 'sqladmin', 'version': 'v1'},
            {'name': 'pubsub', 'version': 'v1'},
            {'name': 'spanner', 'version': 'v1'},
            {'name': 'firestore', 'version': 'v1'},
            {'name': 'bigtableadmin', 'version': 'v2'},
            {'name': 'cloudfunctions', 'version': 'v2'},
            {'name': 'cloudbuild', 'version': 'v1'},
            {'name': 'appengine', 'version': 'v1'},
            {'name': 'dataproc', 'version': 'v1'},
            {'name': 'dataflow', 'version': 'v1'},
            {'name': 'cloudidentity', 'version': 'v1'},
            {'name': 'secretmanager', 'version': 'v1'},
            {'name': 'securitycenter', 'version': 'v1'},
            {'name': 'recommender', 'version': 'v1'},
            {'name': 'serviceusage', 'version': 'v1'},
            {'name': 'servicedirectory', 'version': 'v1'},
            {'name': 'artifactregistry', 'version': 'v1'},
            {'name': 'accessapproval', 'version': 'v1'},
            {'name': 'apigateway', 'version': 'v1'},
            {'name': 'certificatemanager', 'version': 'v1'},
            {'name': 'cloudscheduler', 'version': 'v1'},
            {'name': 'dlp', 'version': 'v2'},
            {'name': 'healthcare', 'version': 'v1'},
            {'name': 'notebooks', 'version': 'v1'},
            {'name': 'run', 'version': 'v1'},
            {'name': 'workflows', 'version': 'v1'},
        ]
        
        # Convert to API format
        return [{'name': s['name'], 'version': s['version']} for s in known_services]
    
    def get_service_info(self, service_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Get detailed service information from Discovery API"""
        if not check_discovery_api():
            return None
            
        try:
            from googleapiclient.discovery import build
            # Fetch the discovery document directly
            discovery_service = build('discovery', 'v1', cache_discovery=False)
            request = discovery_service.apis().getRest(api=service_name, version=version)
            doc = request.execute()
            
            return doc
            
        except Exception as e:
            print(f"    ⚠️  Error getting {service_name} {version}: {e}")
            self.errors.append(f"{service_name} {version}: {e}")
            return None
    
    def parse_discovery_document(self, service_name: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Discovery API document into our catalog format"""
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
                op = self.parse_method(service_name, resource_name, method_name, method_def)
                
                if op:
                    # Categorize as independent or dependent
                    if any(kw in method_name.lower() for kw in ['list', 'get', 'describe']):
                        resource_ops['independent'].append(op)
                    else:
                        resource_ops['dependent'].append(op)
                    
                    total_operations += 1
            
            if resource_ops['independent'] or resource_ops['dependent']:
                api_info['resources'][resource_name] = resource_ops
        
        api_info['total_operations'] = total_operations
        return api_info
    
    def parse_method(self, service_name: str, resource_name: str, method_name: str, method_def: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single API method"""
        http_method = method_def.get('httpMethod', 'GET').upper()
        path = method_def.get('path', '')
        description = method_def.get('description', '')
        
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
        
        # Determine python method name (convert to snake_case)
        python_method = self.to_snake_case(method_name)
        
        op = {
            'operation': method_name,
            'python_method': python_method,
            'yaml_action': python_method,
            'http_method': http_method,
            'path': path,
            'required_params': required_params,
            'optional_params': optional_params,
            'total_optional': len(optional_params),
            'description': description
        }
        
        # Add item_fields if this is a list/get operation
        if any(kw in method_name.lower() for kw in ['list', 'get']):
            if self.field_enricher:
                op['item_fields'] = self.field_enricher.get_resource_fields(service_name, resource_name)
            else:
                op['item_fields'] = self.get_basic_fields()
        else:
            op['item_fields'] = {}
        
        return op
    
    def to_snake_case(self, name: str) -> str:
        """Convert CamelCase to snake_case"""
        import re
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    
    def get_basic_fields(self) -> Dict[str, Any]:
        """Get basic GCP response fields"""
        return {
            'name': {
                'type': 'string',
                'description': 'Resource name',
                'compliance_category': 'identity',
                'operators': ['equals', 'not_equals', 'contains', 'in']
            },
            'id': {
                'type': 'string',
                'description': 'Unique resource identifier',
                'compliance_category': 'identity',
                'operators': ['equals', 'not_equals', 'exists']
            }
        }
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate complete catalog from Discovery API"""
        print("\n" + "=" * 80)
        print("Generating Catalog from Discovery API")
        print("=" * 80)
        print()
        
        apis = self.discover_all_services()
        catalog = {}
        
        total = len(apis)
        processed = 0
        successful = 0
        
        for api_info in apis:
            processed += 1
            service_name = api_info.get('name', '')
            version = api_info.get('version', 'v1')
            
            # Handle version formatting (remove double 'v' if present)
            if version.startswith('v'):
                version = version
            else:
                version = f'v{version}'
            
            # Progress indicator
            if processed % 10 == 0:
                print(f"  Progress: {processed}/{total} ({successful} successful)...")
            
            print(f"  🔍 [{processed}/{total}] {service_name} {version}...", end=' ', flush=True)
            
            # Get discovery document
            doc = self.get_service_info(service_name, version)
            
            if doc:
                try:
                    service_catalog = self.parse_discovery_document(service_name, doc)
                    catalog[service_name] = service_catalog
                    successful += 1
                    print(f"✅ {service_catalog['total_operations']} operations")
                except Exception as e:
                    print(f"⚠️  Parse error: {str(e)[:50]}")
                    self.errors.append(f"{service_name} {version}: Parse error - {e}")
            else:
                print("❌")
        
        print(f"\n  Completed: {processed} processed, {successful} successful, {len(self.errors)} errors")
        return catalog
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str) -> Path:
        """Save catalog to file"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / filename
        
        # Backup existing file if it exists
        if output_file.exists():
            backup_file = output_file.with_suffix('.json.backup')
            import shutil
            shutil.copy2(output_file, backup_file)
            print(f"  📦 Backed up existing file to {backup_file.name}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(catalog, f, indent=2, sort_keys=True, ensure_ascii=False)
        
        print(f"\n✅ Saved catalog to: {output_file}")
        print(f"   Services saved: {len(catalog)}")
        return output_file


def main():
    """Main execution"""
    print("=" * 80)
    print("GCP Discovery API - Full Service Catalog Generator")
    print("=" * 80)
    print()
    
    generator = GCPDiscoveryAPIGenerator()
    catalog = generator.generate_catalog()
    
    # Save catalog
    output_file = generator.save_catalog(catalog, "gcp_dependencies_with_python_names_fully_enriched.json")
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Services discovered: {len(catalog)}")
    print(f"Total operations: {sum(s.get('total_operations', 0) for s in catalog.values()):,}")
    if generator.errors:
        print(f"Errors: {len(generator.errors)}")
    print("=" * 80)


if __name__ == '__main__':
    main()

