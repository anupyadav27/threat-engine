#!/usr/bin/env python3
"""
Agentic AI Platform for Generating Compliance Rules YAML Files

This script generates rules YAML files from operation_registry.json and related data sources.
It handles discovery dependency chains (for_each relationships).
"""

import json
import yaml
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
import re

class RulesGenerator:
    """Generate compliance rules YAML from service data."""
    
    def __init__(self, service_path: Path, service_name: str):
        self.service_path = service_path
        self.service_name = service_name
        self.operation_registry = None
        self.adjacency = None
        self.dependency_index = None
        self.source_spec = None
        self.discoveries = []
        self.checks = []
        self.discovery_map = {}  # discovery_id -> discovery data
        
    def load_data_sources(self) -> bool:
        """Load all required data sources."""
        try:
            # Load operation_registry.json
            registry_file = self.service_path / "operation_registry.json"
            if not registry_file.exists():
                print(f"  ❌ operation_registry.json not found")
                return False
            with open(registry_file, 'r') as f:
                self.operation_registry = json.load(f)
            
            # Load adjacency.json
            adjacency_file = self.service_path / "adjacency.json"
            if adjacency_file.exists():
                with open(adjacency_file, 'r') as f:
                    self.adjacency = json.load(f)
            
            # Load dependency_index.json if available (precomputed dependency chains)
            dependency_index_file = self.service_path / "dependency_index.json"
            if dependency_index_file.exists():
                with open(dependency_index_file, 'r') as f:
                    self.dependency_index = json.load(f)
            
            # Load source spec for field metadata
            spec_file = self.service_path / "boto3_dependencies_with_python_names_fully_enriched.json"
            if spec_file.exists():
                with open(spec_file, 'r') as f:
                    self.source_spec = json.load(f)
            
            return True
        except Exception as e:
            print(f"  ❌ Error loading data: {e}")
            return False
    
    def operation_to_boto3_method(self, operation_name: str) -> str:
        """Convert operation name to boto3 method name."""
        # Get from operation_registry
        if self.operation_registry and 'operations' in self.operation_registry:
            op_data = self.operation_registry['operations'].get(operation_name)
            if op_data and 'sdk' in op_data:
                return op_data['sdk'].get('method', operation_name.lower())
        
        # Fallback: convert PascalCase to snake_case
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation_name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    
    def operation_to_discovery_id(self, operation_name: str) -> str:
        """Convert operation name to discovery_id format."""
        # Use snake_case with underscores
        method = self.operation_to_boto3_method(operation_name)
        return f"aws.{self.service_name}.{method}"
    
    def find_dependency_chain(self, operation_name: str) -> List[str]:
        """Find dependency chain for an operation (what it depends on).
        
        Uses precomputed dependency_index.json if available, otherwise falls back
        to runtime computation from adjacency.json.
        """
        # Try to use precomputed dependency index first
        if self.dependency_index:
            # Find the shortest path for any entity consumed by this operation
            op_data = self.operation_registry.get('operations', {}).get(operation_name, {})
            consumes = op_data.get('consumes', [])
            
            if not consumes:
                return []  # No dependencies
            
            # Get entity_aliases for canonicalization
            entity_aliases = self.operation_registry.get('entity_aliases', {})
            
            # Find the best dependency path
            best_path = None
            best_length = float('inf')
            
            for consume_entry in consumes:
                entity = consume_entry.get('entity', '') if isinstance(consume_entry, dict) else consume_entry
                
                # Canonicalize entity
                canonical_entity = entity_aliases.get(entity, entity)
                
                # Look up paths for this entity
                entity_paths = self.dependency_index.get('entity_paths', {}).get(canonical_entity, [])
                
                if entity_paths:
                    # Use the shortest path (first one, as they're sorted)
                    path_obj = entity_paths[0]
                    path_ops = path_obj.get('operations', path_obj.get('ops', []))  # Support both old and new format
                    
                    # Remove the target operation if it's in the path
                    if operation_name in path_ops:
                        path_ops = [op for op in path_ops if op != operation_name]
                    
                    # Prefer shorter paths
                    if len(path_ops) < best_length and path_ops:
                        best_path = path_ops
                        best_length = len(path_ops)
            
            if best_path:
                # Return the dependency (first operation in path that's not the target)
                return [best_path[0]] if best_path else []
        
        # Fallback to runtime computation
        if not self.adjacency:
            return []
        
        # Check what entities this operation consumes
        op_consumes = self.adjacency.get('op_consumes', {}).get(operation_name, [])
        
        # Find which operations produce these entities
        entity_producers = self.adjacency.get('entity_producers', {})
        dependencies = []
        
        for entity in op_consumes:
            producers = entity_producers.get(entity, [])
            # Prefer read_list operations for dependencies
            for producer in producers:
                if producer != operation_name:
                    producer_kind = self.operation_registry.get('operations', {}).get(producer, {}).get('kind', '')
                    if 'read_list' in producer_kind or 'read_get' in producer_kind:
                        if producer not in dependencies:
                            dependencies.append(producer)
        
        return dependencies
    
    def generate_discovery_from_operation(self, operation_name: str, op_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate discovery item from operation."""
        kind = op_data.get('kind', '')
        
        # Only generate discovery for read operations
        if 'read_list' not in kind and 'read_get' not in kind:
            return None
        
        discovery_id = self.operation_to_discovery_id(operation_name)
        boto3_method = self.operation_to_boto3_method(operation_name)
        
        # Build calls
        calls = [{
            'action': boto3_method,
            'save_as': 'response'
        }]
        
        # Check for dependencies (for_each)
        dependencies = self.find_dependency_chain(operation_name)
        for_each = None
        params = {}
        
        if dependencies:
            # Use the first dependency (prefer read_list)
            dep_op = dependencies[0]
            dep_discovery_id = self.operation_to_discovery_id(dep_op)
            
            # Check if dependency discovery exists (will be created later)
            for_each = dep_discovery_id
            
            # Build params from consumes
            consumes = op_data.get('consumes', [])
            for consume in consumes:
                param_name = consume.get('param', '')
                entity = consume.get('entity', '')
                
                # Map entity to field from dependency
                if param_name:
                    # Try to infer field name from entity
                    field_name = self.entity_to_field_name(entity, dep_op)
                    if field_name:
                        # Use proper field name (keep original case for API params, but use item reference)
                        # For item reference, use the field as it appears in emit
                        params[param_name] = f"{{{{ item.{field_name} }}}}"
                    else:
                        # Fallback: use param name directly (might need adjustment)
                        params[param_name] = f"{{{{ item.{self.to_snake_case(param_name)} }}}}"
        
        if params:
            calls[0]['params'] = params
        
        # Build emit based on produces
        emit = self.build_emit_from_produces(op_data.get('produces', []), kind)
        
        discovery = {
            'discovery_id': discovery_id,
            'calls': calls
        }
        
        if for_each:
            discovery['for_each'] = for_each
            discovery['on_error'] = 'continue'
        
        if emit:
            discovery['emit'] = emit
        
        return discovery
    
    def entity_to_field_name(self, entity: str, operation_name: str) -> Optional[str]:
        """Map entity to field name from operation produces."""
        if not self.operation_registry:
            return None
        
        # Get the operation that produces this entity
        op_data = self.operation_registry.get('operations', {}).get(operation_name, {})
        produces = op_data.get('produces', [])
        
        for produce in produces:
            if produce.get('entity') == entity:
                path = produce.get('path', '')
                # Extract field name from path
                # e.g., "Buckets[].Name" -> "Name"
                if '[]' in path:
                    parts = path.split('[]')
                    if len(parts) > 1:
                        field = parts[1].lstrip('.')
                        # Convert to snake_case for item reference
                        return self.to_snake_case(field)
                elif '.' in path:
                    return self.to_snake_case(path.split('.')[-1])
                else:
                    return self.to_snake_case(path)
        
        # Fallback: extract from entity name
        if '.' in entity:
            return self.to_snake_case(entity.split('.')[-1])
        
        return None
    
    def to_snake_case(self, name: str) -> str:
        """Convert to snake_case."""
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    
    def build_emit_from_produces(self, produces: List[Dict[str, Any]], kind: str) -> Dict[str, Any]:
        """Build emit section from produces."""
        if not produces:
            return {}
        
        # Check if this is a list operation
        is_list = 'read_list' in kind
        
        item_fields = {}
        list_field = None
        
        for produce in produces:
            path = produce.get('path', '')
            entity = produce.get('entity', '')
            source = produce.get('source', 'output')
            
            # Find list field for list operations
            if is_list and '[]' in path:
                list_field = path.split('[]')[0]
                # Extract item field name (keep original case for API response)
                item_field = path.split('[]')[1].lstrip('.') if len(path.split('[]')) > 1 else ''
                if item_field:
                    # Use original field name in template (not snake_case)
                    field_key = self.to_snake_case(item_field)  # For item key
                    item_fields[field_key] = f"{{{{ resource.{item_field} }}}}"
            elif not is_list:
                # Single item operation - use full path
                # Extract field name from path
                if '.' in path:
                    field_name = path.split('.')[-1]
                else:
                    field_name = path
                
                field_key = self.to_snake_case(field_name)
                item_fields[field_key] = f"{{{{ response.{path} }}}}"
        
        if is_list:
            if list_field:
                return {
                    'items_for': f"{{{{ response.{list_field} }}}}",
                    'as': 'resource',
                    'item': item_fields
                }
            else:
                # Fallback: no list field found
                return {'item': item_fields}
        else:
            return {'item': item_fields}
    
    def generate_discoveries(self):
        """Generate all discovery items from operations."""
        if not self.operation_registry:
            return
        
        operations = self.operation_registry.get('operations', {})
        
        # First pass: generate all discoveries
        for op_name, op_data in operations.items():
            discovery = self.generate_discovery_from_operation(op_name, op_data)
            if discovery:
                self.discoveries.append(discovery)
                self.discovery_map[discovery['discovery_id']] = discovery
        
        # Second pass: order discoveries by dependency (dependencies first)
        # This ensures for_each references work correctly
        ordered_discoveries = []
        processed = set()
        
        def add_discovery(discovery):
            if discovery['discovery_id'] in processed:
                return
            
            # Add dependencies first
            if 'for_each' in discovery:
                dep_id = discovery['for_each']
                # Find dependency discovery
                dep_discovery = None
                for d in self.discoveries:
                    if d['discovery_id'] == dep_id:
                        dep_discovery = d
                        break
                
                if dep_discovery:
                    add_discovery(dep_discovery)
            
            ordered_discoveries.append(discovery)
            processed.add(discovery['discovery_id'])
        
        # Process all discoveries
        for discovery in self.discoveries:
            add_discovery(discovery)
        
        self.discoveries = ordered_discoveries
    
    def field_exists_in_discovery(self, field_name: str, discovery: Dict[str, Any]) -> bool:
        """Check if a field exists in a discovery's emit."""
        emit = discovery.get('emit', {})
        item_fields = emit.get('item', {})
        
        # Normalize field name for matching
        field_normalized = field_name.lower().replace('_', '').replace('-', '')
        
        # Check each field in emit
        for key in item_fields.keys():
            key_normalized = key.lower().replace('_', '').replace('-', '')
            
            # Exact match
            if field_normalized == key_normalized:
                return True
            
            # Partial match (field name contained in key or vice versa)
            if field_normalized in key_normalized or key_normalized in field_normalized:
                # Require at least 70% similarity
                similarity = min(len(field_normalized), len(key_normalized)) / max(len(field_normalized), len(key_normalized))
                if similarity >= 0.7:
                    return True
        
        return False
    
    def find_discovery_for_field(self, field_path: str) -> Optional[str]:
        """Find which discovery produces a given field path."""
        # field_path format: "item.KeyAlgorithm" or "item.CertificateArn"
        # Extract field name (remove "item." prefix if present)
        if field_path.startswith('item.'):
            field_name = field_path[5:]  # Remove "item." prefix
        elif '.' in field_path:
            field_name = field_path.split('.')[-1]
        else:
            field_name = field_path
        
        # First pass: find exact or close matches
        exact_matches = []
        close_matches = []
        
        for discovery in self.discoveries:
            if self.field_exists_in_discovery(field_name, discovery):
                # Prefer discoveries without dependencies (root discoveries)
                if 'for_each' not in discovery:
                    exact_matches.insert(0, discovery['discovery_id'])
                else:
                    exact_matches.append(discovery['discovery_id'])
        
        if exact_matches:
            return exact_matches[0]
        
        # Second pass: try partial matching with scoring
        best_match = None
        best_score = 0
        
        field_normalized = field_name.lower().replace('_', '').replace('-', '')
        
        for discovery in self.discoveries:
            emit = discovery.get('emit', {})
            item_fields = emit.get('item', {})
            
            for key in item_fields.keys():
                key_normalized = key.lower().replace('_', '').replace('-', '')
                
                # Calculate similarity
                if field_normalized in key_normalized or key_normalized in field_normalized:
                    score = min(len(field_normalized), len(key_normalized)) / max(len(field_normalized), len(key_normalized))
                    # Bonus for root discoveries (no dependencies)
                    if 'for_each' not in discovery:
                        score += 0.1
                    
                    if score > best_score:
                        best_score = score
                        best_match = discovery['discovery_id']
        
        return best_match
    
    def infer_field_from_rule(self, rule_id: str, metadata: Dict[str, Any]) -> Optional[str]:
        """Infer which field to check from rule_id and metadata."""
        # Extract resource and requirement from metadata
        resource = metadata.get('resource', '')
        requirement = metadata.get('requirement', '').lower()
        title = metadata.get('title', '').lower()
        
        # Common field mappings based on requirement/keywords
        field_mappings = {
            'key_length': 'KeyAlgorithm',
            'encryption': 'Encryption',
            'expiration': 'NotAfter',
            'monitored': 'DaysBeforeExpiry',
            'issuer': 'Issuer',
            'tls': 'Status',
            'public': 'PublicAccessBlock',
            'logging': 'LoggingEnabled',
            'versioning': 'Versioning',
            'mfa': 'MfaEnabled',
            'policy': 'Policy'
        }
        
        # Try to match requirement or title
        for keyword, field in field_mappings.items():
            if keyword in requirement or keyword in title:
                return f"item.{field}"
        
        # Fallback: try to infer from rule_id
        # e.g., "aws.acm.certificate.key_length_minimum" -> "KeyAlgorithm"
        rule_parts = rule_id.split('.')
        if len(rule_parts) >= 4:
            check_type = rule_parts[-1]  # e.g., "key_length_minimum"
            if 'key_length' in check_type:
                return "item.KeyAlgorithm"
            elif 'expiration' in check_type or 'monitored' in check_type:
                return "item.NotAfter"
            elif 'issuer' in check_type:
                return "item.Issuer"
            elif 'tls' in check_type:
                return "item.Status"
        
        return None
    
    def infer_condition_from_requirement(self, requirement: str, rule_id: str) -> Dict[str, Any]:
        """Infer check condition from requirement and rule_id."""
        requirement_lower = requirement.lower()
        rule_lower = rule_id.lower()
        
        # Pattern matching for common requirements
        if 'minimum' in requirement_lower or 'minimum' in rule_lower:
            if 'key_length' in requirement_lower or 'key_length' in rule_lower:
                return {
                    'var': 'item.KeyAlgorithm',
                    'op': 'contains',
                    'value': '2048'
                }
        
        if 'enabled' in requirement_lower or 'enabled' in rule_lower:
            return {
                'var': 'item.Encryption',
                'op': 'equals',
                'value': 'enabled'
            }
        
        if 'monitored' in requirement_lower or 'monitored' in rule_lower:
            return {
                'var': 'item.DaysBeforeExpiry',
                'op': 'exists'
            }
        
        if 'issuer' in requirement_lower or 'issuer' in rule_lower:
            return {
                'var': 'item.Issuer',
                'op': 'equals',
                'value': 'Amazon'
            }
        
        if 'tls' in requirement_lower or 'tls' in rule_lower:
            return {
                'var': 'item.Status',
                'op': 'equals',
                'value': 'ISSUED'
            }
        
        # Default fallback
        return {
            'var': 'item.Status',
            'op': 'exists'
        }
    
    def generate_checks_from_metadata(self, metadata_dir: Path):
        """Generate checks from metadata YAML files."""
        if not metadata_dir.exists():
            return
        
        metadata_files = list(metadata_dir.glob("*.yaml"))
        if not metadata_files:
            return
        
        print(f"     📋 Found {len(metadata_files)} metadata files")
        
        for metadata_file in metadata_files:
            try:
                with open(metadata_file, 'r') as f:
                    metadata = yaml.safe_load(f)
                
                rule_id = metadata.get('rule_id', '')
                if not rule_id:
                    continue
                
                # Infer field to check
                field_path = self.infer_field_from_rule(rule_id, metadata)
                
                # Find which discovery produces this field
                discovery_id = None
                
                if field_path:
                    # Try to find discovery by field
                    discovery_id = self.find_discovery_for_field(field_path)
                
                # If not found by field, try by resource type
                if not discovery_id:
                    resource = metadata.get('resource', '')
                    # Find discovery that matches resource
                    for discovery in self.discoveries:
                        d_id = discovery['discovery_id']
                        # Match resource name in discovery_id
                        if resource.lower() in d_id.lower():
                            discovery_id = d_id
                            break
                
                # If still not found, try to match by rule_id pattern
                if not discovery_id:
                    # Extract operation from rule_id (e.g., "aws.acm.certificate.key_length" -> "certificate")
                    rule_parts = rule_id.split('.')
                    if len(rule_parts) >= 3:
                        resource_type = rule_parts[2]  # e.g., "certificate"
                        # Find discovery that contains this resource type
                        for discovery in self.discoveries:
                            d_id = discovery['discovery_id']
                            if resource_type.lower() in d_id.lower():
                                discovery_id = d_id
                                break
                
                # Last resort: use first discovery that seems relevant
                if not discovery_id and self.discoveries:
                    # Prefer list operations for checks
                    for discovery in self.discoveries:
                        if 'list' in discovery['discovery_id'] or 'get' in discovery['discovery_id']:
                            discovery_id = discovery['discovery_id']
                            break
                    
                    # If no list/get, use first discovery
                    if not discovery_id:
                        discovery_id = self.discoveries[0]['discovery_id']
                
                if not discovery_id:
                    # Skip if no discovery found
                    continue
                
                # Infer condition
                requirement = metadata.get('requirement', '')
                condition = self.infer_condition_from_requirement(requirement, rule_id)
                
                # Update condition var - use the field we found or inferred
                if field_path:
                    condition['var'] = field_path
                elif not condition.get('var'):
                    # Fallback: use a generic field based on discovery
                    condition['var'] = 'item.Status'
                
                # Create check
                check = {
                    'rule_id': rule_id,
                    'for_each': discovery_id,
                    'conditions': condition
                }
                
                self.checks.append(check)
            
            except Exception as e:
                # Skip invalid metadata files
                continue
    
    def generate_checks(self):
        """Generate check items from metadata files."""
        # Look for metadata directory
        metadata_dir = Path(f"aws_compliance_python_engine/services/{self.service_name}/metadata")
        
        if metadata_dir.exists():
            self.generate_checks_from_metadata(metadata_dir)
        else:
            # No metadata directory - skip check generation
            pass
    
    def generate_yaml(self) -> Dict[str, Any]:
        """Generate complete YAML structure."""
        return {
            'version': '1.0',
            'provider': 'aws',
            'service': self.service_name,
            'services': {
                'client': self.service_name,
                'module': 'boto3.client'
            },
            'discovery': self.discoveries,
            'checks': self.checks
        }
    
    def generate(self) -> bool:
        """Main generation method."""
        print(f"  📝 Generating rules for {self.service_name}...")
        
        if not self.load_data_sources():
            return False
        
        print(f"     ✓ Loaded data sources")
        
        self.generate_discoveries()
        print(f"     ✓ Generated {len(self.discoveries)} discovery items")
        
        # Generate checks after discoveries (needs discovery_map)
        self.generate_checks()
        print(f"     ✓ Generated {len(self.checks)} check items")
        
        return True
    
    def save(self, output_path: Path):
        """Save generated YAML to file."""
        yaml_data = self.generate_yaml()
        
        # Create backup if file exists
        if output_path.exists():
            backup_path = output_path.with_suffix('.yaml.bak')
            import shutil
            shutil.copy2(output_path, backup_path)
            print(f"     ✓ Created backup: {backup_path.name}")
        
        with open(output_path, 'w') as f:
            yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"     ✓ Saved: {output_path}")


def generate_rules_for_service(service_path: Path, service_name: str, output_path: Path) -> bool:
    """Generate rules for a single service."""
    generator = RulesGenerator(service_path, service_name)
    
    if not generator.generate():
        return False
    
    generator.save(output_path)
    return True


def generate_all_services(root_path: Path = None) -> Dict[str, Any]:
    """Generate rules for all services in the database."""
    if root_path is None:
        root_path = Path("pythonsdk-database/aws")
    
    if not root_path.exists():
        print(f"Error: Root path not found: {root_path}")
        return {'success': False, 'error': 'Root path not found'}
    
    results = {
        'total': 0,
        'success': 0,
        'failed': 0,
        'services': []
    }
    
    # Find all service directories with operation_registry.json
    service_dirs = []
    for service_dir in root_path.iterdir():
        if service_dir.is_dir():
            registry_file = service_dir / "operation_registry.json"
            if registry_file.exists():
                service_dirs.append(service_dir)
    
    results['total'] = len(service_dirs)
    
    print(f"\n{'='*70}")
    print(f"GENERATING RULES FOR ALL SERVICES")
    print(f"{'='*70}")
    print(f"Found {results['total']} services with operation_registry.json")
    print(f"{'='*70}\n")
    
    for i, service_path in enumerate(sorted(service_dirs), 1):
        service_name = service_path.name
        output_path = Path(f"aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
        
        print(f"[{i}/{results['total']}] Processing: {service_name}")
        
        try:
            # Create output directory if needed
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            success = generate_rules_for_service(service_path, service_name, output_path)
            
            if success:
                results['success'] += 1
                results['services'].append({
                    'service': service_name,
                    'status': 'success',
                    'output': str(output_path)
                })
                print(f"  ✅ Success\n")
            else:
                results['failed'] += 1
                results['services'].append({
                    'service': service_name,
                    'status': 'failed',
                    'error': 'Generation failed'
                })
                print(f"  ❌ Failed\n")
        except Exception as e:
            results['failed'] += 1
            results['services'].append({
                'service': service_name,
                'status': 'error',
                'error': str(e)
            })
            print(f"  ❌ Error: {e}\n")
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"GENERATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total Services: {results['total']}")
    print(f"  ✅ Success: {results['success']} ({results['success']/results['total']*100:.1f}%)")
    print(f"  ❌ Failed:  {results['failed']} ({results['failed']/results['total']*100:.1f}%)")
    print(f"{'='*70}\n")
    
    # Save summary report
    summary_file = Path("tools/rules_generation_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Summary saved to: {summary_file}\n")
    
    return results


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate compliance rules YAML files from service data',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'service_path',
        nargs='?',
        help='Path to service directory (e.g., pythonsdk-database/aws/acm). Omit to process all services.'
    )
    parser.add_argument(
        '--output',
        help='Output path for YAML file (default: aws_compliance_python_engine/services/<service>/rules/<service>.yaml)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Generate rules for all services'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/aws',
        help='Root path for services (default: pythonsdk-database/aws)'
    )
    
    args = parser.parse_args()
    
    # Process all services
    if args.all or not args.service_path:
        root_path = Path(args.root)
        results = generate_all_services(root_path)
        sys.exit(0 if results['success'] > 0 else 1)
    
    # Process single service
    service_path = Path(args.service_path)
    service_name = service_path.name
    
    if args.output:
        output_path = Path(args.output)
    else:
        # Default output to rules folder
        output_path = Path(f"aws_compliance_python_engine/services/{service_name}/rules/{service_name}.yaml")
    
    print(f"\n{'='*70}")
    print(f"Generating Rules for: {service_name}")
    print(f"{'='*70}")
    
    if not service_path.exists():
        print(f"Error: Service path not found: {service_path}")
        sys.exit(1)
    
    # Create output directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    success = generate_rules_for_service(service_path, service_name, output_path)
    
    if success:
        print(f"\n{'='*70}")
        print(f"✅ Successfully generated rules for {service_name}")
        print(f"   Output: {output_path}")
        print(f"{'='*70}\n")
    else:
        print(f"\n{'='*70}")
        print(f"❌ Failed to generate rules for {service_name}")
        print(f"{'='*70}\n")
        sys.exit(1)


if __name__ == '__main__':
    main()

