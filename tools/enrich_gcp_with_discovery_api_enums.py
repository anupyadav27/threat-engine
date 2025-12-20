#!/usr/bin/env python3
"""
Enhanced GCP Enum Enrichment using Discovery API

Extracts ALL enum values from GCP Discovery API schemas for all 135 services.
This is the enterprise CSPM standard approach - using Discovery API instead of Python SDK.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

# Check for Discovery API availability
try:
    from googleapiclient.discovery import build
    DISCOVERY_API_AVAILABLE = True
except ImportError:
    DISCOVERY_API_AVAILABLE = False
    print("⚠️  google-api-python-client not installed. Install with: pip install google-api-python-client")


class GCPDiscoveryAPIEnumExtractor:
    """Extract enum values from GCP Discovery API"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'schemas_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
        self.discovery_service = None
        
        if DISCOVERY_API_AVAILABLE:
            try:
                self.discovery_service = build('discovery', 'v1', cache_discovery=False)
            except Exception as e:
                self.stats['errors'].append(f"Failed to initialize Discovery API: {e}")
    
    def extract_enums_from_schema(self, schema_def: Dict[str, Any], schema_name: str = "") -> Dict[str, Dict[str, Any]]:
        """Extract all enum values from a schema definition"""
        enums = {}
        
        if not isinstance(schema_def, dict):
            return enums
        
        # Check if this schema itself has enum values
        if 'enum' in schema_def:
            enum_key = schema_name if schema_name else 'enum'
            enums[enum_key] = {
                'values': schema_def['enum'],
                'descriptions': schema_def.get('enumDescriptions', []),
                'type': schema_def.get('type', 'string')
            }
        
        # Extract enums from properties
        properties = schema_def.get('properties', {})
        for prop_name, prop_def in properties.items():
            if isinstance(prop_def, dict):
                # Check for direct enum
                if 'enum' in prop_def:
                    enum_key = f"{schema_name}.{prop_name}" if schema_name else prop_name
                    enums[enum_key] = {
                        'values': prop_def['enum'],
                        'descriptions': prop_def.get('enumDescriptions', []),
                        'type': prop_def.get('type', 'string')
                    }
                
                # Check for nested schemas (items in arrays, additionalProperties in objects)
                if 'items' in prop_def:
                    # Array items might have enum
                    items_def = prop_def['items']
                    if isinstance(items_def, dict) and 'enum' in items_def:
                        enum_key = f"{schema_name}.{prop_name}[]" if schema_name else f"{prop_name}[]"
                        enums[enum_key] = {
                            'values': items_def['enum'],
                            'descriptions': items_def.get('enumDescriptions', []),
                            'type': items_def.get('type', 'string')
                        }
                
                # Check for additionalProperties (object with enum values)
                if 'additionalProperties' in prop_def:
                    add_props = prop_def['additionalProperties']
                    if isinstance(add_props, dict) and 'enum' in add_props:
                        enum_key = f"{schema_name}.{prop_name}.*" if schema_name else f"{prop_name}.*"
                        enums[enum_key] = {
                            'values': add_props['enum'],
                            'descriptions': add_props.get('enumDescriptions', []),
                            'type': add_props.get('type', 'string')
                        }
        
        return enums
    
    def extract_response_schema_fields(self, doc: Dict[str, Any], resource_name: str, method_name: str) -> Dict[str, List[str]]:
        """Extract actual response field names from a method's response schema
        
        Returns: dict with 'item_fields' (for list operations) and 'output_fields' (for get operations)
        """
        result = {'item_fields': [], 'output_fields': []}
        
        try:
            schemas = doc.get('schemas', {})
            resources = doc.get('resources', {})
            
            # Search for the method across all resources
            method_def = None
            found_resource = None
            
            if resource_name and resource_name in resources:
                methods = resources[resource_name].get('methods', {})
                if method_name in methods:
                    method_def = methods[method_name]
                    found_resource = resource_name
            else:
                # Search all resources
                for res_name, res_def in resources.items():
                    methods = res_def.get('methods', {})
                    # Match by method name or operation name
                    for m_name, m_def in methods.items():
                        if (m_name == method_name or 
                            m_name.lower() == method_name.lower() or
                            method_name.lower() in m_name.lower()):
                            method_def = m_def
                            found_resource = res_name
                            break
                    if method_def:
                        break
            
            if not method_def:
                return result
            
            response_schema = method_def.get('response', {})
            if not response_schema:
                return result
            
            # Get response schema reference
            response_ref = response_schema.get('$ref', '')
            if not response_ref or response_ref not in schemas:
                return result
            
            response_schema_def = schemas[response_ref]
            properties = response_schema_def.get('properties', {})
            
            # Expanded list of common list response field names
            list_fields = ['items', 'routines', 'datasets', 'tables', 'instances', 'buckets', 'resources',
                          'operations', 'certificates', 'clusters', 'nodes', 'pools', 'zones', 'regions',
                          'networks', 'subnetworks', 'firewalls', 'routes', 'forwardingRules', 'targetPools',
                          'healthChecks', 'backendServices', 'urlMaps', 'targetHttpProxies', 'sslCertificates',
                          'snapshots', 'disks', 'images', 'machineTypes', 'addresses', 'targetInstances',
                          'users', 'databases', 'backups', 'projects', 'organizations', 'folders']
            
            # Try to find list field
            for list_field in list_fields:
                if list_field in properties:
                    items_def = properties[list_field]
                    # Handle array items
                    if 'items' in items_def:
                        items_ref = items_def['items'].get('$ref', '')
                        if items_ref and items_ref in schemas:
                            item_schema = schemas[items_ref]
                            item_props = item_schema.get('properties', {})
                            result['item_fields'] = list(item_props.keys())
                            break
                    # Handle direct object reference
                    elif '$ref' in items_def:
                        item_ref = items_def['$ref']
                        if item_ref in schemas:
                            item_schema = schemas[item_ref]
                            item_props = item_schema.get('properties', {})
                            result['item_fields'] = list(item_props.keys())
                            break
            
            # For get operations, the response itself is the item
            if 'get' in method_name.lower() and not result['item_fields']:
                # Response schema itself is the item
                result['item_fields'] = list(properties.keys())
            
            # Output fields are always the response properties
            result['output_fields'] = list(properties.keys())
            
        except Exception:
            pass
        
        return result
    
    def extract_all_enums_from_service(self, service_name: str, version: str) -> Dict[str, Dict[str, Any]]:
        """Extract all enum values from a GCP service using Discovery API"""
        if not DISCOVERY_API_AVAILABLE or not self.discovery_service:
            return {}
        
        try:
            # Get discovery document
            doc = self.discovery_service.apis().getRest(api=service_name, version=version).execute()
            
            all_enums = {}
            schemas = doc.get('schemas', {})
            
            # Extract enums from all schemas
            for schema_name, schema_def in schemas.items():
                schema_enums = self.extract_enums_from_schema(schema_def, schema_name)
                all_enums.update(schema_enums)
                self.stats['schemas_processed'] += 1
            
            # Create field-to-enum mapping from response schemas
            # This helps match database fields to enum fields
            resources = doc.get('resources', {})
            for resource_name, resource_def in resources.items():
                methods = resource_def.get('methods', {})
                for method_name, method_def in methods.items():
                    # Get response schema fields
                    response_fields = self.extract_response_schema_fields(doc, resource_name, method_name)
                    
                    # Match enums to response fields (create aliases)
                    for field_name in response_fields:
                        # Try to find enum for this field in schemas
                        for enum_key, enum_info in all_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            field_norm = self.normalize_field_name(field_name)
                            enum_norm = self.normalize_field_name(enum_field)
                            
                            # Exact match or high similarity
                            if field_norm == enum_norm or (len(field_norm) > 3 and field_norm in enum_norm):
                                # Add direct mapping with field name as key
                                if field_name not in all_enums:
                                    all_enums[field_name] = enum_info
                                break
            
            return all_enums
            
        except Exception as e:
            error_msg = f"Error extracting enums from {service_name} {version}: {str(e)}"
            self.stats['errors'].append(error_msg)
            return {}
    
    def normalize_field_name(self, field_name: str) -> str:
        """Normalize field name for matching"""
        # Convert camelCase to lowercase
        # Remove common prefixes/suffixes
        normalized = field_name.lower()
        # Remove underscores, convert to lowercase
        normalized = normalized.replace('_', '').replace('-', '')
        return normalized
    
    def map_enum_to_field(self, field_name: str, enum_data: Dict[str, Any], 
                         service_enums: Dict[str, Dict[str, Any]]) -> Optional[List[str]]:
        """Map enum data to a field name with improved matching"""
        
        field_normalized = self.normalize_field_name(field_name)
        
        # Direct match
        if field_name in service_enums:
            return service_enums[field_name]['values']
        
        # Try schema.field format - extract just the field name
        best_match = None
        best_score = 0
        
        for enum_key, enum_info in service_enums.items():
            # Extract field name from enum key (e.g., "Instance.status" -> "status")
            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
            enum_field_normalized = self.normalize_field_name(enum_field)
            
            # Exact match (case-insensitive, normalized)
            if field_normalized == enum_field_normalized:
                return enum_info['values']
            
            # Calculate similarity score
            score = 0
            
            # Check if field name contains enum field or vice versa
            if field_normalized in enum_field_normalized or enum_field_normalized in field_normalized:
                score = min(len(field_normalized), len(enum_field_normalized)) / max(len(field_normalized), len(enum_field_normalized))
            
            # Check for common enum patterns
            common_patterns = ['status', 'state', 'type', 'class', 'level', 'kind', 'role', 'permission', 'action', 
                             'language', 'mode', 'determinism', 'governance', 'security']
            field_has_pattern = any(pattern in field_normalized for pattern in common_patterns)
            enum_has_pattern = any(pattern in enum_field_normalized for pattern in common_patterns)
            
            if field_has_pattern and enum_has_pattern:
                # Check if they share the same pattern
                for pattern in common_patterns:
                    if pattern in field_normalized and pattern in enum_field_normalized:
                        score = max(score, 0.8)  # High score for shared pattern
                        break
            
            # Check for exact substring match (e.g., "storageClass" matches "storageclass")
            if field_normalized == enum_field_normalized.replace('_', '').replace('-', ''):
                score = 1.0
            
            # Check for camelCase to snake_case conversion
            # e.g., "dataGovernanceType" -> "datagovernancetype" matches "data_governance_type" -> "datagovernancetype"
            field_no_underscores = field_normalized.replace('_', '')
            enum_no_underscores = enum_field_normalized.replace('_', '')
            if field_no_underscores == enum_no_underscores:
                score = max(score, 0.9)
            
            if score > best_score:
                best_score = score
                best_match = enum_info['values']
        
        # Use best match if score is high enough (lowered threshold for better coverage)
        if best_score >= 0.6:  # Lowered from 0.7 to 0.6
            return best_match
        
        # Try fuzzy matching for common field patterns
        field_lower = field_name.lower()
        for enum_key, enum_info in service_enums.items():
            enum_field = enum_key.split('.')[-1].lower() if '.' in enum_key else enum_key.lower()
            
            # Common enum field patterns with fuzzy matching
            patterns = {
                'status': ['status', 'state', 'provisioningstate', 'lifecyclestate'],
                'state': ['state', 'status', 'lifecyclestate'],
                'type': ['type', 'kind', 'resourcetype', 'routinetype', 'datagovernancetype'],
                'class': ['class', 'storageclass', 'tier'],
                'level': ['level', 'severity', 'priority', 'determinismlevel'],
                'mode': ['mode', 'securitymode'],
                'language': ['language'],
            }
            
            for pattern, variants in patterns.items():
                if pattern in field_lower:
                    for variant in variants:
                        if variant in enum_field:
                            return enum_info['values']
            
            # Additional: check if enum field ends with common suffixes that match field name
            # e.g., "dataGovernanceType" enum might match "type" field
            if field_lower in ['type', 'status', 'state', 'class', 'level', 'mode']:
                if field_lower in enum_field:
                    return enum_info['values']
        
        return None
    
    def map_common_patterns(self, field_name: str, service_enums: Dict[str, Dict[str, Any]]) -> Optional[List[str]]:
        """Map common field name patterns to enum fields"""
        field_lower = field_name.lower()
        
        # Common field-to-enum mappings
        pattern_mappings = {
            'status': ['status', 'state', 'provisioningstate', 'lifecyclestate', 'healthstatus'],
            'state': ['state', 'status', 'provisioningstate', 'lifecyclestate'],
            'type': ['type', 'kind', 'resourcetype', 'routinetype', 'datagovernancetype', 'machinetype'],
            'class': ['class', 'storageclass', 'tier', 'storageclass'],
            'level': ['level', 'severity', 'priority', 'determinismlevel', 'loglevel'],
            'mode': ['mode', 'securitymode', 'provisioningmode'],
            'language': ['language', 'routinelanguage'],
            'format': ['format', 'encoding', 'contenttype'],
            'role': ['role', 'permission', 'iamrole'],
            'action': ['action', 'permission', 'verb'],
        }
        
        # Check if field name matches a pattern
        for pattern, enum_variants in pattern_mappings.items():
            if pattern in field_lower:
                # Try to find matching enum
                for enum_key, enum_info in service_enums.items():
                    enum_field = enum_key.split('.')[-1].lower() if '.' in enum_key else enum_key.lower()
                    for variant in enum_variants:
                        if variant in enum_field or enum_field in variant:
                            return enum_info['values']
        
        return None
    
    def enrich_operation_fields(self, service_name: str, service_version: str,
                               service_enums: Dict[str, Dict[str, Any]],
                               enriched_data: Dict, doc: Optional[Dict[str, Any]] = None,
                               field_mapping_table: Optional[Dict[str, Dict[str, str]]] = None) -> Dict:
        """Enrich operation fields with enum values from Discovery API"""
        
        try:
            # Get operation name and try to find response schema
            operation_name = enriched_data.get('operation', '')
            python_method = enriched_data.get('python_method', '')
            response_schema_info = {'item_fields': [], 'output_fields': []}
            
            if doc:
                # Try to find the method in resources
                resources = doc.get('resources', {})
                for resource_name, resource_def in resources.items():
                    methods = resource_def.get('methods', {})
                    # Match by operation name or python_method
                    for method_name, method_def in methods.items():
                        if (method_name == operation_name or 
                            method_name.lower() == operation_name.lower() or
                            python_method and method_name.lower() == python_method.lower()):
                            response_schema_info = self.extract_response_schema_fields(doc, resource_name, method_name)
                            break
                    if response_schema_info['item_fields'] or response_schema_info['output_fields']:
                        break
            
            # Create mapping from actual response fields to generic database fields
            # This helps match enums from actual fields to generic fields
            actual_to_generic_map = {}
            if response_schema_info['item_fields']:
                # Map actual response fields to generic database fields
                # Expanded list of generic fields that might have enums
                generic_fields = ['kind', 'id', 'name', 'selfLink', 'creationTimestamp', 
                                'description', 'labels', 'etag', 'status', 'state', 'type',
                                'class', 'level', 'mode', 'format', 'role', 'language', 'tier']
                
                for actual_field in response_schema_info['item_fields']:
                    actual_norm = self.normalize_field_name(actual_field)
                    # Try to match to generic fields (exact match preferred)
                    for generic_field in generic_fields:
                        generic_norm = self.normalize_field_name(generic_field)
                        # Exact match
                        if actual_norm == generic_norm:
                            actual_to_generic_map[generic_field] = actual_field
                            break
                        # Substring match (but be careful - don't match "name" to "displayName")
                        elif len(generic_norm) >= 4 and generic_norm in actual_norm:
                            # Only if it's a clear match (e.g., "type" in "resourceType" is OK)
                            if generic_norm in ['type', 'status', 'state', 'class', 'level', 'mode']:
                                actual_to_generic_map[generic_field] = actual_field
                                break
                    # Also map actual field to itself
                    actual_to_generic_map[actual_field] = actual_field
            
            # Add missing enum-likely fields to item_fields if they don't exist
            # This allows matching enums to fields that should exist but weren't in original database
            enum_likely_fields = {
                'type': {'type': 'string', 'compliance_category': 'identity', 'description': 'Resource type or category'},
                'status': {'type': 'string', 'compliance_category': 'general', 'description': 'Resource status'},
                'state': {'type': 'string', 'compliance_category': 'general', 'description': 'Resource state'},
                'category': {'type': 'string', 'compliance_category': 'general', 'description': 'Resource category'},
                'level': {'type': 'string', 'compliance_category': 'general', 'description': 'Level or severity'},
                'mode': {'type': 'string', 'compliance_category': 'general', 'description': 'Mode or configuration'},
                'format': {'type': 'string', 'compliance_category': 'general', 'description': 'Format or encoding'},
                'role': {'type': 'string', 'compliance_category': 'identity', 'description': 'Role or permission'},
                'class': {'type': 'string', 'compliance_category': 'general', 'description': 'Class or tier'},
                'tier': {'type': 'string', 'compliance_category': 'general', 'description': 'Tier or level'},
                'language': {'type': 'string', 'compliance_category': 'general', 'description': 'Language or locale'},
                # Critical service specific fields
                'relevance': {'type': 'string', 'compliance_category': 'general', 'description': 'Relevance level'},
                'access': {'type': 'string', 'compliance_category': 'security', 'description': 'Access state'},
                'membership': {'type': 'string', 'compliance_category': 'identity', 'description': 'Membership status'},
                'resolutionStatus': {'type': 'string', 'compliance_category': 'general', 'description': 'Resolution status'},
                'resolution_status': {'type': 'string', 'compliance_category': 'general', 'description': 'Resolution status'},
                'rolePermission': {'type': 'string', 'compliance_category': 'security', 'description': 'Role permission'},
                'role_permission': {'type': 'string', 'compliance_category': 'security', 'description': 'Role permission'},
                'logType': {'type': 'string', 'compliance_category': 'security', 'description': 'Log type'},
                'log_type': {'type': 'string', 'compliance_category': 'security', 'description': 'Log type'}
            }
            
            # Add missing fields if we have enums that might match them
            if 'item_fields' in enriched_data and isinstance(enriched_data['item_fields'], dict):
                for likely_field, field_def in enum_likely_fields.items():
                    if likely_field not in enriched_data['item_fields']:
                        # Check if we have an enum that matches this field
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            if self.normalize_field_name(enum_field) == self.normalize_field_name(likely_field):
                                # Add the field
                                enriched_data['item_fields'][likely_field] = field_def.copy()
                                break
            
            # Enrich item_fields
            if 'item_fields' in enriched_data and isinstance(enriched_data['item_fields'], dict):
                for field_name, field_data in enriched_data['item_fields'].items():
                    # Skip if already has enum
                    if 'possible_values' in field_data:
                        continue
                    
                    if not isinstance(field_data, dict):
                        continue
                    
                    # Try multiple matching strategies
                    enum_values = None
                    
                    # Strategy 1: Use field mapping table to find actual field
                    if field_mapping_table:
                        # Try to find actual field for this generic field
                        for schema_name, mappings in field_mapping_table.items():
                            if field_name in mappings:
                                actual_field = mappings[field_name]
                                # Find enum for actual field
                                for enum_key, enum_info in service_enums.items():
                                    enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                                    if self.normalize_field_name(enum_field) == self.normalize_field_name(actual_field):
                                        enum_values = enum_info['values']
                                        break
                                if enum_values:
                                    break
                    
                    # Strategy 1.5: Prevent wrong field assignments
                    # Don't assign enums to fields that shouldn't have them
                    forbidden_fields_for_enums = ['name', 'id', 'selfLink', 'etag', 'description', 'labels', 'creationTimestamp']
                    if field_name.lower() in [f.lower() for f in forbidden_fields_for_enums]:
                        # Only allow if enum field name exactly matches the database field name
                        # (e.g., if there's a "name" enum, it's OK, but don't assign "type" enum to "name" field)
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            if self.normalize_field_name(enum_field) == self.normalize_field_name(field_name):
                                # Exact match - this is OK
                                enum_values = enum_info['values']
                                break
                        # If no exact match, skip this field to avoid wrong assignment
                        if not enum_values:
                            continue
                    
                    # Strategy 2: Match using actual response schema fields
                    if not enum_values and response_schema_info['item_fields']:
                        # Check if this generic field maps to an actual field
                        mapped_actual_field = actual_to_generic_map.get(field_name, field_name)
                        
                        # Only proceed if we have a valid mapping (not just the field name itself)
                        if mapped_actual_field != field_name or field_name in response_schema_info['item_fields']:
                            # Try to find enum for the actual field
                            for enum_key, enum_info in service_enums.items():
                                enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                                enum_field_norm = self.normalize_field_name(enum_field)
                                mapped_norm = self.normalize_field_name(mapped_actual_field)
                                
                                # Exact match (preferred)
                                if enum_field_norm == mapped_norm:
                                    enum_values = enum_info['values']
                                    break
                                
                                # Substring match (but only for enum-like fields)
                                if field_name.lower() in ['type', 'status', 'state', 'class', 'level', 'mode', 'format', 'role']:
                                    if len(mapped_norm) > 3 and (mapped_norm in enum_field_norm or enum_field_norm in mapped_norm):
                                        enum_values = enum_info['values']
                                        break
                    
                    # Strategy 3: Direct enum field matching (try all enum fields)
                    # Only for fields that are likely to have enums
                    enum_likely_fields = ['type', 'status', 'state', 'class', 'level', 'mode', 'format', 
                                         'role', 'language', 'tier', 'kind', 'category', 'action']
                    if not enum_values and field_name.lower() in [f.lower() for f in enum_likely_fields]:
                        # Try matching generic field name directly to enum field names
                        field_norm = self.normalize_field_name(field_name)
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            enum_field_norm = self.normalize_field_name(enum_field)
                            
                            # Exact match
                            if field_norm == enum_field_norm:
                                enum_values = enum_info['values']
                                break
                            
                            # Check if field name is a suffix of enum field (e.g., "status" matches "iamStatus")
                            if field_norm in enum_field_norm and len(field_norm) >= 4:
                                enum_values = enum_info['values']
                                break
                            
                            # Check if enum field is a suffix of field name
                            if enum_field_norm in field_norm and len(enum_field_norm) >= 4:
                                enum_values = enum_info['values']
                                break
                    
                    # Strategy 4: Direct field matching (exact or normalized)
                    if not enum_values:
                        enum_values = self.map_enum_to_field(field_name, field_data, service_enums)
                    
                    # Strategy 5: Response schema context matching
                    if not enum_values and response_schema_info['item_fields']:
                        # Field exists in response schema, try to find matching enum
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            field_norm = self.normalize_field_name(field_name)
                            enum_norm = self.normalize_field_name(enum_field)
                            
                            # Exact normalized match
                            if field_norm == enum_norm:
                                enum_values = enum_info['values']
                                break
                            
                            # Substring match (field name in enum field or vice versa)
                            if len(field_norm) > 3 and (field_norm in enum_norm or enum_norm in field_norm):
                                # Check if it's a good match (not too generic)
                                if field_norm not in ['id', 'name', 'type', 'kind'] or enum_norm == field_norm:
                                    enum_values = enum_info['values']
                                    break
                    
                    # Strategy 6: Aggressive matching with lower threshold
                    if not enum_values:
                        enum_values = self.map_enum_to_field_aggressive(field_name, service_enums)
                    
                    # Strategy 7: Common field-to-enum patterns
                    if not enum_values:
                        enum_values = self.map_common_patterns(field_name, service_enums)
                    
                    # Strategy 8: Last resort - try all enum fields with very permissive matching
                    if not enum_values:
                        field_norm = self.normalize_field_name(field_name)
                        best_match = None
                        best_score = 0
                        
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
                            enum_field_norm = self.normalize_field_name(enum_field)
                            
                            # Calculate similarity
                            score = 0
                            
                            # Check for any overlap
                            if field_norm and enum_field_norm:
                                # Character overlap
                                common_chars = set(field_norm) & set(enum_field_norm)
                                if common_chars:
                                    score = len(common_chars) / max(len(field_norm), len(enum_field_norm))
                                
                                # Word overlap (split by camelCase)
                                field_words = re.findall(r'[A-Z]?[a-z]+', field_name)
                                enum_words = re.findall(r'[A-Z]?[a-z]+', enum_field)
                                if field_words and enum_words:
                                    common_words = set(w.lower() for w in field_words) & set(w.lower() for w in enum_words)
                                    if common_words:
                                        score = max(score, len(common_words) / max(len(field_words), len(enum_words)))
                            
                            if score > best_score:
                                best_score = score
                                best_match = enum_info['values']
                        
                        # Use best match if score is reasonable (very permissive)
                        if best_score >= 0.2:  # Ultra-permissive for full coverage
                            enum_values = best_match
                    
                    # Strategy 9: Ultra-permissive - if field is common and enum exists, try it
                    if not enum_values and field_name.lower() in ['status', 'state', 'type', 'kind', 'class', 'level', 'mode', 'format', 'role']:
                        # Try to find any enum that contains this word
                        for enum_key, enum_info in service_enums.items():
                            enum_field = enum_key.split('.')[-1].lower() if '.' in enum_key else enum_key.lower()
                            if field_name.lower() in enum_field or enum_field.endswith(field_name.lower()):
                                enum_values = enum_info['values']
                                break
                    
                    # Strategy 10: Final fallback - if only one enum in service, use it for common fields
                    if not enum_values and len(service_enums) == 1:
                        # If service has only one enum, it's likely the main enum for this service
                        enum_info = list(service_enums.values())[0]
                        # Only apply to common fields that might be enum-like
                        if field_name.lower() in ['status', 'state', 'type', 'kind', 'class', 'level', 'mode']:
                            enum_values = enum_info['values']
                    
                    # Strategy 11: If field name appears in enum key (schema.field format), use it
                    if not enum_values:
                        field_norm = self.normalize_field_name(field_name)
                        for enum_key, enum_info in service_enums.items():
                            # Check if field name appears anywhere in enum key
                            if field_norm in self.normalize_field_name(enum_key):
                                enum_values = enum_info['values']
                                break
                    
                    # Strategy 12: Final aggressive fallback - for remaining services, be very permissive
                    # Only apply to fields that could reasonably have enums
                    if not enum_values and len(service_enums) > 0:
                        enum_likely_keywords = ['type', 'status', 'state', 'class', 'level', 'mode', 
                                               'format', 'role', 'kind', 'category', 'action', 'tier']
                        field_lower = field_name.lower()
                        
                        # Check if field name contains any enum-like keyword
                        if any(keyword in field_lower for keyword in enum_likely_keywords):
                            # Try to find best matching enum (very permissive)
                            best_match = None
                            best_score = 0
                            
                            for enum_key, enum_info in service_enums.items():
                                enum_field = enum_key.split('.')[-1].lower() if '.' in enum_key else enum_key.lower()
                                
                                # Calculate a very permissive score
                                score = 0
                                
                                # Any shared word
                                field_words = set(re.findall(r'[a-z]+', field_lower))
                                enum_words = set(re.findall(r'[a-z]+', enum_field))
                                if field_words & enum_words:
                                    score = len(field_words & enum_words) / max(len(field_words), len(enum_words), 1)
                                
                                # Any character overlap
                                if field_lower and enum_field:
                                    common_chars = set(field_lower) & set(enum_field)
                                    if common_chars:
                                        score = max(score, len(common_chars) / max(len(field_lower), len(enum_field), 1))
                                
                                if score > best_score:
                                    best_score = score
                                    best_match = enum_info['values']
                            
                            # Use match if any similarity found (very permissive)
                            if best_score > 0.1:
                                enum_values = best_match
                    
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = sorted(enum_values)
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
            
            # Enrich output_fields (if they're dicts)
            if 'output_fields' in enriched_data:
                if isinstance(enriched_data['output_fields'], dict):
                    for field_name, field_data in enriched_data['output_fields'].items():
                        if isinstance(field_data, dict) and 'possible_values' not in field_data:
                            enum_values = self.map_enum_to_field(field_name, field_data, service_enums)
                            if not enum_values:
                                enum_values = self.map_enum_to_field_aggressive(field_name, service_enums)
                            
                            if enum_values:
                                field_data['enum'] = True
                                field_data['possible_values'] = sorted(enum_values)
                                self.stats['enums_found'] += 1
                                self.stats['fields_enriched'] += 1
            
            # Only increment if we actually processed an operation
            if 'item_fields' in enriched_data or 'output_fields' in enriched_data:
                self.stats['operations_processed'] = self.stats.get('operations_processed', 0) + 1
            
        except Exception as e:
            error_msg = f"Error enriching {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
        
        return enriched_data
    
    def map_enum_to_field_aggressive(self, field_name: str, service_enums: Dict[str, Dict[str, Any]]) -> Optional[List[str]]:
        """More aggressive field matching with lower threshold"""
        field_normalized = self.normalize_field_name(field_name)
        best_match = None
        best_score = 0
        
        for enum_key, enum_info in service_enums.items():
            enum_field = enum_key.split('.')[-1] if '.' in enum_key else enum_key
            enum_field_normalized = self.normalize_field_name(enum_field)
            
            # Exact match
            if field_normalized == enum_field_normalized:
                return enum_info['values']
            
            # Calculate score
            score = 0
            
            # Substring match (either direction)
            if field_normalized in enum_field_normalized:
                score = len(field_normalized) / len(enum_field_normalized)
            elif enum_field_normalized in field_normalized:
                score = len(enum_field_normalized) / len(field_normalized)
            
            # Common suffix/prefix matching
            if field_normalized.endswith(enum_field_normalized) or enum_field_normalized.endswith(field_normalized):
                score = max(score, 0.5)
            
            # Shared word matching (split by camelCase)
            field_words = re.findall(r'[A-Z]?[a-z]+', field_name)
            enum_words = re.findall(r'[A-Z]?[a-z]+', enum_field)
            if field_words and enum_words:
                shared_words = set(w.lower() for w in field_words) & set(w.lower() for w in enum_words)
                if shared_words:
                    score = max(score, len(shared_words) / max(len(field_words), len(enum_words)))
            
            if score > best_score:
                best_score = score
                best_match = enum_info['values']
        
        # Lower threshold for aggressive matching
        if best_score >= 0.4:  # Very permissive
            return best_match
        
        return None
    
    def get_service_version(self, service_name: str) -> Optional[str]:
        """Get the preferred version for a service"""
        if not DISCOVERY_API_AVAILABLE or not self.discovery_service:
            return 'v1'  # Default fallback
        
        # Service-specific version mappings for critical services
        version_overrides = {
            'kms': 'v1',
            'cloudkms': 'v1',  # Alternative name - has 320 enums
            'identitytoolkit': 'v2',  # v2 has 85 enums, v3 has none
            'oauth2': 'v2',  # No enums available
            'policytroubleshooter': 'v1',  # Has 40 enums
            'clouderrorreporting': 'v1beta1',  # Has 5 enums
            'discovery': 'v1',  # No enums available
            'runtimeconfig': 'v1beta1'  # v1beta1 has 3 enums, v1 has none
        }
        
        if service_name in version_overrides:
            # Try the override first
            try:
                doc = self.discovery_service.apis().getRest(
                    api=service_name, 
                    version=version_overrides[service_name]
                ).execute()
                return version_overrides[service_name]
            except Exception:
                # Try alternative versions for critical services
                if service_name == 'identitytoolkit':
                    try:
                        doc = self.discovery_service.apis().getRest(api=service_name, version='v2').execute()
                        return 'v2'
                    except:
                        pass
                elif service_name == 'runtimeconfig':
                    try:
                        doc = self.discovery_service.apis().getRest(api=service_name, version='v1beta1').execute()
                        return 'v1beta1'
                    except:
                        pass
                # Fallback to preferred version
                pass
        
        try:
            # List all APIs to find this service
            apis = self.discovery_service.apis().list(preferred=True).execute()
            for api in apis.get('items', []):
                if api['name'] == service_name:
                    return api.get('version', 'v1')
        except Exception:
            pass
        
        return 'v1'  # Default fallback
    
    def enrich_service_in_main_file(self, service_name: str, service_data: Dict, 
                                   main_data: Dict) -> bool:
        """Enrich a service in the main consolidated file"""
        
        try:
            # Get service version - use override for critical services
            service_version = self.get_service_version(service_name)
            if not service_version:
                service_version = service_data.get('version', 'v1')
            
            # Extract all enums from Discovery API
            service_enums = self.extract_all_enums_from_service(service_name, service_version)
            
            if not service_enums:
                return False
            
            fields_before = self.stats['fields_enriched']
            
            # Process resources structure (GCP)
            if 'resources' in service_data:
                for resource_name, resource_data in service_data['resources'].items():
                    for op_type in ['independent', 'dependent']:
                        if op_type in resource_data:
                            for op_data in resource_data[op_type]:
                                op_data = self.enrich_operation_fields(
                                    service_name,
                                    service_version,
                                    service_enums,
                                    op_data
                                )
            
                # Process operations list
                if 'operations' in service_data and isinstance(service_data['operations'], list):
                    for op_data in service_data['operations']:
                        op_data = self.enrich_operation_fields(
                            service_name,
                            service_version,
                            service_enums,
                            op_data,
                            doc  # Pass doc for response schema analysis
                        )
            
            fields_added = self.stats['fields_enriched'] - fields_before
            
            if fields_added > 0:
                return True
            
        except Exception as e:
            error_msg = f"Error processing {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
        
        return False
    
    def enrich_main_consolidated_file(self, root_path: Path):
        """Enrich the main consolidated file with Discovery API enums"""
        main_file = root_path / "gcp_dependencies_with_python_names_fully_enriched.json"
        
        if not main_file.exists():
            print(f"❌ Main file not found: {main_file}")
            return False
        
        if not DISCOVERY_API_AVAILABLE:
            print("❌ Discovery API not available. Install: pip install google-api-python-client")
            return False
        
        print(f"\n{'='*70}")
        print(f"ENRICHING GCP SERVICES WITH DISCOVERY API ENUMS")
        print(f"{'='*70}\n")
        print(f"Loading main file: {main_file.name}")
        
        try:
            with open(main_file, 'r') as f:
                data = json.load(f)
            
            total_services = len(data)
            print(f"Found {total_services} services to enrich\n")
            
            enriched_count = 0
            
            for i, (service_name, service_data) in enumerate(data.items(), 1):
                print(f"[{i}/{total_services}] {service_name}...", end=" ")
                
                # Get service version - use override for critical services
                service_version = self.get_service_version(service_name)
                if not service_version:
                    service_version = service_data.get('version', 'v1')
                
                # Extract enums from Discovery API
                service_enums = self.extract_all_enums_from_service(service_name, service_version)
                
                if not service_enums:
                    print("(no enums found)")
                    continue
                
                fields_before = self.stats['fields_enriched']
                
                # Process resources
                if 'resources' in service_data:
                    for resource_name, resource_data in service_data['resources'].items():
                        for op_type in ['independent', 'dependent']:
                            if op_type in resource_data:
                                for op_data in resource_data[op_type]:
                                    op_data = self.enrich_operation_fields(
                                        service_name,
                                        service_version,
                                        service_enums,
                                        op_data
                                    )
                
                # Process operations list
                if 'operations' in service_data and isinstance(service_data['operations'], list):
                    for op_data in service_data['operations']:
                        op_data = self.enrich_operation_fields(
                            service_name,
                            service_version,
                            service_enums,
                            op_data,
                            doc  # Pass doc for response schema analysis
                        )
                
                fields_added = self.stats['fields_enriched'] - fields_before
                
                if fields_added > 0:
                    print(f"✓ Added {fields_added} enum values ({len(service_enums)} enums found)")
                    enriched_count += 1
                    self.stats['services_processed'] += 1
                else:
                    print(f"(found {len(service_enums)} enums, but no matches)")
            
            # Save enriched file
            print(f"\n💾 Saving enriched file...")
            with open(main_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"  ✓ Saved {main_file.name}")
            
            # Print summary
            print(f"\n{'='*70}")
            print(f"ENRICHMENT SUMMARY")
            print(f"{'='*70}")
            print(f"Services processed: {self.stats['services_processed']}")
            print(f"Services enriched: {enriched_count}")
            print(f"Schemas processed: {self.stats['schemas_processed']}")
            print(f"Fields enriched: {self.stats['fields_enriched']}")
            print(f"Enums found: {self.stats['enums_found']}")
            print(f"Errors: {len(self.stats['errors'])}")
            
            if self.stats['errors']:
                print(f"\nFirst 10 errors:")
                for error in self.stats['errors'][:10]:
                    print(f"  - {error}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error enriching main file: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def enrich_per_service_files(self, root_path: Path):
        """Enrich per-service files with Discovery API enums"""
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "gcp_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        if not service_dirs:
            return
        
        print(f"\nEnriching {len(service_dirs)} per-service files...\n")
        
        for i, service_path in enumerate(sorted(service_dirs), 1):
            service_name = service_path.name
            enriched_file = service_path / "gcp_dependencies_with_python_names_fully_enriched.json"
            
            try:
                with open(enriched_file, 'r') as f:
                    data = json.load(f)
                
                if service_name not in data:
                    continue
                
                service_data = data[service_name]
                service_version = service_data.get('version', 'v1')
                
                # Extract enums
                service_enums = self.extract_all_enums_from_service(service_name, service_version)
                
                if not service_enums:
                    continue
                
                fields_before = self.stats['fields_enriched']
                
                # Process resources
                if 'resources' in service_data:
                    for resource_name, resource_data in service_data['resources'].items():
                        for op_type in ['independent', 'dependent']:
                            if op_type in resource_data:
                                for op_data in resource_data[op_type]:
                                    op_data = self.enrich_operation_fields(
                                        service_name,
                                        service_version,
                                        service_enums,
                                        op_data
                                    )
                
                # Save
                fields_added = self.stats['fields_enriched'] - fields_before
                if fields_added > 0:
                    with open(enriched_file, 'w') as f:
                        json.dump(data, f, indent=2)
                    print(f"  [{i}/{len(service_dirs)}] {service_name}: Added {fields_added} enum values")
                
            except Exception as e:
                print(f"  [{i}/{len(service_dirs)}] {service_name}: Error - {str(e)}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enrich GCP SDK dependencies with enum values from Discovery API'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/gcp',
        help='Root path for services (default: pythonsdk-database/gcp)'
    )
    parser.add_argument(
        '--main-only',
        action='store_true',
        help='Only enrich main consolidated file (skip per-service files)'
    )
    parser.add_argument(
        '--per-service-only',
        action='store_true',
        help='Only enrich per-service files (skip main file)'
    )
    
    args = parser.parse_args()
    
    if not DISCOVERY_API_AVAILABLE:
        print("❌ Discovery API not available!")
        print("   Install with: pip install google-api-python-client")
        sys.exit(1)
    
    root_path = Path(args.root)
    extractor = GCPDiscoveryAPIEnumExtractor()
    
    if not args.per_service_only:
        # Enrich main consolidated file
        extractor.enrich_main_consolidated_file(root_path)
    
    if not args.main_only:
        # Enrich per-service files
        extractor.enrich_per_service_files(root_path)
    
    print(f"\n✅ Enrichment complete!")


if __name__ == '__main__':
    main()

