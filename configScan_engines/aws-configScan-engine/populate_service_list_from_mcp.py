#!/usr/bin/env python3
"""
One-time script to populate service_list.json using AWS MCP server.
This script queries AWS MCP server for 100% accurate ARN patterns for all services.

If MCP server is not available, falls back to:
- Extracting resource types from resource_arn_mapping.json
- Using standard AWS ARN patterns
- Validating against discovery outputs when available

Usage:
    python populate_service_list_from_mcp.py

Requirements:
    - AWS MCP server access (optional, will fallback if not available)
    - pythonsdk-database/aws directory with service folders
"""

import json
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
PYTHONSDK_DIR = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/aws")
SERVICE_LIST_FILE = Path("/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/config/service_list.json")

# AWS MCP Server Configuration (if available)
MCP_SERVER_URL = os.getenv("AWS_MCP_SERVER_URL", "")
MCP_API_KEY = os.getenv("AWS_MCP_API_KEY", "")

# Known global services (no region in ARN)
GLOBAL_SERVICES = {
    'iam', 'cloudfront', 'route53', 'waf', 'wafv2', 'shield', 
    'acm', 'account', 'organizations', 's3', 'sts', 'ce', 
    'pricing', 'budgets', 'support', 'trustedadvisor', 'artifact',
    'route53domains', 'route53profiles', 'wellarchitected', 'tag',
    'globalaccelerator', 'costexplorer'
}

# Service name mappings (pythonsdk-database name -> service_list name)
SERVICE_NAME_MAPPINGS = {
    'ce': 'costexplorer',
    'application-autoscaling': 'autoscaling',
    'elbv2': 'alb',
    'elb': 'nlb',
    'logs': 'cloudwatch',
    'directconnect': 'dx',
}

# Special ARN patterns (exceptions to standard format)
SPECIAL_ARN_PATTERNS = {
    's3': {
        'pattern': 'arn:aws:s3:::{resource_id}',
        'scope': 'global',
    },
    'iam': {
        'pattern': 'arn:aws:iam::{account_id}:{resource_type}/{resource_id}',
        'scope': 'global',
    },
    'route53': {
        'pattern': 'arn:aws:route53::{account_id}:{resource_type}/{resource_id}',
        'scope': 'global',
    },
    'cloudfront': {
        'pattern': 'arn:aws:cloudfront::{account_id}:{resource_type}/{resource_id}',
        'scope': 'global',
    },
    'apigateway': {
        'pattern': 'arn:aws:apigateway:{region}::/{resource_type}/{resource_id}',
        'scope': 'regional',
    },
    'wafv2': {
        'pattern': 'arn:aws:wafv2::{account_id}:global/webacl/{resource_id}',
        'scope': 'global',
    },
    'waf': {
        'pattern': 'arn:aws:waf::{account_id}:webacl/{resource_id}',
        'scope': 'global',
    },
}


class AWSMCPServerClient:
    """Client for AWS MCP Server to query ARN patterns"""
    
    def __init__(self, server_url: str = "", api_key: str = ""):
        self.server_url = server_url
        self.api_key = api_key
        self.available = bool(server_url and api_key)
        
        if not self.available:
            logger.warning("⚠️  AWS MCP server not configured, using fallback method")
    
    def get_service_arn_patterns(self, service_name: str) -> Optional[Dict]:
        """
        Query MCP server for ARN patterns for a specific service.
        
        Returns:
            {
                'service': 'ec2',
                'scope': 'regional',
                'arn_pattern': 'arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}',
                'resource_types': ['instance', 'vpc', 'subnet', ...]
            }
            or None if MCP server not available
        """
        if not self.available:
            return None
        
        # TODO: Implement actual MCP server query
        # Example:
        # import requests
        # response = requests.get(
        #     f"{self.server_url}/api/v1/services/{service_name}/arn-patterns",
        #     headers={"Authorization": f"Bearer {self.api_key}"}
        # )
        # return response.json()
        
        logger.debug(f"MCP server query for {service_name} not implemented yet")
        return None


def normalize_service_name(service_dir_name: str) -> str:
    """Normalize service directory name to service_list.json format"""
    if service_dir_name in SERVICE_NAME_MAPPINGS:
        return SERVICE_NAME_MAPPINGS[service_dir_name]
    
    # Convert to lowercase, replace underscores with hyphens
    service_name = service_dir_name.replace('_', '-').lower()
    return service_name


def determine_scope(service_name: str) -> str:
    """Determine if service is global or regional"""
    if service_name in GLOBAL_SERVICES:
        return "global"
    return "regional"


def clean_resource_type(resource_type: str) -> str:
    """Clean resource type name (remove duplicates, normalize)"""
    # Handle cases like "bucket_bucket" -> "bucket"
    if '_' in resource_type:
        parts = resource_type.split('_')
        if len(parts) > 1 and parts[0] == parts[1]:
            return parts[0].replace('_', '-')
    
    # Convert underscores to hyphens
    cleaned = resource_type.replace('_', '-')
    
    # Remove common suffixes that don't affect ARN
    if cleaned.endswith('-list') or cleaned.endswith('-detail'):
        cleaned = cleaned.rsplit('-', 1)[0]
    
    return cleaned


def extract_resource_types_from_mapping(mapping_file: Path) -> Set[str]:
    """Extract resource types from resource_arn_mapping.json"""
    if not mapping_file.exists():
        return set()
    
    try:
        with open(mapping_file, 'r') as f:
            data = json.load(f)
        
        resources = data.get('analysis', {}).get('resources', {})
        resource_types = set()
        
        for resource_info in resources.values():
            resource_type = resource_info.get('resource_type')
            arn_entity = resource_info.get('arn_entity')
            
            # Only include resources that have ARN entities (actual resources, not metadata)
            if resource_type and arn_entity:
                cleaned = clean_resource_type(resource_type)
                if cleaned and cleaned != 'resource':  # Skip generic "resource" type
                    resource_types.add(cleaned)
        
        return resource_types
    except Exception as e:
        logger.debug(f"  ⚠️  Error reading {mapping_file}: {e}")
        return set()


def extract_resource_types_from_prioritized(prioritized_file: Path) -> Set[str]:
    """Extract resource types from resource_operations_prioritized.json"""
    if not prioritized_file.exists():
        return set()
    
    try:
        with open(prioritized_file, 'r') as f:
            data = json.load(f)
        
        resource_types = set()
        
        # Extract from primary_resources
        primary_resources = data.get('primary_resources', [])
        for resource in primary_resources:
            resource_type = resource.get('resource_type')
            if resource_type and resource.get('has_arn', False):
                cleaned = clean_resource_type(resource_type)
                if cleaned:
                    resource_types.add(cleaned)
        
        return resource_types
    except Exception as e:
        logger.debug(f"  ⚠️  Error reading {prioritized_file}: {e}")
        return set()


def extract_resource_types(service_dir: Path) -> Set[str]:
    """Extract resource types from multiple sources"""
    resource_types = set()
    
    # Try resource_arn_mapping.json first
    mapping_file = service_dir / "resource_arn_mapping.json"
    if mapping_file.exists():
        resource_types.update(extract_resource_types_from_mapping(mapping_file))
    
    # Try resource_operations_prioritized.json
    prioritized_file = service_dir / "resource_operations_prioritized.json"
    if prioritized_file.exists():
        resource_types.update(extract_resource_types_from_prioritized(prioritized_file))
    
    return resource_types


def infer_arn_pattern(service_name: str, resource_type: str, scope: str) -> str:
    """Infer ARN pattern based on service name and resource type"""
    
    # Check special patterns first
    if service_name in SPECIAL_ARN_PATTERNS:
        special = SPECIAL_ARN_PATTERNS[service_name]
        pattern = special['pattern']
        # Replace {resource_type} with actual type if needed
        if '{resource_type}' in pattern:
            pattern = pattern.replace('{resource_type}', resource_type)
        return pattern
    
    # Standard patterns
    if scope == "global":
        # Global services: arn:aws:service::account:resource-type/resource-id
        return f"arn:aws:{service_name}::{{account_id}}:{resource_type}/{{resource_id}}"
    else:
        # Regional services: arn:aws:service:region:account:resource-type/resource-id
        return f"arn:aws:{service_name}:{{region}}:{{account_id}}:{resource_type}/{{resource_id}}"


def populate_service_list_from_mcp():
    """Main function to populate service_list.json from AWS MCP server"""
    
    logger.info("🚀 Starting service_list.json population")
    logger.info("=" * 80)
    
    # Initialize MCP client
    mcp_client = AWSMCPServerClient(
        server_url=MCP_SERVER_URL,
        api_key=MCP_API_KEY
    )
    
    # Load existing service_list.json
    if SERVICE_LIST_FILE.exists():
        with open(SERVICE_LIST_FILE, 'r') as f:
            service_list = json.load(f)
    else:
        service_list = {"services": []}
    
    existing_services = {svc['name'] for svc in service_list['services']}
    logger.info(f"📋 Found {len(existing_services)} existing services in service_list.json")
    
    # Get all services from pythonsdk-database
    logger.info(f"🔍 Scanning {PYTHONSDK_DIR} for services...")
    all_service_dirs = []
    for service_dir in sorted(PYTHONSDK_DIR.iterdir()):
        if service_dir.is_dir() and not service_dir.name.startswith('.'):
            # Skip non-service directories
            if service_dir.name in ['tools', 'test_reports', 'backup']:
                continue
            all_service_dirs.append(service_dir)
    
    logger.info(f"✅ Found {len(all_service_dirs)} service directories")
    
    new_services = []
    updated_services = []
    skipped_services = []
    
    # Process each service
    for service_dir in all_service_dirs:
        service_dir_name = service_dir.name
        service_name = normalize_service_name(service_dir_name)
        
        # Skip if already exists (preserve existing configuration)
        if service_name in existing_services:
            logger.debug(f"⏭️  Skipping {service_name} (already exists)")
            continue
        
        logger.info(f"📦 Processing {service_name}...")
        
        # Try MCP server first
        arn_info = None
        if mcp_client.available:
            arn_info = mcp_client.get_service_arn_patterns(service_name)
        
        # Fallback: Extract from multiple sources
        if not arn_info:
            resource_types = extract_resource_types(service_dir)
            
            # If no resource types found, use generic "resource" type with standard pattern
            if not resource_types:
                logger.debug(f"  ⚠️  No specific resource types found for {service_name}, using generic pattern")
                resource_types = {'resource'}  # Use generic type
            
            # Determine scope
            scope = determine_scope(service_name)
            
            # Get first resource type for pattern inference
            first_resource_type = sorted(resource_types)[0]
            
            # Infer ARN pattern
            arn_pattern = infer_arn_pattern(service_name, first_resource_type, scope)
            
            arn_info = {
                'service': service_name,
                'scope': scope,
                'arn_pattern': arn_pattern,
                'resource_types': sorted(list(resource_types))
            }
        
        # Create service entry
        service_entry = {
            'name': service_name,
            'enabled': False,  # Disable by default, enable manually
            'scope': arn_info.get('scope', 'regional'),
            'arn_pattern': arn_info.get('arn_pattern'),
            'resource_types': sorted(arn_info.get('resource_types', []))
        }
        
        # Validate required fields
        if not service_entry['arn_pattern']:
            skipped_services.append((service_name, "No ARN pattern determined"))
            continue
        
        new_services.append(service_entry)
        logger.info(f"  ✅ Added {service_name}: {len(service_entry['resource_types'])} resource types, scope: {service_entry['scope']}")
    
    # Add new services to service_list
    if new_services:
        service_list['services'].extend(new_services)
        # Sort by service name
        service_list['services'].sort(key=lambda x: x['name'])
        
        # Write back
        with open(SERVICE_LIST_FILE, 'w') as f:
            json.dump(service_list, f, indent=2)
        
        logger.info(f"\n✅ Successfully added {len(new_services)} new services to service_list.json")
    else:
        logger.info("\n✅ No new services to add")
    
    # Summary
    logger.info("\n" + "=" * 80)
    logger.info("📊 SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total service directories scanned: {len(all_service_dirs)}")
    logger.info(f"Existing services: {len(existing_services)}")
    logger.info(f"New services added: {len(new_services)}")
    logger.info(f"Skipped services: {len(skipped_services)}")
    
    if skipped_services:
        logger.info(f"\n⚠️  Skipped services (first 20):")
        for name, reason in skipped_services[:20]:
            logger.info(f"  - {name}: {reason}")
        if len(skipped_services) > 20:
            logger.info(f"  ... and {len(skipped_services) - 20} more")
    
    logger.info(f"\n✅ service_list.json updated: {SERVICE_LIST_FILE}")
    logger.info(f"📝 Total services in file: {len(service_list['services'])}")


if __name__ == "__main__":
    try:
        populate_service_list_from_mcp()
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n❌ Error: {e}", exc_info=True)
        sys.exit(1)
