"""
OCI Compartment Scanner - Multi-compartment and multi-region discovery
Equivalent to AWS organizations_scanner.py
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def list_compartments(config) -> List[Dict[str, str]]:
    """List all OCI compartments"""
    try:
        from oci.identity import IdentityClient
        
        identity_client = IdentityClient(config)
        tenancy_id = config['tenancy']
        
        compartments = []
        for compartment in identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data:
            if compartment.lifecycle_state == 'ACTIVE':
                compartments.append({
                    'compartment_id': compartment.id,
                    'name': compartment.name,
                    'state': 'ACTIVE'
                })
        
        logger.info(f"Found {len(compartments)} active compartments")
        return compartments
    except Exception as e:
        logger.error(f"Error listing compartments: {e}")
        return []


def list_regions(config) -> List[str]:
    """List all OCI regions"""
    try:
        from oci.identity import IdentityClient
        
        identity_client = IdentityClient(config)
        regions = [r.name for r in identity_client.list_regions().data]
        
        logger.info(f"Found {len(regions)} regions")
        return sorted(regions)
    except Exception as e:
        logger.warning(f"Error listing regions: {e}")
        return ['us-ashburn-1', 'us-phoenix-1']


def filter_compartments_by_config(all_compartments, include=None, exclude=None):
    """Filter compartments"""
    filtered = all_compartments
    if include:
        filtered = [c for c in filtered if c['compartment_id'] in set(include)]
    if exclude:
        filtered = [c for c in filtered if c['compartment_id'] not in set(exclude)]
    return filtered


def filter_regions_by_config(all_regions, include=None, exclude=None):
    """Filter regions"""
    filtered = all_regions
    if include:
        filtered = [r for r in filtered if r in set(include)]
    if exclude:
        filtered = [r for r in filtered if r not in set(exclude)]
    return filtered
