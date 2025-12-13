"""
Azure Subscription Scanner - Multi-subscription and multi-location discovery

Equivalent to AWS organizations_scanner.py
"""

import logging
from typing import List, Dict, Optional
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource.subscriptions import SubscriptionClient as SubClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

logger = logging.getLogger(__name__)


def list_subscriptions(credential: DefaultAzureCredential) -> List[Dict[str, str]]:
    """
    List all Azure subscriptions accessible by the credential.
    
    Returns:
        List of dicts with 'subscription_id', 'display_name', 'state' keys
    """
    try:
        subscription_client = SubClient(credential)
        subscriptions = []
        
        for sub in subscription_client.subscriptions.list():
            state_value = sub.state.value if hasattr(sub.state, 'value') else str(sub.state)
            if state_value == 'Enabled' or sub.state == 'Enabled':
                subscriptions.append({
                    'subscription_id': sub.subscription_id,
                    'display_name': sub.display_name,
                    'state': state_value,
                    'tenant_id': sub.tenant_id or 'unknown'
                })
        
        logger.info(f"Found {len(subscriptions)} enabled subscriptions")
        return subscriptions
        
    except ClientAuthenticationError as e:
        logger.warning("Authentication failed - will scan current subscription only")
        return []
    except HttpResponseError as e:
        logger.error(f"Error listing subscriptions: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing subscriptions: {e}")
        return []


def get_current_subscription_id(credential: DefaultAzureCredential) -> Optional[str]:
    """Get the default/current Azure subscription ID from environment or config"""
    import os
    
    # Try environment variable first
    sub_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    if sub_id:
        return sub_id
    
    # Try listing subscriptions and get first one
    try:
        subs = list_subscriptions(credential)
        if subs:
            return subs[0]['subscription_id']
    except Exception as e:
        logger.error(f"Failed to get current subscription ID: {e}")
    
    return None


def list_locations(credential: DefaultAzureCredential, subscription_id: str) -> List[str]:
    """
    List all Azure locations/regions for a subscription.
    
    Returns:
        List of location names (e.g., ['eastus', 'westus2', 'westeurope', ...])
    """
    try:
        subscription_client = SubClient(credential)
        locations = []
        
        for location in subscription_client.subscriptions.list_locations(subscription_id):
            # Only include locations that are available (not deprecated/unavailable)
            if location.name and location.metadata and location.metadata.region_type == 'Physical':
                locations.append(location.name)
        
        logger.info(f"Found {len(locations)} physical locations")
        return sorted(locations)
        
    except Exception as e:
        logger.warning(f"Error listing locations, using defaults: {e}")
        # Default common Azure locations
        return ['eastus', 'westus2', 'westeurope', 'eastasia', 'australiaeast']


def filter_subscriptions_by_config(
    all_subscriptions: List[Dict[str, str]], 
    include_subscriptions: Optional[List[str]] = None,
    exclude_subscriptions: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """
    Filter subscriptions based on inclusion/exclusion lists.
    
    Args:
        all_subscriptions: List of all subscriptions
        include_subscriptions: If provided, only include these subscription IDs
        exclude_subscriptions: If provided, exclude these subscription IDs
        
    Returns:
        Filtered list of subscriptions
    """
    filtered = all_subscriptions
    
    # Apply inclusion filter
    if include_subscriptions:
        include_set = set(include_subscriptions)
        filtered = [sub for sub in filtered if sub['subscription_id'] in include_set]
        logger.info(f"Included {len(filtered)} subscriptions from inclusion list")
    
    # Apply exclusion filter
    if exclude_subscriptions:
        exclude_set = set(exclude_subscriptions)
        filtered = [sub for sub in filtered if sub['subscription_id'] not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} subscriptions after exclusions")
    
    return filtered


def filter_locations_by_config(
    all_locations: List[str],
    include_locations: Optional[List[str]] = None,
    exclude_locations: Optional[List[str]] = None
) -> List[str]:
    """
    Filter Azure locations based on inclusion/exclusion lists.
    
    Args:
        all_locations: List of all locations
        include_locations: If provided, only include these locations
        exclude_locations: If provided, exclude these locations
        
    Returns:
        Filtered list of locations
    """
    filtered = all_locations
    
    # Apply inclusion filter
    if include_locations:
        include_set = set(include_locations)
        filtered = [loc for loc in filtered if loc in include_set]
        logger.info(f"Included {len(filtered)} locations from inclusion list")
    
    # Apply exclusion filter
    if exclude_locations:
        exclude_set = set(exclude_locations)
        filtered = [loc for loc in filtered if loc not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} locations after exclusions")
    
    return filtered
