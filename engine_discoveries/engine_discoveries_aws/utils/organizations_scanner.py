import boto3
import logging
from typing import List, Dict, Optional, Set
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def list_organization_accounts(session: boto3.session.Session) -> List[Dict[str, str]]:
    """
    List all AWS accounts in the organization.
    
    Returns:
        List of dicts with 'Id', 'Name', 'Email', 'Status' keys
    """
    try:
        org_client = session.client('organizations', region_name='us-east-1')
        accounts = []
        
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                if account.get('Status') == 'ACTIVE':
                    accounts.append({
                        'Id': account.get('Id'),
                        'Name': account.get('Name'),
                        'Email': account.get('Email'),
                        'Status': account.get('Status')
                    })
        
        logger.info(f"Found {len(accounts)} active accounts in organization")
        return accounts
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'AccessDeniedException':
            logger.warning("No access to AWS Organizations - will scan current account only")
            return []
        elif error_code == 'AWSOrganizationsNotInUseException':
            logger.info("AWS Organizations not enabled - will scan current account only")
            return []
        else:
            logger.error(f"Error listing organization accounts: {e}")
            return []
    except Exception as e:
        logger.error(f"Unexpected error listing organization accounts: {e}")
        return []


def get_current_account_id(session: boto3.session.Session) -> Optional[str]:
    """Get the current AWS account ID"""
    try:
        sts_client = session.client('sts')
        return sts_client.get_caller_identity().get('Account')
    except Exception as e:
        logger.error(f"Failed to get current account ID: {e}")
        return None


def list_enabled_regions(session: boto3.session.Session) -> List[str]:
    """
    List all enabled AWS regions.
    
    Returns:
        List of region names (e.g., ['us-east-1', 'us-west-2', ...])
    """
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        response = ec2_client.describe_regions(AllRegions=True)
        
        enabled_regions = [
            region['RegionName'] 
            for region in response.get('Regions', [])
            if region.get('OptInStatus') in (None, 'opt-in-not-required', 'opted-in')
        ]
        
        logger.info(f"Found {len(enabled_regions)} enabled regions")
        return sorted(enabled_regions)
        
    except Exception as e:
        logger.warning(f"Error listing regions, using default: {e}")
        return ['us-east-1', 'us-west-2', 'eu-west-1']


def filter_accounts_by_config(
    all_accounts: List[Dict[str, str]], 
    include_accounts: Optional[List[str]] = None,
    exclude_accounts: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """
    Filter accounts based on inclusion/exclusion lists.
    
    Args:
        all_accounts: List of all accounts
        include_accounts: If provided, only include these account IDs
        exclude_accounts: If provided, exclude these account IDs
        
    Returns:
        Filtered list of accounts
    """
    filtered = all_accounts
    
    # Apply inclusion filter
    if include_accounts:
        include_set = set(include_accounts)
        filtered = [acc for acc in filtered if acc['Id'] in include_set]
        logger.info(f"Included {len(filtered)} accounts from inclusion list")
    
    # Apply exclusion filter
    if exclude_accounts:
        exclude_set = set(exclude_accounts)
        filtered = [acc for acc in filtered if acc['Id'] not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} accounts after exclusions")
    
    return filtered


def filter_regions_by_config(
    all_regions: List[str],
    include_regions: Optional[List[str]] = None,
    exclude_regions: Optional[List[str]] = None
) -> List[str]:
    """
    Filter regions based on inclusion/exclusion lists.
    
    Args:
        all_regions: List of all regions
        include_regions: If provided, only include these regions
        exclude_regions: If provided, exclude these regions
        
    Returns:
        Filtered list of regions
    """
    filtered = all_regions
    
    # Apply inclusion filter
    if include_regions:
        include_set = set(include_regions)
        filtered = [reg for reg in filtered if reg in include_set]
        logger.info(f"Included {len(filtered)} regions from inclusion list")
    
    # Apply exclusion filter
    if exclude_regions:
        exclude_set = set(exclude_regions)
        filtered = [reg for reg in filtered if reg not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} regions after exclusions")
    
    return filtered
