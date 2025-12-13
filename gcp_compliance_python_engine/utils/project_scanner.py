"""
GCP Project Scanner - Multi-project and multi-region discovery

Equivalent to AWS organizations_scanner.py
"""

import logging
from typing import List, Dict, Optional
from google.cloud import resourcemanager_v3
from google.api_core import exceptions

logger = logging.getLogger(__name__)


def list_organization_projects(credentials=None) -> List[Dict[str, str]]:
    """
    List all GCP projects in the organization.
    
    Returns:
        List of dicts with 'project_id', 'display_name', 'state' keys
    """
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        projects = []
        
        # List all projects
        for project in client.search_projects():
            if project.state == resourcemanager_v3.Project.State.ACTIVE:
                projects.append({
                    'project_id': project.project_id,
                    'display_name': project.display_name,
                    'state': 'ACTIVE',
                    'project_number': project.name.split('/')[-1]
                })
        
        logger.info(f"Found {len(projects)} active projects")
        return projects
        
    except exceptions.PermissionDenied:
        logger.warning("No permission to list projects - will scan current project only")
        return []
    except Exception as e:
        logger.error(f"Error listing projects: {e}")
        return []


def list_projects(credentials=None) -> List[Dict[str, str]]:
    """Legacy alias for list_organization_projects"""
    return list_organization_projects(credentials)


def get_current_project_id() -> Optional[str]:
    """Get the current/default GCP project ID"""
    import os
    
    # Try environment variable
    project_id = os.getenv('GCP_PROJECT') or os.getenv('GOOGLE_CLOUD_PROJECT')
    if project_id:
        return project_id
    
    # Try gcloud config
    try:
        import subprocess
        result = subprocess.run(
            ['gcloud', 'config', 'get-value', 'project'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    
    return None


def list_gcp_regions() -> List[str]:
    """
    List all GCP regions.
    
    Returns:
        List of region names
    """
    # GCP standard regions
    return [
        'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
        'europe-central2', 'europe-north1', 'europe-west1', 'europe-west2', 'europe-west3',
        'europe-west4', 'europe-west6', 'europe-west8', 'europe-west9',
        'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3',
        'asia-south1', 'asia-south2', 'asia-southeast1', 'asia-southeast2',
        'australia-southeast1', 'australia-southeast2',
        'northamerica-northeast1', 'northamerica-northeast2',
        'southamerica-east1', 'southamerica-west1'
    ]


def list_regions() -> List[str]:
    """Legacy alias for list_gcp_regions"""
    return list_gcp_regions()


def filter_projects_by_config(
    all_projects: List[Dict[str, str]], 
    include_projects: Optional[List[str]] = None,
    exclude_projects: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """Filter projects based on inclusion/exclusion lists"""
    filtered = all_projects
    
    if include_projects:
        include_set = set(include_projects)
        filtered = [p for p in filtered if p['project_id'] in include_set]
        logger.info(f"Included {len(filtered)} projects from inclusion list")
    
    if exclude_projects:
        exclude_set = set(exclude_projects)
        filtered = [p for p in filtered if p['project_id'] not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} projects after exclusions")
    
    return filtered


def filter_regions_by_config(
    all_regions: List[str],
    include_regions: Optional[List[str]] = None,
    exclude_regions: Optional[List[str]] = None
) -> List[str]:
    """Filter regions based on inclusion/exclusion lists"""
    filtered = all_regions
    
    if include_regions:
        include_set = set(include_regions)
        filtered = [r for r in filtered if r in include_set]
        logger.info(f"Included {len(filtered)} regions from inclusion list")
    
    if exclude_regions:
        exclude_set = set(exclude_regions)
        filtered = [r for r in filtered if r not in exclude_set]
        logger.info(f"Filtered to {len(filtered)} regions after exclusions")
    
    return filtered

