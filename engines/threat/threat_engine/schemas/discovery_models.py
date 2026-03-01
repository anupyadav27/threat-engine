"""
Pydantic models for ConfigScan Discovery Results API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class ServiceDiscoveryStats(BaseModel):
    """Statistics for a single service"""
    service: str = Field(..., description="Service name (e.g., s3, iam, ec2)")
    total_discoveries: int = Field(..., description="Total discovery records")
    unique_resources: int = Field(..., description="Unique resources discovered")
    regions: List[str] = Field(default_factory=list, description="Regions with discoveries")
    discovery_functions: List[str] = Field(default_factory=list, description="Discovery functions executed")
    
    class Config:
        json_schema_extra = {
            "example": {
                "service": "s3",
                "total_discoveries": 96,
                "unique_resources": 96,
                "regions": ["global"],
                "discovery_functions": ["aws.s3.list_buckets", "aws.s3.get_bucket_versioning"]
            }
        }


class DiscoveryScanSummary(BaseModel):
    """Summary of a discovery scan"""
    scan_id: str = Field(..., description="Discovery scan identifier")
    customer_id: str
    tenant_id: str
    provider: str = Field(default="aws", description="Cloud provider")
    hierarchy_id: str = Field(..., description="Account/Project/Org ID")
    hierarchy_type: str = Field(default="account", description="Hierarchy type")
    total_discoveries: int = Field(..., description="Total discovery records")
    unique_resources: int = Field(..., description="Unique resources discovered")
    services_scanned: int = Field(..., description="Number of services scanned")
    regions_scanned: int = Field(..., description="Number of regions scanned")
    scan_timestamp: datetime = Field(..., description="Scan execution time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "discovery_20260122_080533",
                "customer_id": "test_customer",
                "tenant_id": "test_tenant",
                "provider": "aws",
                "hierarchy_id": "039612851381",
                "total_discoveries": 50000,
                "unique_resources": 12000,
                "services_scanned": 100,
                "regions_scanned": 27,
                "scan_timestamp": "2026-01-22T08:05:33Z"
            }
        }


class DiscoveryDetail(BaseModel):
    """Detailed discovery record"""
    id: Optional[int] = Field(None, description="Database ID (if from database)")
    scan_id: str = Field(..., description="Discovery scan identifier")
    customer_id: str
    tenant_id: str
    provider: str
    hierarchy_id: str
    hierarchy_type: str
    discovery_id: str = Field(..., description="Discovery function ID (e.g., aws.s3.list_buckets)")
    region: Optional[str] = Field(None, description="AWS region (or 'global')")
    service: str = Field(..., description="Service name (e.g., s3, iam)")
    resource_arn: Optional[str] = Field(None, description="Resource ARN")
    resource_id: Optional[str] = Field(None, description="Resource ID")
    raw_response: Dict[str, Any] = Field(default_factory=dict, description="Full API response")
    emitted_fields: Dict[str, Any] = Field(default_factory=dict, description="Extracted/emitted fields")
    config_hash: Optional[str] = Field(None, description="Configuration hash for drift detection")
    scan_timestamp: datetime = Field(..., description="When discovery was executed")
    version: int = Field(default=1, description="Schema version")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "discovery_20260122_080533",
                "discovery_id": "aws.s3.get_bucket_versioning",
                "resource_arn": "arn:aws:s3:::my-bucket",
                "resource_id": "my-bucket",
                "service": "s3",
                "region": "global",
                "emitted_fields": {
                    "Status": "Enabled",
                    "MfaDelete": "Disabled"
                }
            }
        }


class DiscoveryList(BaseModel):
    """Paginated list of discoveries"""
    discoveries: List[DiscoveryDetail] = Field(default_factory=list)
    total: int = Field(..., description="Total number of discoveries (before pagination)")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=50, description="Results per page")
    total_pages: int = Field(..., description="Total number of pages")
    
    class Config:
        json_schema_extra = {
            "example": {
                "discoveries": [],
                "total": 50000,
                "page": 1,
                "page_size": 50,
                "total_pages": 1000
            }
        }


class DiscoveryDashboard(BaseModel):
    """Dashboard statistics for discovery scans"""
    total_discoveries: int = Field(..., description="Total discoveries across all scans")
    unique_resources: int = Field(..., description="Unique resources discovered")
    services_scanned: int = Field(..., description="Unique services with discoveries")
    accounts_scanned: int = Field(default=1, description="Number of accounts scanned")
    top_services: List[ServiceDiscoveryStats] = Field(
        default_factory=list,
        description="Services with most discoveries"
    )
    recent_scans: List[DiscoveryScanSummary] = Field(
        default_factory=list,
        description="Recent discovery scans"
    )
    last_scan_timestamp: Optional[datetime] = Field(None, description="Most recent scan time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_discoveries": 50000,
                "unique_resources": 12000,
                "services_scanned": 100,
                "top_services": [],
                "recent_scans": []
            }
        }


class ServiceDiscoveryDetail(BaseModel):
    """Detailed statistics for a specific service in a scan"""
    service: str
    scan_id: str
    total_discoveries: int
    unique_resources: int
    regions: List[str]
    discovery_functions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of discovery functions with their statistics"
    )
    top_resources: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Resources with most discovery data"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "service": "s3",
                "scan_id": "discovery_20260122_080533",
                "total_discoveries": 96,
                "unique_resources": 96,
                "regions": ["global"],
                "discovery_functions": []
            }
        }


class ResourceDiscoveries(BaseModel):
    """All discoveries for a specific resource"""
    resource_arn: str
    resource_id: Optional[str]
    resource_type: str
    total_discoveries: int
    discovery_functions: List[str] = Field(default_factory=list, description="Discovery functions that found this resource")
    discoveries: List[DiscoveryDetail]
    
    class Config:
        json_schema_extra = {
            "example": {
                "resource_arn": "arn:aws:s3:::my-bucket",
                "resource_id": "my-bucket",
                "resource_type": "s3",
                "total_discoveries": 22,
                "discovery_functions": ["aws.s3.list_buckets", "aws.s3.get_bucket_versioning"],
                "discoveries": []
            }
        }


class DiscoveryFunctionDetail(BaseModel):
    """All discoveries for a specific discovery function"""
    discovery_id: str
    total_discoveries: int
    service: str
    resources_discovered: List[str] = Field(
        default_factory=list,
        description="List of resource ARNs discovered by this function"
    )
    discoveries: List[DiscoveryDetail]
    
    class Config:
        json_schema_extra = {
            "example": {
                "discovery_id": "aws.s3.list_buckets",
                "total_discoveries": 96,
                "service": "s3",
                "resources_discovered": [],
                "discoveries": []
            }
        }


class DiscoveryScanListItem(BaseModel):
    """Summary item for scan list"""
    scan_id: str
    customer_id: str
    tenant_id: str
    provider: str
    hierarchy_id: str
    total_discoveries: int
    unique_resources: int
    services_scanned: int
    regions_scanned: int
    scan_timestamp: datetime


class DiscoveryScanList(BaseModel):
    """Paginated list of scans"""
    scans: List[DiscoveryScanListItem]
    total: int
    page: int
    page_size: int
    total_pages: int
