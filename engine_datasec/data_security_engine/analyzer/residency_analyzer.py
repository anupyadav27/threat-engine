"""
Data Residency Analyzer - Tracks geographic location and enforces residency policies.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RegionCompliance(Enum):
    """Region compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass
class ResidencyCheck:
    """Result of residency policy check."""
    resource_id: str
    resource_arn: str
    primary_region: str
    replication_regions: List[str]
    policy_name: Optional[str]
    compliance_status: RegionCompliance
    violations: List[str]


class ResidencyPolicy:
    """Defines a data residency policy."""
    
    def __init__(self, name: str, allowed_regions: List[str], description: str = ""):
        self.name = name
        self.allowed_regions = set(region.lower() for region in allowed_regions)
        self.description = description
    
    def check_compliance(self, regions: List[str]) -> Tuple[bool, List[str]]:
        """
        Check if regions comply with policy.
        
        Args:
            regions: List of regions where data is stored/replicated
            
        Returns:
            Tuple of (is_compliant, violations)
        """
        violations = []
        regions_set = set(region.lower() for region in regions)
        
        # Check if any region is outside allowed regions
        disallowed = regions_set - self.allowed_regions
        if disallowed:
            violations.append(f"Data stored in disallowed regions: {', '.join(disallowed)}")
        
        return len(violations) == 0, violations


class ResidencyAnalyzer:
    """Analyzes data residency and policy compliance."""
    
    def __init__(self, policies: Optional[List[ResidencyPolicy]] = None):
        """
        Initialize residency analyzer.
        
        Args:
            policies: List of residency policies to enforce
        """
        self.policies = policies or []
    
    def get_resource_regions(self, asset: Dict) -> Tuple[str, List[str]]:
        """
        Extract primary and replication regions from asset.
        
        Args:
            asset: Asset from inventory
            
        Returns:
            Tuple of (primary_region, replication_regions)
        """
        primary_region = asset.get("region", "")
        replication_regions = []
        
        # Check metadata for replication information
        metadata = asset.get("metadata", {})
        
        # For S3, check for replication configuration
        if "s3" in asset.get("service", "").lower():
            # Would parse replication config from metadata
            pass
        
        return primary_region, replication_regions
    
    def check_residency(self, asset: Dict, policy: Optional[ResidencyPolicy] = None) -> ResidencyCheck:
        """
        Check residency compliance for an asset.
        
        Args:
            asset: Asset from inventory
            policy: Optional specific policy (uses first policy if not specified)
            
        Returns:
            ResidencyCheck result
        """
        resource_id = asset.get("resource_id", "")
        resource_arn = asset.get("resource_arn", asset.get("resource_uid", ""))
        
        primary_region, replication_regions = self.get_resource_regions(asset)
        all_regions = [primary_region] + replication_regions
        all_regions = [r for r in all_regions if r]  # Filter empty
        
        # Use provided policy or first default policy
        check_policy = policy or (self.policies[0] if self.policies else None)
        
        if check_policy:
            is_compliant, violations = check_policy.check_compliance(all_regions)
            compliance_status = RegionCompliance.COMPLIANT if is_compliant else RegionCompliance.NON_COMPLIANT
            policy_name = check_policy.name
        else:
            violations = []
            compliance_status = RegionCompliance.UNKNOWN
            policy_name = None
        
        return ResidencyCheck(
            resource_id=resource_id,
            resource_arn=resource_arn,
            primary_region=primary_region,
            replication_regions=replication_regions,
            policy_name=policy_name,
            compliance_status=compliance_status,
            violations=violations
        )
    
    def check_all_resources(self, data_stores: List[Dict]) -> List[ResidencyCheck]:
        """
        Check residency for all data stores.
        
        Args:
            data_stores: List of data store assets
            
        Returns:
            List of ResidencyCheck results
        """
        results = []
        
        for store in data_stores:
            check = self.check_residency(store)
            results.append(check)
        
        return results


# Convenience functions
def check_residency(asset: Dict, allowed_regions: List[str], policy_name: str = "default") -> ResidencyCheck:
    """Check residency for a single asset."""
    policy = ResidencyPolicy(policy_name, allowed_regions)
    analyzer = ResidencyAnalyzer([policy])
    return analyzer.check_residency(asset, policy)

