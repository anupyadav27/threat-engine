"""
Standardized storage path resolution for CSPM engines

Provides consistent path resolution for both S3 and local storage
across all engines (ConfigScan, Threat, Compliance, DataSec, Inventory).
"""
import os
from typing import Optional
from enum import Enum


class StorageType(str, Enum):
    """Storage type enumeration"""
    S3 = "s3"
    LOCAL = "local"


class StoragePathResolver:
    """Resolves storage paths for scan results"""
    
    def __init__(
        self,
        storage_type: Optional[str] = None,
        s3_bucket: Optional[str] = None,
        local_base_path: Optional[str] = None
    ):
        """
        Initialize path resolver
        
        Args:
            storage_type: "s3" or "local" (defaults to env var STORAGE_TYPE or "local")
            s3_bucket: S3 bucket name (defaults to env var S3_BUCKET or "cspm-lgtech")
            local_base_path: Local base path (defaults to env var WORKSPACE_ROOT/engines-output)
        """
        self.storage_type = storage_type or os.getenv("STORAGE_TYPE", "local").lower()
        self.s3_bucket = s3_bucket or os.getenv("S3_BUCKET", "cspm-lgtech")
        
        if local_base_path:
            self.local_base_path = local_base_path
        else:
            workspace_root = os.getenv("WORKSPACE_ROOT", "/Users/apple/Desktop/threat-engine")
            self.local_base_path = os.path.join(workspace_root, "engines-output")
    
    def get_scan_results_path(
        self,
        csp: str,
        scan_run_id: str,
        filename: str = "results.ndjson"
    ) -> str:
        """
        Get path to scan results file
        
        Args:
            csp: Cloud service provider (aws, azure, gcp, alicloud, oci, ibm)
            scan_run_id: Unified scan identifier
            filename: Filename (default: results.ndjson)
        
        Returns:
            Full path (S3 key or local file path)
        """
        # Standardized path format: {csp}-configScan-engine/output/{scan_run_id}/{filename}
        relative_path = f"{csp}-configScan-engine/output/{scan_run_id}/{filename}"
        
        if self.storage_type == StorageType.S3:
            return f"s3://{self.s3_bucket}/{relative_path}"
        else:
            return os.path.join(self.local_base_path, relative_path)
    
    def get_inventory_path(
        self,
        csp: str,
        scan_run_id: str,
        account_id: Optional[str] = None,
        region: Optional[str] = None
    ) -> str:
        """
        Get path to inventory file
        
        Args:
            csp: Cloud service provider
            scan_run_id: Unified scan identifier
            account_id: Account ID (optional, for filtering)
            region: Region (optional, for filtering)
        
        Returns:
            Full path to inventory file
        """
        if account_id and region:
            filename = f"inventory_{account_id}_{region}.ndjson"
        elif account_id:
            filename = f"inventory_{account_id}.ndjson"
        else:
            filename = "inventory.ndjson"
        
        return self.get_scan_results_path(csp, scan_run_id, filename)
    
    def get_summary_path(
        self,
        csp: str,
        scan_run_id: str
    ) -> str:
        """
        Get path to summary file
        
        Args:
            csp: Cloud service provider
            scan_run_id: Unified scan identifier
        
        Returns:
            Full path to summary.json
        """
        return self.get_scan_results_path(csp, scan_run_id, "summary.json")
    
    def get_scan_directory(
        self,
        csp: str,
        scan_run_id: str
    ) -> str:
        """
        Get directory path for scan results
        
        Args:
            csp: Cloud service provider
            scan_run_id: Unified scan identifier
        
        Returns:
            Directory path (without trailing slash for S3, with for local)
        """
        relative_path = f"{csp}-configScan-engine/output/{scan_run_id}"
        
        if self.storage_type == StorageType.S3:
            return f"s3://{self.s3_bucket}/{relative_path}"
        else:
            return os.path.join(self.local_base_path, relative_path)
    
    def is_s3_path(self, path: str) -> bool:
        """Check if path is an S3 path"""
        return path.startswith("s3://")
    
    def is_local_path(self, path: str) -> bool:
        """Check if path is a local path"""
        return not self.is_s3_path(path)


# Global instance for convenience
_default_resolver = None


def get_path_resolver() -> StoragePathResolver:
    """Get default path resolver instance"""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = StoragePathResolver()
    return _default_resolver


def get_scan_results_path(
    csp: str,
    scan_run_id: str,
    filename: str = "results.ndjson"
) -> str:
    """Convenience function to get scan results path"""
    return get_path_resolver().get_scan_results_path(csp, scan_run_id, filename)


def get_inventory_path(
    csp: str,
    scan_run_id: str,
    account_id: Optional[str] = None,
    region: Optional[str] = None
) -> str:
    """Convenience function to get inventory path"""
    return get_path_resolver().get_inventory_path(csp, scan_run_id, account_id, region)


def get_summary_path(csp: str, scan_run_id: str) -> str:
    """Convenience function to get summary path"""
    return get_path_resolver().get_summary_path(csp, scan_run_id)


def get_scan_directory(csp: str, scan_run_id: str) -> str:
    """Convenience function to get scan directory"""
    return get_path_resolver().get_scan_directory(csp, scan_run_id)
