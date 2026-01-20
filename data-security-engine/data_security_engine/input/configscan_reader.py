"""
Read findings and inventory from configScan engine output.

ConfigScan output location:
engines-output/{csp}-configScan-engine/output/{scan_id}/
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator, Set
import logging

logger = logging.getLogger(__name__)


class ConfigScanReader:
    """Reads findings and inventory from configScan engine output."""
    
    def __init__(self, engines_output_path: Optional[str] = None):
        """
        Initialize configScan reader.
        
        Args:
            engines_output_path: Path to engines-output directory.
                               Default: ../engines-output relative to project root
        """
        if engines_output_path is None:
            base_path = Path(__file__).parent.parent.parent.parent
            self.engines_output_path = base_path / "engines-output"
        else:
            self.engines_output_path = Path(engines_output_path)
        
        if not self.engines_output_path.exists():
            raise ValueError(f"Engines output path does not exist: {self.engines_output_path}")
    
    def get_scan_path(self, csp: str, scan_id: str) -> Path:
        """Get path to scan output directory."""
        return self.engines_output_path / f"{csp}-configScan-engine" / "output" / scan_id
    
    def read_findings(self, csp: str, scan_id: str) -> Iterator[Dict[str, Any]]:
        """
        Read findings from results.ndjson files.
        
        Supports both:
        - results.ndjson (single file)
        - results_{account}_{region}.ndjson (multiple files)
        
        Args:
            csp: Cloud service provider (e.g., 'aws')
            scan_id: Scan run ID
            
        Yields:
            Finding dictionaries (cspm_finding.v1 schema)
        """
        scan_path = self.get_scan_path(csp, scan_id)
        
        # Try single results.ndjson first (but check if it has content)
        findings_file = scan_path / "results.ndjson"
        
        # If not found or empty, try pattern-based files (results_*.ndjson)
        if not findings_file.exists() or findings_file.stat().st_size == 0:
            findings_files = list(scan_path.glob("results_*.ndjson"))
            # Filter out empty files
            findings_files = [f for f in findings_files if f.stat().st_size > 0]
            if not findings_files:
                logger.warning(f"No findings files found in: {scan_path}")
                return
            else:
                logger.debug(f"Found {len(findings_files)} results_*.ndjson files in {scan_path}")
        else:
            findings_files = [findings_file]
            logger.debug(f"Found results.ndjson file in {scan_path}")
        
        # Read from all findings files
        total_files = len(findings_files)
        for file_idx, findings_file in enumerate(findings_files, 1):
            try:
                file_size_mb = findings_file.stat().st_size / (1024 * 1024)
                if file_size_mb > 100:  # Log progress for large files
                    logger.info(f"Reading findings file {file_idx}/{total_files}: {findings_file.name} ({file_size_mb:.1f} MB)")
                
                line_count = 0
                with open(findings_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                finding = json.loads(line)
                                line_count += 1
                                yield finding
                                
                                # Log progress for very large files
                                if file_size_mb > 500 and line_count % 10000 == 0:
                                    logger.debug(f"Processed {line_count} findings from {findings_file.name}")
                            except json.JSONDecodeError as e:
                                logger.warning(f"Error parsing finding line in {findings_file.name}: {e}")
                
                if file_size_mb > 100:
                    logger.debug(f"Completed {findings_file.name}: {line_count} findings")
            except Exception as e:
                logger.error(f"Error reading findings file {findings_file}: {e}", exc_info=True)
    
    def filter_data_related_findings(
        self, 
        csp: str, 
        scan_id: str, 
        services: Optional[List[str]] = None, 
        data_security_rule_ids: Optional[Set[str]] = None,
        max_findings: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Read and filter findings for data security relevant rules.
        
        OPTIMIZED: Filters by rule_id FIRST (if provided), then by service.
        This is much more efficient than reading all findings then filtering.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            services: List of services to filter (optional, for additional filtering)
            data_security_rule_ids: Set of data security relevant rule IDs to filter by (OPTIMAL - filters first)
            max_findings: Optional limit on number of findings to return (for testing/large files)
            
        Returns:
            List of data security relevant findings
        """
        findings = []
        total_checked = 0
        
        # Primary filter: By rule_id (most efficient)
        if data_security_rule_ids:
            logger.info(f"Filtering findings by {len(data_security_rule_ids)} data security rule IDs")
        else:
            # Fallback: Filter by service
            if services is None:
                services = ["s3", "rds", "dynamodb", "redshift", "glacier", "documentdb", "neptune"]
            services_set = set(service.lower() for service in services)
            logger.info(f"Filtering findings for services: {services} (fallback mode - less efficient)")
        
        for finding in self.read_findings(csp, scan_id):
            total_checked += 1
            rule_id = finding.get("rule_id", "")
            
            # Primary filter: By rule_id (if provided)
            if data_security_rule_ids:
                if rule_id in data_security_rule_ids:
                    findings.append(finding)
                    
                    # Early stopping if max_findings reached
                    if max_findings and len(findings) >= max_findings:
                        logger.info(f"Reached max_findings limit ({max_findings}), stopping filter")
                        break
                    
                    # Progress logging
                    if len(findings) % 100 == 0:
                        logger.debug(f"Found {len(findings)} data security findings (checked {total_checked} total)")
            else:
                # Fallback: Filter by service
                service = finding.get("service", "").lower()
                if service in services_set:
                    findings.append(finding)
                    
                    # Early stopping if max_findings reached
                    if max_findings and len(findings) >= max_findings:
                        logger.info(f"Reached max_findings limit ({max_findings}), stopping filter")
                        break
            
            # Progress logging for large files
            if total_checked % 10000 == 0:
                logger.debug(f"Checked {total_checked} findings, found {len(findings)} relevant")
        
        if data_security_rule_ids:
            logger.info(f"Filtered {len(findings)} data security findings from {total_checked} total findings (using rule_id filter)")
        else:
            logger.info(f"Filtered {len(findings)} data-related findings from {total_checked} total findings (using service filter)")
        return findings
    
    def read_inventory(self, csp: str, scan_id: str) -> Iterator[Dict[str, Any]]:
        """
        Read assets from inventory NDJSON files.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            
        Yields:
            Asset dictionaries (cspm_asset.v1 schema)
        """
        scan_path = self.get_scan_path(csp, scan_id)
        
        # Inventory files are named: inventory_{account_id}_{region}.ndjson
        inventory_pattern = scan_path / "inventory_*.ndjson"
        
        inventory_files = list(scan_path.glob("inventory_*.ndjson"))
        
        if not inventory_files:
            logger.warning(f"No inventory files found in: {scan_path}")
            return
        
        for inventory_file in inventory_files:
            try:
                with open(inventory_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                asset = json.loads(line)
                                yield asset
                            except json.JSONDecodeError as e:
                                logger.warning(f"Error parsing asset line: {e}")
            except Exception as e:
                logger.error(f"Error reading inventory file {inventory_file}: {e}")
    
    def filter_data_stores(self, csp: str, scan_id: str) -> List[Dict[str, Any]]:
        """
        Filter inventory to get only data store assets.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            
        Returns:
            List of data store assets
        """
        data_stores = []
        data_resource_types = [
            "s3:bucket",
            "rds:db-instance",
            "rds:db-cluster",
            "dynamodb:table",
            "redshift:cluster",
            "glacier:vault",
            "documentdb:cluster",
            "neptune:cluster",
        ]
        
        for asset in self.read_inventory(csp, scan_id):
            resource_type = asset.get("resource_type", "").lower()
            service = asset.get("service", "").lower()
            
            # Check if it's a data store by resource_type or service
            if any(drt in resource_type for drt in data_resource_types) or service in ["s3", "rds", "dynamodb", "redshift", "glacier"]:
                data_stores.append(asset)
        
        return data_stores
    
    def read_raw_json(self, csp: str, scan_id: str, account_id: str, region: str, service: str) -> Optional[Dict[str, Any]]:
        """
        Read raw JSON file for a specific service/region.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            account_id: Account ID
            region: Region name
            service: Service name
            
        Returns:
            Raw JSON data or None
        """
        scan_path = self.get_scan_path(csp, scan_id)
        raw_file = scan_path / "raw" / csp / account_id / region / f"{service}.json"
        
        if not raw_file.exists():
            logger.debug(f"Raw file not found: {raw_file}")
            return None
        
        try:
            with open(raw_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading raw file {raw_file}: {e}")
            return None
    
    def get_findings_by_rule_id(self, csp: str, scan_id: str, rule_id: str) -> List[Dict[str, Any]]:
        """
        Get all findings for a specific rule ID.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            rule_id: Rule ID to filter by
            
        Returns:
            List of findings for the rule
        """
        findings = []
        for finding in self.read_findings(csp, scan_id):
            if finding.get("rule_id") == rule_id:
                findings.append(finding)
        return findings
    
    def get_findings_by_resource(self, csp: str, scan_id: str, resource_uid: str) -> List[Dict[str, Any]]:
        """
        Get all findings for a specific resource.
        
        Args:
            csp: Cloud service provider
            scan_id: Scan run ID
            resource_uid: Resource UID/ARN
            
        Returns:
            List of findings for the resource
        """
        findings = []
        for finding in self.read_findings(csp, scan_id):
            if finding.get("resource_uid") == resource_uid or finding.get("resource_arn") == resource_uid:
                findings.append(finding)
        return findings


# Convenience functions
def load_data_findings(csp: str, scan_id: str, engines_output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load data-related findings from configScan output."""
    reader = ConfigScanReader(engines_output_path)
    return reader.filter_data_related_findings(csp, scan_id)


def load_data_stores(csp: str, scan_id: str, engines_output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load data store assets from configScan inventory."""
    reader = ConfigScanReader(engines_output_path)
    return reader.filter_data_stores(csp, scan_id)

