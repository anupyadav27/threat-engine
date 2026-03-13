"""
Threat Engine Loader

Loads check results from threat engine findings.ndjson files and converts them
to the format expected by the compliance engine.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from collections import defaultdict


class ThreatEngineLoader:
    """Loads check results from threat engine output."""
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize threat engine loader.
        
        Args:
            base_path: Base directory for threat engine output
                      Default: engine_output/engine_configscan_aws/output/configscan/rule_check
        """
        if base_path is None:
            from engine_common.storage_paths import get_project_root
            root = get_project_root()
            base_path = root / "engine_output" / "engine_configscan_aws" / "output" / "configscan" / "rule_check"
        
        self.base_path = Path(base_path)
        self._cache: Dict[str, List[Dict]] = {}
    
    def find_latest_ndjson(self) -> Optional[Path]:
        """Find the most recent findings.ndjson file."""
        if not self.base_path.exists():
            return None
        
        scan_dirs = sorted(self.base_path.glob("rule_check_*"), reverse=True)
        for scan_dir in scan_dirs:
            findings_file = scan_dir / "findings.ndjson"
            if findings_file.exists():
                return findings_file
        return None
    
    def load_check_results(self, ndjson_file: Optional[Path] = None, 
                          tenant_id: Optional[str] = None,
                          scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Load check results from findings.ndjson.
        
        Args:
            ndjson_file: Path to findings.ndjson (if None, finds latest)
            tenant_id: Filter by tenant_id (optional)
            scan_id: Filter by scan_id (optional)
        
        Returns:
            List of check result dictionaries
        """
        if ndjson_file is None:
            ndjson_file = self.find_latest_ndjson()
        
        if not ndjson_file or not ndjson_file.exists():
            return []
        
        # Check cache
        cache_key = f"{ndjson_file}_{tenant_id}_{scan_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        records = []
        with open(ndjson_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    
                    # Filter by tenant_id if provided
                    if tenant_id and record.get('tenant_id') != tenant_id:
                        continue
                    
                    # Filter by scan_id if provided
                    if scan_id and record.get('scan_id') != scan_id:
                        continue
                    
                    records.append(record)
                except json.JSONDecodeError:
                    continue
        
        self._cache[cache_key] = records
        return records
    
    def convert_to_scan_results_format(self, check_results: List[Dict[str, Any]], 
                                      csp: str = "aws") -> Dict[str, Any]:
        """
        Convert threat engine check results to compliance engine scan results format.
        
        Threat engine format:
        {
            "scan_id": "...",
            "rule_id": "aws.s3.bucket.block_public_access_enabled",
            "status": "PASS" | "FAIL" | "ERROR",
            "resource_arn": "arn:aws:s3:::bucket",
            "resource_id": "bucket",
            "resource_type": "s3",
            "checked_fields": [...],
            "finding_data": {...}
        }
        
        Compliance engine format:
        {
            "scan_id": "...",
            "csp": "aws",
            "account_id": "...",
            "scanned_at": "...",
            "results": [{
                "service": "s3",
                "region": "us-east-1",
                "checks": [{
                    "rule_id": "...",
                    "result": "PASS" | "FAIL",
                    "severity": "high",
                    "resource": {...},
                    "evidence": {...}
                }]
            }]
        }
        
        Args:
            check_results: List of check results from threat engine
            csp: Cloud service provider
        
        Returns:
            Scan results in compliance engine format
        """
        if not check_results:
            return {
                'scan_id': '',
                'csp': csp,
                'account_id': '',
                'scanned_at': datetime.now(timezone.utc).isoformat() + 'Z',
                'results': []
            }
        
        # Group by service and region
        service_region_map: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
        
        # Extract metadata from first record
        first_record = check_results[0]
        scan_id = first_record.get('scan_id', '')
        account_id = first_record.get('hierarchy_id', '')  # hierarchy_id is typically account_id
        scanned_at = first_record.get('scan_timestamp', datetime.now(timezone.utc).isoformat() + 'Z')
        
        # Convert timestamp if it's a string
        if isinstance(scanned_at, str):
            try:
                # Try to parse and reformat
                dt = datetime.fromisoformat(scanned_at.replace('Z', '+00:00'))
                scanned_at = dt.isoformat() + 'Z'
            except Exception:
                scanned_at = datetime.now(timezone.utc).isoformat() + 'Z'
        
        for record in check_results:
            rule_id = record.get('rule_id', '')
            status = record.get('status', 'UNKNOWN')
            resource_type = record.get('resource_type', 'unknown')
            resource_arn = record.get('resource_arn', '')
            resource_id = record.get('resource_id', '')
            
            # Extract service from resource_type or rule_id
            service = resource_type
            if not service or service == 'unknown':
                # Extract from rule_id: aws.s3.bucket.* -> s3
                parts = rule_id.split('.')
                if len(parts) >= 2:
                    service = parts[1]
            
            # Extract region from resource_arn or use 'global'
            region = 'global'
            if resource_arn:
                # ARN format: arn:aws:service:region:account:resource
                arn_parts = resource_arn.split(':')
                if len(arn_parts) >= 4:
                    region = arn_parts[3] if arn_parts[3] else 'global'
            
            # Determine severity from rule_id or use default
            severity = 'medium'
            if 'high' in rule_id.lower() or 'critical' in rule_id.lower():
                severity = 'high'
            elif 'low' in rule_id.lower():
                severity = 'low'
            
            # Convert status
            result = status
            if status == 'ERROR':
                result = 'ERROR'
            elif status in ['PASS', 'FAIL']:
                result = status
            else:
                result = 'UNKNOWN'
            
            # Build check entry
            check_entry = {
                'rule_id': rule_id,
                'result': result,
                'severity': severity,
                'resource': {
                    'arn': resource_arn,
                    'id': resource_id,
                    'type': resource_type
                },
                'evidence': {
                    'checked_fields': record.get('checked_fields', []),
                    'finding_data': record.get('finding_data', {})
                }
            }
            
            service_region_map[service][region].append(check_entry)
        
        # Build results array
        results = []
        for service, regions in service_region_map.items():
            for region, checks in regions.items():
                results.append({
                    'service': service,
                    'region': region,
                    'checks': checks
                })
        
        return {
            'scan_id': scan_id,
            'csp': csp,
            'account_id': account_id,
            'scanned_at': scanned_at,
            'results': results
        }
    
    def load_and_convert(self, tenant_id: Optional[str] = None,
                        scan_id: Optional[str] = None,
                        csp: str = "aws") -> Dict[str, Any]:
        """
        Load check results and convert to compliance engine format.
        
        Args:
            tenant_id: Filter by tenant_id
            scan_id: Filter by scan_id
            csp: Cloud service provider
        
        Returns:
            Scan results in compliance engine format
        """
        check_results = self.load_check_results(tenant_id=tenant_id, scan_id=scan_id)
        return self.convert_to_scan_results_format(check_results, csp=csp)
