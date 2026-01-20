"""
Threat Report Storage

Handles storage and retrieval of threat reports.
Currently uses file-based storage, can be enhanced with database later.
"""

import os
import json
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from ..schemas.threat_report_schema import ThreatReport, Threat, ThreatStatus


class ThreatStorage:
    """Storage for threat reports"""
    
    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize storage.
        
        Args:
            storage_dir: Directory to store reports. Defaults to ./threat_reports
        """
        if storage_dir is None:
            storage_dir = os.getenv("THREAT_REPORTS_DIR", "./threat_reports")
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache for quick access
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._threat_status_cache: Dict[str, ThreatStatus] = {}
    
    def save_report(self, report: ThreatReport) -> str:
        """
        Save threat report to storage.
        
        Args:
            report: Threat report to save
            
        Returns:
            Storage key (scan_run_id)
        """
        scan_run_id = report.scan_context.scan_run_id
        tenant_id = report.tenant.tenant_id
        
        # Create tenant directory
        tenant_dir = self.storage_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        
        # Save report as JSON
        report_file = tenant_dir / f"{scan_run_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report.dict(), f, default=str, indent=2)
        
        # Cache in memory
        self._cache[scan_run_id] = report.dict()
        
        # Cache threat statuses
        for threat in report.threats:
            self._threat_status_cache[threat.threat_id] = threat.status
        
        return scan_run_id
    
    def get_report(self, scan_run_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get threat report by scan_run_id.
        
        Args:
            scan_run_id: Scan run identifier
            tenant_id: Tenant identifier
            
        Returns:
            Threat report dict or None if not found
        """
        # Check cache first
        if scan_run_id in self._cache:
            report = self._cache[scan_run_id].copy()
            # Apply status updates from cache
            self._apply_status_updates(report)
            return report
        
        # Load from file
        report_file = self.storage_dir / tenant_id / f"{scan_run_id}.json"
        if not report_file.exists():
            return None
        
        try:
            with open(report_file, 'r') as f:
                report = json.load(f)
            
            # Cache it
            self._cache[scan_run_id] = report
            
            # Apply status updates
            self._apply_status_updates(report)
            
            return report
        except Exception as e:
            print(f"Error loading report: {e}")
            return None
    
    def get_summary(self, scan_run_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get threat summary only (lightweight).
        
        Args:
            scan_run_id: Scan run identifier
            tenant_id: Tenant identifier
            
        Returns:
            Threat summary dict or None if not found
        """
        report = self.get_report(scan_run_id, tenant_id)
        if not report:
            return None
        
        return {
            "scan_run_id": scan_run_id,
            "threat_summary": report.get("threat_summary"),
            "generated_at": report.get("generated_at")
        }
    
    def list_reports(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        List all threat reports for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            limit: Maximum number of reports to return
            
        Returns:
            List of report metadata
        """
        tenant_dir = self.storage_dir / tenant_id
        if not tenant_dir.exists():
            return []
        
        reports = []
        for report_file in sorted(tenant_dir.glob("*.json"), reverse=True)[:limit]:
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                    reports.append({
                        "scan_run_id": report["scan_context"]["scan_run_id"],
                        "generated_at": report.get("generated_at"),
                        "cloud": report["scan_context"]["cloud"],
                        "total_threats": report["threat_summary"]["total_threats"],
                        "threats_by_severity": report["threat_summary"]["threats_by_severity"]
                    })
            except Exception as e:
                print(f"Error loading report {report_file}: {e}")
                continue
        
        return reports
    
    def update_threat_status(
        self,
        threat_id: str,
        status: ThreatStatus,
        notes: Optional[str] = None
    ) -> bool:
        """
        Update threat status.
        
        Args:
            threat_id: Threat identifier
            status: New status
            notes: Optional notes
            
        Returns:
            True if updated, False if threat not found
        """
        # Cache status update
        self._threat_status_cache[threat_id] = status
        
        # Find and update in all cached reports
        for scan_run_id, report in self._cache.items():
            for threat in report.get("threats", []):
                if threat.get("threat_id") == threat_id:
                    threat["status"] = status.value
                    if notes:
                        threat["notes"] = notes
                    threat["status_updated_at"] = datetime.utcnow().isoformat()
                    
                    # Save back to file
                    tenant_id = report.get("tenant", {}).get("tenant_id")
                    if tenant_id:
                        self._save_report_to_file(scan_run_id, tenant_id, report)
                    
                    return True
        
        return False
    
    def get_threat(self, threat_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get single threat by ID.
        
        Args:
            threat_id: Threat identifier
            tenant_id: Tenant identifier
            
        Returns:
            Threat dict with full report context or None
        """
        # Search through all reports
        tenant_dir = self.storage_dir / tenant_id
        if not tenant_dir.exists():
            return None
        
        for report_file in tenant_dir.glob("*.json"):
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                
                for threat in report.get("threats", []):
                    if threat.get("threat_id") == threat_id:
                        # Apply status update if exists
                        if threat_id in self._threat_status_cache:
                            threat["status"] = self._threat_status_cache[threat_id].value
                        
                        return {
                            "threat": threat,
                            "report_context": {
                                "scan_run_id": report["scan_context"]["scan_run_id"],
                                "generated_at": report.get("generated_at"),
                                "tenant": report.get("tenant")
                            },
                            "misconfig_findings": [
                                f for f in report.get("misconfig_findings", [])
                                if f.get("misconfig_finding_id") in threat.get("correlations", {}).get("misconfig_finding_refs", [])
                            ]
                        }
            except Exception as e:
                print(f"Error loading report {report_file}: {e}")
                continue
        
        return None
    
    def _apply_status_updates(self, report: Dict[str, Any]) -> None:
        """Apply cached status updates to report"""
        for threat in report.get("threats", []):
            threat_id = threat.get("threat_id")
            if threat_id in self._threat_status_cache:
                threat["status"] = self._threat_status_cache[threat_id].value
    
    def _save_report_to_file(self, scan_run_id: str, tenant_id: str, report: Dict[str, Any]) -> None:
        """Save report dict to file"""
        tenant_dir = self.storage_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = tenant_dir / f"{scan_run_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, default=str, indent=2)



