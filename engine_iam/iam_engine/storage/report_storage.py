"""
Report Storage for IAM Security Engine

Saves IAM reports to engine_output/iam/reports/{tenant_id}/{scan_id}_report.json
"""

from pathlib import Path
import json
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class ReportStorage:
    """Stores IAM security reports to file system in engine_output/iam/reports/"""
    
    def __init__(self, base_path: Optional[str] = None):
        """
        Initialize report storage.
        
        Args:
            base_path: Base path for reports. Default: engine_output/iam/reports/
        """
        if base_path is None:
            # Default: engine_output/iam/reports/
            base_path = Path(__file__).parent.parent.parent.parent / "engine_output" / "iam" / "reports"
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"IAM report storage initialized at: {self.base_path}")
    
    def save_report(self, report: Dict[str, Any], tenant_id: str, scan_id: str) -> str:
        """
        Save IAM report to file system.
        
        Args:
            report: IAM report dictionary
            tenant_id: Tenant identifier
            scan_id: Scan identifier
            
        Returns:
            Path to saved report file
        """
        tenant_dir = self.base_path / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        report_path = tenant_dir / f"{scan_id}_report.json"
        
        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"IAM report saved: {report_path}")
            return str(report_path)
        except Exception as e:
            logger.error(f"Error saving IAM report to {report_path}: {e}")
            raise
    
    def get_report(self, tenant_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Load IAM report from storage.
        
        Args:
            tenant_id: Tenant identifier
            scan_id: Scan identifier
            
        Returns:
            Report dictionary or None if not found
        """
        report_path = self.base_path / tenant_id / f"{scan_id}_report.json"
        if not report_path.exists():
            logger.debug(f"IAM report not found: {report_path}")
            return None
        
        try:
            with open(report_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading IAM report from {report_path}: {e}")
            return None
    
    def list_reports(self, tenant_id: Optional[str] = None) -> List[str]:
        """
        List available reports.
        
        Args:
            tenant_id: Optional tenant filter
            
        Returns:
            List of report file paths
        """
        if tenant_id:
            tenant_dir = self.base_path / tenant_id
            if tenant_dir.exists():
                return [str(f) for f in tenant_dir.glob("*_report.json")]
            return []
        else:
            reports = []
            for tenant_dir in self.base_path.iterdir():
                if tenant_dir.is_dir():
                    reports.extend([str(f) for f in tenant_dir.glob("*_report.json")])
            return reports
