"""
Threat Report Storage

Handles storage and retrieval of threat reports.
- THREAT_USE_DB=true: persist to PostgreSQL (threat_reports table, THREAT_DB_*).
- Otherwise: file-based (THREAT_REPORTS_DIR, default ./threat_reports).
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from ..schemas.threat_report_schema import ThreatReport, Threat, ThreatStatus

logger = logging.getLogger(__name__)


def _use_db() -> bool:
    # Database is now PRIMARY - always use DB if available
    # Only fallback to files if DB connection fails
    return True  # Always prefer DB


class ThreatStorage:
    """Storage for threat reports (DB or file)."""

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize storage.

        Args:
            storage_dir: Directory for file storage. Defaults to THREAT_REPORTS_DIR or ./threat_reports
        """
        if storage_dir is None:
            storage_dir = os.getenv("THREAT_REPORTS_DIR", "./threat_reports")

        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._use_db = _use_db()

        self._cache: Dict[str, Dict[str, Any]] = {}
        self._threat_status_cache: Dict[str, ThreatStatus] = {}

    def save_report(self, report: ThreatReport) -> str:
        """
        Save threat report to storage.
        Database is PRIMARY - always tries DB first, falls back to files only if DB fails.
        """
        scan_run_id = report.scan_context.scan_run_id
        tenant_id = report.tenant.tenant_id

        # Try DB first (primary)
        if self._use_db:
            try:
                from .threat_db_writer import save_report_to_db
                save_report_to_db(report)
                logger.info(f"Threat report saved to database: {scan_run_id}")
            except Exception as e:
                # Fallback to file if DB fails
                logger.warning(f"Failed to save threat report to DB, falling back to file: {e}")
                tenant_dir = self.storage_dir / tenant_id
                tenant_dir.mkdir(parents=True, exist_ok=True)
                report_file = tenant_dir / f"{scan_run_id}.json"
                with open(report_file, "w") as f:
                    json.dump(report.dict(), f, default=str, indent=2)
                logger.info(f"Threat report saved to file: {report_file}")
        else:
            # File fallback (shouldn't happen with _use_db=True, but kept for safety)
            tenant_dir = self.storage_dir / tenant_id
            tenant_dir.mkdir(parents=True, exist_ok=True)
            report_file = tenant_dir / f"{scan_run_id}.json"
            with open(report_file, "w") as f:
                json.dump(report.dict(), f, default=str, indent=2)

        self._cache[scan_run_id] = report.dict()
        for threat in report.threats:
            self._threat_status_cache[threat.threat_id] = threat.status

        return scan_run_id
    
    def get_report(self, scan_run_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get threat report by scan_run_id and tenant_id.
        Database is PRIMARY - tries DB first, falls back to files if DB fails.
        """
        if scan_run_id in self._cache:
            report = self._cache[scan_run_id].copy()
            self._apply_status_updates(report)
            return report

        if self._use_db:
            try:
                from .threat_db_writer import get_report_from_db
                report = get_report_from_db(tenant_id, scan_run_id)
            except Exception:
                return None
            if report:
                self._cache[scan_run_id] = report
                self._apply_status_updates(report)
            return report

        report_file = self.storage_dir / tenant_id / f"{scan_run_id}.json"
        if not report_file.exists():
            return None
        try:
            with open(report_file, "r") as f:
                report = json.load(f)
            self._cache[scan_run_id] = report
            self._apply_status_updates(report)
            return report
        except Exception:
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
        List threat report metadata for a tenant.
        Database is PRIMARY - tries DB first, falls back to files if DB fails.
        """
        if self._use_db:
            try:
                from .threat_db_writer import list_reports_from_db
                return list_reports_from_db(tenant_id, limit)
            except Exception:
                return []

        tenant_dir = self.storage_dir / tenant_id
        if not tenant_dir.exists():
            return []
        reports = []
        for report_file in sorted(tenant_dir.glob("*.json"), reverse=True)[:limit]:
            try:
                with open(report_file, "r") as f:
                    report = json.load(f)
                reports.append({
                    "scan_run_id": report["scan_context"]["scan_run_id"],
                    "generated_at": report.get("generated_at"),
                    "cloud": report["scan_context"]["cloud"],
                    "total_threats": report["threat_summary"]["total_threats"],
                    "threats_by_severity": report["threat_summary"]["threats_by_severity"],
                })
            except Exception:
                continue
        return reports
    
    def update_threat_status(
        self,
        threat_id: str,
        status: ThreatStatus,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Update threat status. Persists to DB when THREAT_USE_DB=true, else to file.
        """
        self._threat_status_cache[threat_id] = status

        for scan_run_id, report in self._cache.items():
            for threat in report.get("threats", []):
                if threat.get("threat_id") != threat_id:
                    continue
                threat["status"] = status.value
                if notes:
                    threat["notes"] = notes
                threat["status_updated_at"] = datetime.utcnow().isoformat()

                tenant_id = (report.get("tenant") or {}).get("tenant_id")
                if not tenant_id:
                    return True
                if self._use_db:
                    try:
                        from .threat_db_writer import update_report_in_db
                        update_report_in_db(tenant_id, scan_run_id, report)
                    except Exception:
                        pass
                else:
                    self._save_report_to_file(scan_run_id, tenant_id, report)
                return True

        return False
    
    def get_threat(self, threat_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get single threat by ID. In DB mode, scans stored reports (best-effort).
        """
        def _extract(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            for threat in report.get("threats", []):
                if threat.get("threat_id") == threat_id:
                    if threat_id in self._threat_status_cache:
                        threat = {**threat, "status": self._threat_status_cache[threat_id].value}
                    refs = (threat.get("correlations") or {}).get("misconfig_finding_refs") or []
                    return {
                        "threat": threat,
                        "report_context": {
                            "scan_run_id": report["scan_context"]["scan_run_id"],
                            "generated_at": report.get("generated_at"),
                            "tenant": report.get("tenant"),
                        },
                        "misconfig_findings": [
                            f for f in report.get("misconfig_findings", [])
                            if f.get("misconfig_finding_id") in refs
                        ],
                    }
            return None

        if self._use_db:
            try:
                from .threat_db_writer import list_reports_from_db, get_report_from_db
            except Exception:
                return None
            for meta in list_reports_from_db(tenant_id, limit=500):
                scan_run_id = meta.get("scan_run_id")
                if not scan_run_id:
                    continue
                report = get_report_from_db(tenant_id, scan_run_id)
                if not report:
                    continue
                out = _extract(report)
                if out:
                    return out
            return None

        tenant_dir = self.storage_dir / tenant_id
        if not tenant_dir.exists():
            return None
        for report_file in tenant_dir.glob("*.json"):
            try:
                with open(report_file, "r") as f:
                    report = json.load(f)
                out = _extract(report)
                if out:
                    return out
            except Exception:
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



