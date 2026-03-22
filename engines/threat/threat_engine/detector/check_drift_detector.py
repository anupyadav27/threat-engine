"""
Check Status Drift Detector

Detects PASS/WARN to FAIL status changes between scans.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from ..schemas.threat_report_schema import (
    Threat,
    ThreatType,
    Severity,
    Confidence,
    ThreatStatus,
    ThreatCorrelation,
    DriftEvent
)
from ..database.check_queries import CheckDatabaseQueries
from .threat_detector import generate_stable_threat_id


class CheckDriftDetector:
    """Detects check status drift threats"""

    def __init__(self, check_queries: Optional[CheckDatabaseQueries] = None):
        self.check_queries = check_queries or CheckDatabaseQueries()

    def detect_check_status_drift(
        self,
        tenant_id: str,
        account_id: Optional[str] = None,
        service: Optional[str] = None,
        current_scan_id: Optional[str] = None,
        region: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Threat]:
        """
        Detect PASS/WARN to FAIL changes between latest and previous scans.
        """
        if not current_scan_id:
            latest = self.check_queries.get_latest_scan(
                tenant_id=tenant_id,
                account_id=account_id,
                service=service,
                start_time=start_time,
                end_time=end_time
            )
            if not latest:
                return []
            current_scan_id = latest.get("scan_id")

        previous = self.check_queries.get_previous_scan(
            tenant_id=tenant_id,
            current_scan_id=current_scan_id,
            account_id=account_id,
            service=service,
            start_time=start_time,
            end_time=end_time
        )
        baseline_scan_id = previous.get("scan_id") if previous else None
        if not baseline_scan_id:
            return []

        current_results = self.check_queries.get_check_results_for_scan(
            scan_id=current_scan_id,
            tenant_id=tenant_id,
            account_id=account_id,
            service=service,
            include_metadata=True
        )
        previous_results = self.check_queries.get_check_results_for_scan(
            scan_id=baseline_scan_id,
            tenant_id=tenant_id,
            account_id=account_id,
            service=service,
            include_metadata=True
        )

        previous_map = {}
        for prev in previous_results:
            key = self._build_key(prev)
            previous_map[key] = prev

        threats: List[Threat] = []

        for curr in current_results:
            key = self._build_key(curr)
            prev = previous_map.get(key)
            if not prev:
                continue

            prev_status = (prev.get("status") or "").upper()
            curr_status = (curr.get("status") or "").upper()

            if not self._is_drift(prev_status, curr_status):
                continue

            resource_uid = curr.get("resource_uid") or curr.get("resource_arn") or curr.get("resource_id")
            resource_arn = curr.get("resource_arn")
            account = curr.get("account_id") or "unknown"
            extracted_region = self._extract_region(resource_arn)
            if region and extracted_region != region:
                continue
            region = extracted_region

            severity = self._map_severity(curr.get("rule_severity"))

            threat_id = generate_stable_threat_id(
                ThreatType.CHECK_STATUS_DRIFT,
                resource_uid or "unknown",
                account,
                region
            )

            threats.append(Threat(
                threat_id=threat_id,
                threat_type=ThreatType.CHECK_STATUS_DRIFT,
                title="Check status drift detected",
                description=f"Check {curr.get('rule_id')} changed from {prev_status} to {curr_status}",
                severity=severity,
                confidence=Confidence.MEDIUM,
                status=ThreatStatus.OPEN,
                first_seen_at=curr.get("first_seen_at") or datetime.now(timezone.utc),
                last_seen_at=curr.get("first_seen_at") or datetime.now(timezone.utc),
                correlations=ThreatCorrelation(
                    misconfig_finding_refs=[],
                    affected_assets=[]
                ),
                affected_assets=[{
                    "resource_uid": resource_uid,
                    "resource_arn": resource_arn,
                    "resource_type": curr.get("resource_type"),
                    "resource_id": curr.get("resource_id"),
                    "region": region,
                    "account": account
                }],
                drift=DriftEvent(
                    drift_type="check_status",
                    rule_id=curr.get("rule_id"),
                    resource_arn=resource_arn,
                    resource_uid=resource_uid,
                    service=curr.get("resource_type"),
                    region=region,
                    baseline_scan_id=baseline_scan_id,
                    current_scan_id=current_scan_id,
                    change_summary={
                        "previous_status": prev_status,
                        "current_status": curr_status
                    }
                )
            ))

        return threats

    def _build_key(self, result: Dict[str, Any]) -> str:
        rule_id = result.get("rule_id") or "unknown"
        resource_uid = result.get("resource_uid") or result.get("resource_arn") or result.get("resource_id") or "unknown"
        return f"{rule_id}|{resource_uid}"

    def _is_drift(self, prev_status: str, curr_status: str) -> bool:
        if curr_status == "FAIL" and prev_status in ["PASS", "WARN", "ERROR"]:
            return True
        if curr_status == "WARN" and prev_status == "PASS":
            return True
        return False

    def _extract_region(self, resource_arn: Optional[str]) -> str:
        if not resource_arn:
            return "global"
        parts = resource_arn.split(":")
        if len(parts) >= 4 and parts[3]:
            return parts[3]
        return "global"

    def _map_severity(self, severity_value: Optional[str]) -> Severity:
        if not severity_value:
            return Severity.MEDIUM
        severity_str = str(severity_value).lower()
        if severity_str == "critical":
            return Severity.CRITICAL
        if severity_str == "high":
            return Severity.HIGH
        if severity_str == "low":
            return Severity.LOW
        if severity_str == "info":
            return Severity.INFO
        return Severity.MEDIUM
