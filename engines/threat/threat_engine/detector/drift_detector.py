"""
Drift Detector

Detects configuration drift from discovery history.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from ..schemas.threat_report_schema import (
    Threat,
    ThreatType,
    Severity,
    Confidence,
    ThreatStatus,
    ThreatCorrelation,
    DriftEvent
)
from ..database.discovery_queries import DiscoveryDatabaseQueries
from .threat_detector import generate_stable_threat_id


class DriftDetector:
    """Detects configuration drift threats from discovery history"""

    def __init__(self, discovery_queries: Optional[DiscoveryDatabaseQueries] = None):
        self.discovery_queries = discovery_queries or DiscoveryDatabaseQueries()

    def detect_configuration_drift(
        self,
        tenant_id: str,
        hierarchy_id: Optional[str] = None,
        service: Optional[str] = None,
        current_scan_id: Optional[str] = None,
        region: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Threat]:
        """
        Detect configuration drift threats.

        Uses latest and previous discovery scans when current_scan_id is not provided.
        """
        # Determine current scan
        if not current_scan_id:
            latest = self.discovery_queries.get_latest_scan(
                tenant_id=tenant_id,
                hierarchy_id=hierarchy_id,
                service=service,
                start_time=start_time,
                end_time=end_time
            )
            if not latest:
                return []
            current_scan_id = latest.get("scan_id")

        # Determine baseline scan
        previous = self.discovery_queries.get_previous_scan(
            tenant_id=tenant_id,
            current_scan_id=current_scan_id,
            hierarchy_id=hierarchy_id,
            service=service,
            start_time=start_time,
            end_time=end_time
        )
        baseline_scan_id = previous.get("scan_id") if previous else None

        # Get configuration drift events
        drift_events = self.discovery_queries.get_configuration_drift(
            tenant_id=tenant_id,
            current_scan_id=current_scan_id,
            hierarchy_id=hierarchy_id,
            service=service,
            region=region,
            start_time=start_time,
            end_time=end_time
        )

        threats: List[Threat] = []

        for event in drift_events:
            resource_arn = event.get("resource_arn")
            resource_uid = event.get("resource_uid") or resource_arn
            region = event.get("region") or "global"
            account = event.get("hierarchy_id") or "unknown"
            discovery_id = event.get("discovery_id")

            change_summary = event.get("diff_summary") or {}
            severity = self._calculate_severity(change_summary)

            threat_id = generate_stable_threat_id(
                ThreatType.CONFIGURATION_DRIFT,
                resource_uid or "unknown",
                account,
                region
            )

            threats.append(Threat(
                threat_id=threat_id,
                threat_type=ThreatType.CONFIGURATION_DRIFT,
                title="Configuration drift detected",
                description=f"Configuration drift detected for {discovery_id or 'resource'}",
                severity=severity,
                confidence=Confidence.MEDIUM,
                status=ThreatStatus.OPEN,
                first_seen_at=event.get("scan_timestamp") or datetime.utcnow(),
                last_seen_at=event.get("scan_timestamp") or datetime.utcnow(),
                correlations=ThreatCorrelation(
                    misconfig_finding_refs=[],
                    affected_assets=[]
                ),
                affected_assets=[{
                    "resource_uid": resource_uid,
                    "resource_arn": resource_arn,
                    "resource_type": event.get("service"),
                    "resource_id": event.get("resource_id"),
                    "region": region,
                    "account": account
                }],
                drift=DriftEvent(
                    drift_type="configuration",
                    discovery_id=discovery_id,
                    resource_arn=resource_arn,
                    resource_uid=resource_uid,
                    service=event.get("service"),
                    region=region,
                    baseline_scan_id=event.get("baseline_scan_id") or baseline_scan_id,
                    current_scan_id=current_scan_id,
                    change_summary=change_summary,
                    previous_hash=event.get("previous_hash"),
                    current_hash=event.get("config_hash")
                )
            ))

        return threats

    def _calculate_severity(self, change_summary: Dict[str, Any]) -> Severity:
        """Calculate drift severity based on change summary fields"""
        critical_fields = ['policy', 'encryption', 'publicaccessblock', 'versioning', 'kms']

        fields_modified = change_summary.get('fields_modified', []) or []
        fields_added = change_summary.get('fields_added', []) or []
        fields_removed = change_summary.get('fields_removed', []) or []

        modified_field_names = [c.get('field', '') for c in fields_modified if isinstance(c, dict)]
        modified_field_names += [str(f) for f in fields_added]
        modified_field_names += [str(f) for f in fields_removed]

        field_text = " ".join(modified_field_names).lower()

        if any(token in field_text for token in critical_fields):
            return Severity.HIGH

        if len(modified_field_names) > 5:
            return Severity.MEDIUM

        return Severity.LOW
