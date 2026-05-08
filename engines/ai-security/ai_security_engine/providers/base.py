"""Base provider interface for the AI Security engine."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseAISecurityProvider(ABC):

    @property
    @abstractmethod
    def discovery_services(self) -> List[str]:
        """CSP-specific AI/ML service names to load from discovery_findings."""

    @property
    @abstractmethod
    def inventory_resource_prefixes(self) -> List[str]:
        """resource_type prefixes for inventory_findings."""

    @property
    def check_scope_column(self) -> str:
        return "ai_security"

    def is_supported(self) -> bool:
        return True

    def enrich_resources(
        self,
        resources: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Enrich resource list with additional context data.

        Args:
            resources: Raw discovery resource dicts.
            context: Additional contextual data (e.g. IAM policies).

        Returns:
            Enriched resource list.
        """
        return resources

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Read discovery_findings for AI/ML resources and produce ATLAS-mapped findings.

        Each subclass overrides this to inspect CSP-specific AI/ML resource
        configurations from ``discovery_findings.emitted_fields`` (already a
        dict — never call json.loads on it) and return a list of finding dicts
        with the MITRE ATLAS pillar and technique populated.

        Finding dict keys:
            finding_id (str): sha256(rule_id|resource_uid|account_id|region)[:16]
            scan_run_id (str): pipeline scan run identifier
            tenant_id (str): tenant identifier
            account_id (str): cloud account identifier
            provider (str): lowercase csp name
            region (str): resource region
            resource_uid (str): unique resource identifier / ARN
            resource_type (str): e.g. 'SageMaker::NotebookInstance'
            severity (str): CRITICAL | HIGH | MEDIUM | LOW
            status (str): FAIL | PASS | NOT_APPLICABLE
            pillar (str): model_security | training_data_security |
                          inference_security | supply_chain | ai_governance
            atlas_technique (str | None): AML.T0000 – AML.T0005
            atlas_detail (dict): technique name and description
            blast_radius_score (int): ALWAYS 0 — risk engine owns this
            first_seen_at (datetime): utc timestamp
            last_seen_at (datetime): utc timestamp

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — ALL DB queries MUST filter by this.
            account_id: Cloud account identifier.
            discoveries_conn: Open psycopg2 connection to the discoveries DB.
            check_conn: Optional open psycopg2 connection to the check DB.

        Returns:
            List of finding dicts.  Default implementation returns [].
        """
        return []
