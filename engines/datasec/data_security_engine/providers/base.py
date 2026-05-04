"""Base provider interface for the Data Security engine."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseDataSecProvider(ABC):

    @property
    @abstractmethod
    def storage_services(self) -> List[str]:
        """Object/blob storage services."""

    @property
    @abstractmethod
    def database_services(self) -> List[str]:
        """Managed database services with data classification relevance."""

    @property
    @abstractmethod
    def streaming_services(self) -> List[str]:
        """Message queue and streaming services."""

    @property
    def all_services(self) -> List[str]:
        return sorted(set(self.storage_services + self.database_services + self.streaming_services))

    @property
    @abstractmethod
    def inventory_resource_prefixes(self) -> List[str]:
        """resource_type prefixes for inventory_findings."""

    @property
    def check_scope_column(self) -> str:
        return "data_security"

    def is_supported(self) -> bool:
        return True

    def enrich_resources(self, resources: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        return resources

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Read discovery_findings for this CSP and produce structured DSPM findings.

        Each subclass overrides this to implement all 8 DSPM modules (ENG-10):
          1. data_classification  — PII/PHI/FINANCIAL/CONFIDENTIAL label detection
          2. encryption_posture   — at-rest + in-transit encryption (CMEK preferred)
          3. access_control       — public access flags, overly permissive policies
          4. data_residency       — region compliance (EU for GDPR, US for HIPAA)
          5. activity_logging     — audit/access logging enabled
          6. data_lifecycle       — versioning, retention, backup
          7. data_lineage         — cross-service data flow patterns
          8. governance_scoring   — aggregate DSPM score per resource

        All SELECT queries on discovery_findings MUST include AND tenant_id = %s.
        blast_radius_score MUST always be 0 — the risk engine owns this field.
        finding_id = sha256(f"{rule_id}|{resource_uid}|{account_id}|{region}")[:16]

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused by most providers).

        Returns:
            List of finding dicts — one per (resource, module) pair.
            Each dict must include: finding_id, scan_run_id, tenant_id, account_id,
            provider, region, resource_uid, resource_type, severity, status,
            dspm_module, classification_labels, encryption_status, public_access,
            blast_radius_score (always 0), first_seen_at, last_seen_at.
        """
        return []
