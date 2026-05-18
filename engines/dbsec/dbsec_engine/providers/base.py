"""Base DBSec provider — abstract contract for all CSP implementations."""

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseDBSecProvider(ABC):
    """Abstract base for all 6 CSP DBSec providers.

    Subclasses implement ``db_resource_types``, ``provider_name``, and the
    five pillar check methods. The ``analyze()`` method orchestrates the
    full 5-pillar scan and returns a flat list of finding dicts.
    """

    # ── Abstract interface ────────────────────────────────────────────────────

    @property
    @abstractmethod
    def db_resource_types(self) -> List[str]:
        """discovery_findings resource_type values this provider scans."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Lowercase CSP name: aws|azure|gcp|oci|alicloud|k8s."""

    # ── Pillar check methods (override in subclasses) ─────────────────────────

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Pillar 1: Network Exposure — publicly accessible DB endpoints."""
        return []

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Pillar 2: Encryption — at-rest and in-transit."""
        return []

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Pillar 3: Authentication — IAM auth, password policies, default users."""
        return []

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Pillar 4: Audit & Activity — query logging, performance insights."""
        return []

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Pillar 5: Compliance Posture — backup, deletion protection, multi-AZ."""
        return []

    # ── Core orchestration ────────────────────────────────────────────────────

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run all 5 pillars against DB resources from discovery_findings.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier (used to scope all DB queries).
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to threat_engine_discoveries.
            check_conn: psycopg2 connection to threat_engine_check (unused by
                most providers but available for rule cross-reference).

        Returns:
            List of finding dicts — one per pillar-check per resource.
        """
        resources = self._load_db_resources(scan_run_id, tenant_id, discoveries_conn)
        logger.info(
            "DBSec[%s] scan_run_id=%s loaded %d DB resources",
            self.provider_name,
            scan_run_id,
            len(resources),
        )

        findings: List[Dict[str, Any]] = []
        for resource in resources:
            try:
                findings.extend(
                    self._check_pillar_1_exposure(resource, tenant_id, account_id, scan_run_id)
                )
            except Exception as exc:
                logger.warning("Pillar 1 error resource=%s: %s", resource.get("resource_uid"), exc)
            try:
                findings.extend(
                    self._check_pillar_2_encryption(resource, tenant_id, account_id, scan_run_id)
                )
            except Exception as exc:
                logger.warning("Pillar 2 error resource=%s: %s", resource.get("resource_uid"), exc)
            try:
                findings.extend(
                    self._check_pillar_3_authentication(resource, tenant_id, account_id, scan_run_id)
                )
            except Exception as exc:
                logger.warning("Pillar 3 error resource=%s: %s", resource.get("resource_uid"), exc)
            try:
                findings.extend(
                    self._check_pillar_4_audit(resource, tenant_id, account_id, scan_run_id)
                )
            except Exception as exc:
                logger.warning("Pillar 4 error resource=%s: %s", resource.get("resource_uid"), exc)
            try:
                findings.extend(
                    self._check_pillar_5_compliance(resource, tenant_id, account_id, scan_run_id)
                )
            except Exception as exc:
                logger.warning("Pillar 5 error resource=%s: %s", resource.get("resource_uid"), exc)

        logger.info(
            "DBSec[%s] scan_run_id=%s produced %d findings from %d resources",
            self.provider_name,
            scan_run_id,
            len(findings),
            len(resources),
        )
        return findings

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _load_db_resources(
        self, scan_run_id: str, tenant_id: str, discoveries_conn: Any
    ) -> List[Dict[str, Any]]:
        """Load DB resource rows from discovery_findings for this provider.

        Filters by scan_run_id, tenant_id, provider_name, and
        db_resource_types. Returns each row as a dict with
        ``resource_uid``, ``resource_type``, ``region``, ``account_id``,
        ``emitted_fields``, ``credential_ref``, ``credential_type``.

        Fallback: if no rows match the current scan_run_id, loads from the
        most recent available scan for this provider/tenant (allows
        re-analysis of older data).
        """
        resource_types = self.db_resource_types
        if not resource_types:
            return []

        with discoveries_conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource_uid, resource_type, region, account_id,
                       emitted_fields, credential_ref, credential_type
                FROM discovery_findings
                WHERE provider = %s
                  AND tenant_id = %s
                  AND scan_run_id = %s
                  AND resource_type = ANY(%s)
                ORDER BY resource_type, resource_uid
                """,
                (self.provider_name, tenant_id, scan_run_id, resource_types),
            )
            rows = cur.fetchall()

        if not rows:
            # Fallback: query latest scan for this provider/tenant
            with discoveries_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, account_id,
                           emitted_fields, credential_ref, credential_type
                    FROM discovery_findings
                    WHERE provider = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    ORDER BY last_seen_at DESC NULLS LAST
                    LIMIT 500
                    """,
                    (self.provider_name, tenant_id, resource_types),
                )
                rows = cur.fetchall()
            if rows:
                logger.info(
                    "DBSec[%s] fallback: loaded %d resources from latest available scan",
                    self.provider_name,
                    len(rows),
                )

        return [
            {
                "resource_uid": r[0],
                "resource_type": r[1],
                "region": r[2] or "",
                "account_id": r[3] or "",
                "emitted_fields": r[4] if isinstance(r[4], dict) else {},
                "credential_ref": r[5] or "",
                "credential_type": r[6] or "",
            }
            for r in rows
            if isinstance(r[4], dict) or r[4] is None
        ]

    @staticmethod
    def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
        """Compute deterministic finding_id.

        Format: sha256(rule_id|resource_uid|account_id|region)[:16]

        Note: ``rule_id`` must already contain the pillar name (e.g.
        ``aws.dbsec.network_exposure.db_instance``) so that findings from
        different pillars on the same resource produce different IDs.
        """
        raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _make_finding(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        resource: Dict[str, Any],
        rule_id: str,
        pillar: str,
        severity: str,
        status: str,
        pillar_detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a complete finding dict from common fields.

        The ``finding_id`` is computed as:
        ``sha256(f"{pillar}_{rule_id}|{resource_uid}|{account_id}|{region}")[:16]``

        Prefixing with ``pillar_`` ensures cross-pillar collisions cannot
        occur even when multiple pillars produce findings for the same
        rule_id/resource combination (AC-S3).

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant identifier.
            account_id: Cloud account identifier.
            resource: Discovery resource row dict.
            rule_id: Rule identifier in format
                ``<csp>.dbsec.<pillar>.<resource_type_slug>``.
            pillar: One of network_exposure|encryption|authentication|
                audit_activity|compliance_posture.
            severity: CRITICAL|HIGH|MEDIUM|LOW|INFO.
            status: FAIL|PASS|NOT_APPLICABLE.
            pillar_detail: Pillar-specific metadata dict.

        Returns:
            Complete finding dict ready for DB insertion.
        """
        _VALID_PILLARS = {
            "network_exposure",
            "encryption",
            "authentication",
            "audit_activity",
            "compliance_posture",
        }
        if pillar not in _VALID_PILLARS:
            raise ValueError(
                f"Invalid pillar '{pillar}'. Must be one of {sorted(_VALID_PILLARS)}"
            )

        now = datetime.now(timezone.utc)
        resource_uid = resource["resource_uid"]
        region = resource["region"] or ""
        eff_account = account_id or resource.get("account_id", "")

        # Include pillar prefix in the hash key to prevent cross-pillar ID
        # collisions on the same resource (AC-S3).
        finding_id = self._make_finding_id(
            f"{pillar}_{rule_id}", resource_uid, eff_account, region
        )

        return {
            "finding_id": finding_id,
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": eff_account,
            "provider": self.provider_name,
            "region": region,
            "resource_uid": resource_uid,
            "resource_type": resource["resource_type"],
            "severity": severity,
            "status": status,
            "pillar": pillar,
            "pillar_detail": pillar_detail or {},
            "blast_radius_score": 0,
            "first_seen_at": now,
            "last_seen_at": now,
            "rule_id": rule_id,
        }

    @staticmethod
    def _slug(resource_type: str) -> str:
        """Convert resource_type to a rule_id-safe slug.

        Examples:
            'db_instance' → 'db_instance'
            'RDS::DBInstance' → 'rds_dbinstance'
        """
        return resource_type.lower().replace("::", "_").replace(":", "_").replace("-", "_")


class NoOpDBSecProvider(BaseDBSecProvider):
    """Fallback provider for unknown CSPs — returns no findings."""

    def __init__(self, csp: str) -> None:
        self._csp = csp

    @property
    def db_resource_types(self) -> List[str]:
        return []

    @property
    def provider_name(self) -> str:
        return self._csp
