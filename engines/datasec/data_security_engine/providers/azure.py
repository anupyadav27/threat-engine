"""Azure provider for Data Security engine — 8-module DSPM analyze()."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# Azure EU regions for GDPR residency
_EU_REGIONS = {
    "westeurope", "northeurope", "francecentral", "francesouth",
    "germanywestcentral", "germanynorth", "switzerlandnorth", "switzerlandwest",
    "norwayeast", "norwaywest", "swedencentral", "uksouth", "ukwest",
    "polandcentral", "italynorth",
}

# Actual resource_type values in discovery_findings for Azure
_STORAGE_TYPES = {"StorageAccount"}
_KEYVAULT_TYPES = {"KeyVault"}
_ALL_DATA_TYPES = _STORAGE_TYPES | _KEYVAULT_TYPES

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "patient", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, description: str = "") -> List[str]:
    text = (name + " " + description).lower()
    tokens = set(text.replace("-", " ").replace("_", " ").replace(".", " ").split())
    labels: List[str] = []
    if tokens & _PII_TOKENS:
        labels.append("PII")
    if tokens & _PHI_TOKENS:
        labels.append("PHI")
    if tokens & _FINANCIAL_TOKENS:
        labels.append("FINANCIAL")
    if tokens & _CONFIDENTIAL_TOKENS:
        labels.append("CONFIDENTIAL")
    return labels


def _base_finding(
    rule_id: str,
    resource_uid: str,
    resource_type: str,
    account_id: str,
    region: str,
    scan_run_id: str,
    tenant_id: str,
    dspm_module: str,
    severity: str,
    status: str,
    classification_labels: List[str],
    encryption_status: str,
    public_access: bool,
    now: datetime,
) -> Dict[str, Any]:
    return {
        "finding_id": _make_finding_id(rule_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "azure",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        "dspm_module": dspm_module,
        "classification_labels": classification_labels,
        "encryption_status": encryption_status,
        "public_access": public_access,
        "blast_radius_score": 0,
        "first_seen_at": now,
        "last_seen_at": now,
    }


class AzureDataSecProvider(BaseDataSecProvider):

    @property
    def storage_services(self) -> List[str]:
        return ["storage", "datalake", "datalakestorage", "storageaccounts"]

    @property
    def database_services(self) -> List[str]:
        return ["sql", "cosmosdb", "postgresql", "mysql", "synapse", "sqldw"]

    @property
    def streaming_services(self) -> List[str]:
        return ["eventhub", "servicebus", "storagequeue"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["storage.", "sql.", "cosmosdb.", "eventhub.", "servicebus.", "datalake."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over Azure discovery_findings.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for Azure resources.
        """
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []

        try:
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id, list(_ALL_DATA_TYPES)),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("Azure DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning("Azure DSPM: no data-relevant rows for scan_run_id=%s", scan_run_id)
            return []

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            resource_type = row.get("resource_type", "")
            region = (row.get("region") or "eastus").lower().replace(" ", "")
            emitted = row.get("emitted_fields") or {}
            slug = _resource_type_slug(resource_type)

            name = (
                emitted.get("name")
                or emitted.get("resource_id")
                or resource_uid
            )
            labels = _infer_labels(str(name))

            # ── Module 1: classification ────────────────────────────────────
            class_sev = "HIGH" if labels else "MEDIUM"
            rule_id = f"azure.dspm.classification.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="classification",
                severity=class_sev, status="FAIL" if labels else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 2: encryption ────────────────────────────────────────
            if resource_type in _STORAGE_TYPES:
                enc_info = emitted.get("encryption", {})
                services = enc_info.get("services", {})
                blob_enc = services.get("blob", {}).get("enabled", False) if isinstance(services, dict) else False
                enc_status = "encrypted" if blob_enc else "unencrypted"
                sev = "INFO" if blob_enc else "CRITICAL"
                rule_id = f"azure.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity=sev, status="PASS" if blob_enc else "FAIL",
                    classification_labels=labels, encryption_status=enc_status,
                    public_access=False, now=now,
                ))
            elif resource_type in _KEYVAULT_TYPES:
                # Key Vault is always encrypted at rest by Azure
                rule_id = f"azure.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="INFO", status="PASS",
                    classification_labels=labels, encryption_status="encrypted",
                    public_access=False, now=now,
                ))

            # ── Module 3: access_control ────────────────────────────────────
            if resource_type in _STORAGE_TYPES:
                # Check allowBlobPublicAccess — if True or absent, potentially public
                allow_public = emitted.get("allowBlobPublicAccess")
                if allow_public is None:
                    # Check nested properties
                    props = emitted.get("properties", {})
                    allow_public = props.get("allowBlobPublicAccess", False) if isinstance(props, dict) else False
                is_public = bool(allow_public)
                sev = "CRITICAL" if is_public else "INFO"
                rule_id = f"azure.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity=sev, status="FAIL" if is_public else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=is_public, now=now,
                ))

            # ── Module 4: data_residency ────────────────────────────────────
            in_eu = region in _EU_REGIONS
            residency_ok = in_eu
            sev = "MEDIUM" if not residency_ok else "INFO"
            rule_id = f"azure.dspm.data_residency.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_residency",
                severity=sev, status="FAIL" if not residency_ok else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 5: activity_logging ──────────────────────────────────
            if resource_type in _STORAGE_TYPES:
                # Logging enabled if diagnostic settings exist (approximated by tags)
                tags = emitted.get("tags") or {}
                has_logging = bool(tags.get("monitoring") or tags.get("logging"))
                sev = "HIGH" if not has_logging else "INFO"
                rule_id = f"azure.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity=sev, status="FAIL" if not has_logging else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 6: lifecycle ─────────────────────────────────────────
            if resource_type in _STORAGE_TYPES:
                # Soft-delete and versioning indicate lifecycle management
                blob_props = emitted.get("blobSoftDeleteEnabled") or emitted.get("isVersioningEnabled")
                lifecycle_ok = bool(blob_props)
                sev = "MEDIUM" if not lifecycle_ok else "INFO"
                rule_id = f"azure.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity=sev, status="FAIL" if not lifecycle_ok else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 7: data_lineage ──────────────────────────────────────
            rule_id = f"azure.dspm.data_lineage.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_lineage",
                severity="LOW", status="PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 8: governance_score ──────────────────────────────────
            enc_ok = resource_type in _KEYVAULT_TYPES
            pub_ok = True
            if resource_type in _STORAGE_TYPES:
                enc_info2 = emitted.get("encryption", {})
                enc_ok = bool(enc_info2.get("services", {}).get("blob", {}).get("enabled", False)
                              if isinstance(enc_info2.get("services"), dict) else False)
                allow_pub2 = emitted.get("allowBlobPublicAccess", False)
                pub_ok = not bool(allow_pub2)
            score = int(sum([enc_ok, pub_ok]) / 2 * 100)
            gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
            rule_id = f"azure.dspm.governance_score.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="governance_score",
                severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

        logger.info("Azure DSPM analyze(): produced %d findings from %d discovery rows", len(findings), len(rows))
        return findings
