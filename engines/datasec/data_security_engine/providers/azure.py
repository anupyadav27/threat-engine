"""Azure provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  Storage::BlobContainer, SQL::Database, CosmosDB::Account,
  DataLake::Store, Synapse::Workspace, KeyVault::Vault
"""

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

# Canonical resource_type values in discovery_findings for Azure (ENG-10)
_BLOB_TYPES = {"Storage::BlobContainer"}
_SQL_TYPES = {"SQL::Database"}
_COSMOS_TYPES = {"CosmosDB::Account"}
_DATALAKE_TYPES = {"DataLake::Store"}
_SYNAPSE_TYPES = {"Synapse::Workspace"}
_KEYVAULT_TYPES = {"KeyVault::Vault"}

_ALL_DATA_TYPES = list(
    _BLOB_TYPES | _SQL_TYPES | _COSMOS_TYPES
    | _DATALAKE_TYPES | _SYNAPSE_TYPES | _KEYVAULT_TYPES
)

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "patient", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Build canonical finding_id as sha256[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    """Convert resource_type to rule_id slug."""
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, description: str = "") -> List[str]:
    """Infer classification labels from resource name and description tokens."""
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
    """Build a canonical DSPM finding dict."""
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
    """Azure DSPM provider — 8-module analysis over Blob, SQL, CosmosDB, DataLake, Synapse, KeyVault."""

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

        Queries discovery_findings for resource_types:
          Storage::BlobContainer, SQL::Database, CosmosDB::Account,
          DataLake::Store, Synapse::Workspace, KeyVault::Vault

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
                    (scan_run_id, tenant_id, _ALL_DATA_TYPES),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("Azure DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "Azure DSPM: no data-relevant rows for scan_run_id=%s (queried types: %s)",
                scan_run_id, _ALL_DATA_TYPES,
            )
            return []

        # Process in batches of 500 (STRIDE DoS mitigation)
        batch_size = 500
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            for row in batch:
                resource_uid = row.get("resource_uid") or ""
                resource_type = row.get("resource_type", "")
                region = (row.get("region") or "eastus").lower().replace(" ", "")
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                name = (
                    emitted.get("name")
                    or emitted.get("databaseName")
                    or emitted.get("accountName")
                    or emitted.get("resource_id")
                    or resource_uid
                )
                description = str(emitted.get("tags", "")) or str(emitted.get("kind", ""))
                labels = _infer_labels(str(name), description)

                # ── Module 1: data_classification ──────────────────────────────
                class_sev = "HIGH" if labels else "MEDIUM"
                rule_id = f"azure.dspm.data_classification.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_classification",
                    severity=class_sev, status="FAIL" if labels else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 2: encryption_posture ───────────────────────────────
                if resource_type in _BLOB_TYPES:
                    enc_info = emitted.get("encryption", {})
                    services = enc_info.get("services", {}) if isinstance(enc_info, dict) else {}
                    blob_enc = (
                        services.get("blob", {}).get("enabled", False)
                        if isinstance(services, dict) else False
                    )
                    enc_status = "enabled" if blob_enc else "disabled"
                    rule_id = f"azure.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO" if blob_enc else "CRITICAL",
                        status="PASS" if blob_enc else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _SQL_TYPES:
                    # Azure SQL: transparentDataEncryption state
                    tde = emitted.get("transparentDataEncryption", {})
                    tde_enabled = (
                        isinstance(tde, dict) and tde.get("state", "").lower() == "enabled"
                    ) or bool(emitted.get("encryptionProtector"))
                    enc_status = "enabled" if tde_enabled else "disabled"
                    rule_id = f"azure.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO" if tde_enabled else "CRITICAL",
                        status="PASS" if tde_enabled else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _COSMOS_TYPES:
                    # CosmosDB: always encrypted at rest with Microsoft-managed keys
                    cmek = bool(emitted.get("keyVaultKeyUri") or emitted.get("customerManagedKey"))
                    enc_status = "enabled"
                    rule_id = f"azure.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in (_DATALAKE_TYPES | _SYNAPSE_TYPES):
                    # DataLake / Synapse: encryption via managed or customer key
                    enc_ok = bool(
                        emitted.get("encryptionState")
                        or emitted.get("encryption", {})
                        or emitted.get("encryptionConfig")
                    )
                    enc_status = "enabled" if enc_ok else "partial"
                    rule_id = f"azure.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO" if enc_ok else "HIGH",
                        status="PASS" if enc_ok else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _KEYVAULT_TYPES:
                    # Key Vault is always encrypted at rest by Azure
                    rule_id = f"azure.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="enabled",
                        public_access=False, now=now,
                    ))

                # ── Module 3: access_control ───────────────────────────────────
                if resource_type in _BLOB_TYPES:
                    allow_public = emitted.get("allowBlobPublicAccess")
                    if allow_public is None:
                        props = emitted.get("properties", {})
                        allow_public = props.get("allowBlobPublicAccess", False) if isinstance(props, dict) else False
                    is_public = bool(allow_public)
                    rule_id = f"azure.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _SQL_TYPES:
                    # SQL: check for public network access or firewall allowing all
                    pub_net = emitted.get("publicNetworkAccess", "Enabled")
                    firewall = emitted.get("firewallRules", [])
                    all_azure = any(
                        r.get("startIpAddress") == "0.0.0.0" and r.get("endIpAddress") == "0.0.0.0"
                        for r in (firewall if isinstance(firewall, list) else [])
                    )
                    is_public = (
                        str(pub_net).lower() == "enabled"
                        and all_azure
                    )
                    rule_id = f"azure.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="HIGH" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _COSMOS_TYPES:
                    # CosmosDB: publicNetworkAccess
                    pub_net = emitted.get("publicNetworkAccess", "Enabled")
                    is_public = str(pub_net).lower() == "enabled"
                    rule_id = f"azure.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="HIGH" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in (_DATALAKE_TYPES | _SYNAPSE_TYPES | _KEYVAULT_TYPES):
                    # DataLake/Synapse/KeyVault: public network access
                    pub_net = emitted.get("publicNetworkAccess", "Enabled")
                    is_public = str(pub_net).lower() == "enabled"
                    rule_id = f"azure.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="MEDIUM" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))

                # ── Module 4: data_residency ───────────────────────────────────
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

                # ── Module 5: activity_logging ─────────────────────────────────
                if resource_type in _BLOB_TYPES:
                    # Diagnostic settings approximated by tags or diagnosticSettings field
                    diag = emitted.get("diagnosticSettings") or emitted.get("diagnosticLogsConfiguration")
                    tags = emitted.get("tags") or {}
                    has_logging = bool(
                        diag
                        or (isinstance(tags, dict) and (tags.get("monitoring") or tags.get("logging")))
                    )
                    rule_id = f"azure.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _SQL_TYPES:
                    # Azure SQL: auditingSettings enabled
                    audit = emitted.get("auditingSettings", {}) or emitted.get("auditingState", "")
                    has_logging = bool(
                        (isinstance(audit, dict) and audit.get("state", "").lower() == "enabled")
                        or str(audit).lower() == "enabled"
                    )
                    rule_id = f"azure.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_COSMOS_TYPES | _DATALAKE_TYPES | _SYNAPSE_TYPES | _KEYVAULT_TYPES):
                    # CosmosDB/DataLake/Synapse/KeyVault: check diagnosticSettings
                    diag2 = emitted.get("diagnosticSettings") or emitted.get("loggingPolicy")
                    has_logging = bool(diag2)
                    rule_id = f"azure.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 6: data_lifecycle ───────────────────────────────────
                if resource_type in _BLOB_TYPES:
                    soft_delete = bool(
                        emitted.get("blobSoftDeleteEnabled")
                        or emitted.get("isVersioningEnabled")
                        or emitted.get("containerDeleteRetentionPolicy")
                    )
                    rule_id = f"azure.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="MEDIUM" if not soft_delete else "INFO",
                        status="FAIL" if not soft_delete else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _SQL_TYPES:
                    # SQL: shortTermRetention or longTermRetentionPolicies
                    retention = emitted.get("shortTermRetentionPolicy") or emitted.get("backupRetentionDays")
                    lifecycle_ok = bool(retention)
                    rule_id = f"azure.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="HIGH" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_COSMOS_TYPES | _DATALAKE_TYPES | _SYNAPSE_TYPES | _KEYVAULT_TYPES):
                    # CosmosDB: backupPolicy; DataLake/Synapse/KV: no native versioning
                    backup = emitted.get("backupPolicy") or emitted.get("backupRetentionDays")
                    lifecycle_ok = bool(backup)
                    rule_id = f"azure.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="LOW" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 7: data_lineage ─────────────────────────────────────
                # DataLake/Synapse connected to other data services = data flow
                if resource_type in (_DATALAKE_TYPES | _SYNAPSE_TYPES):
                    linked = emitted.get("linkedServices") or emitted.get("integrationRuntimes")
                    has_flow = bool(linked)
                    rule_id = f"azure.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="LOW" if has_flow else "INFO",
                        status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                else:
                    rule_id = f"azure.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 8: governance_scoring ───────────────────────────────
                enc_ok = False
                pub_ok = True
                log_ok = False

                if resource_type in _BLOB_TYPES:
                    enc_info2 = emitted.get("encryption", {})
                    enc_ok = bool(
                        isinstance(enc_info2, dict)
                        and enc_info2.get("services", {}).get("blob", {}).get("enabled", False)
                    )
                    pub_ok = not bool(emitted.get("allowBlobPublicAccess", False))
                    log_ok = bool(emitted.get("diagnosticSettings") or emitted.get("tags", {}).get("logging"))
                elif resource_type in _SQL_TYPES:
                    tde2 = emitted.get("transparentDataEncryption", {})
                    enc_ok = isinstance(tde2, dict) and tde2.get("state", "").lower() == "enabled"
                    pub_ok = str(emitted.get("publicNetworkAccess", "Enabled")).lower() != "enabled"
                    audit2 = emitted.get("auditingSettings", {})
                    log_ok = isinstance(audit2, dict) and audit2.get("state", "").lower() == "enabled"
                elif resource_type in _COSMOS_TYPES:
                    enc_ok = True  # always encrypted
                    pub_ok = str(emitted.get("publicNetworkAccess", "Enabled")).lower() != "enabled"
                    log_ok = bool(emitted.get("diagnosticSettings"))
                elif resource_type in (_DATALAKE_TYPES | _SYNAPSE_TYPES):
                    enc_ok = bool(emitted.get("encryptionState") or emitted.get("encryption"))
                    pub_ok = str(emitted.get("publicNetworkAccess", "Enabled")).lower() != "enabled"
                    log_ok = bool(emitted.get("diagnosticSettings"))
                elif resource_type in _KEYVAULT_TYPES:
                    enc_ok = True  # always encrypted
                    pub_ok = str(emitted.get("publicNetworkAccess", "Enabled")).lower() != "enabled"
                    log_ok = bool(emitted.get("diagnosticSettings"))

                passes = sum([enc_ok, pub_ok, log_ok])
                score = int(passes / 3 * 100)
                gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                rule_id = f"azure.dspm.governance_scoring.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_scoring",
                    severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

        logger.info(
            "Azure DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings
