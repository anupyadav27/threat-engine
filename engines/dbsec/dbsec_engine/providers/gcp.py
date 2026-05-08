"""GCP DBSec provider — CloudSQL, Spanner, Bigtable, Firestore, BigQuery, GCS.

Current discovery catalog for GCP includes:
  - bigquery.googleapis.com/Dataset  (data store)
  - storage.googleapis.com/Bucket    (object storage data store)
  - compute.googleapis.com/Instance  (may host self-managed DBs)
  - secretmanager.googleapis.com/Secret (credential store)
  - iam.googleapis.com/ServiceAccount

Dedicated CloudSQL/Spanner types are evaluated when discovered.
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

GCP_DB_RESOURCE_TYPES = [
    # Currently discovered types (produce findings now)
    "bigquery.googleapis.com/Dataset",
    "storage.googleapis.com/Bucket",
    "secretmanager.googleapis.com/Secret",
    # Dedicated DB types (evaluated when discovered)
    "CloudSQL::Instance",
    "Spanner::Instance",
    "Bigtable::Instance",
    "Firestore::Database",
    "Memorystore::Instance",
    "cloudsql_instance",
    "spanner_instance",
    "bigtable_instance",
    "firestore_database",
    "memorystore_instance",
    "sql_instance",
    "database_instance",
]

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"

# Resource types handled by generic fallback (GCS, BQ, Secret)
_PROXY_TYPES = {
    "bigquery.googleapis.com/Dataset",
    "storage.googleapis.com/Bucket",
    "secretmanager.googleapis.com/Secret",
}


class GCPDBSecProvider(BaseDBSecProvider):
    """GCP database security checks.

    Evaluates BigQuery Datasets and GCS Buckets as data stores,
    plus dedicated CloudSQL/Spanner types when present in discovery data.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return GCP_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "gcp"

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"gcp.dbsec.{PILLAR_NETWORK}.{slug}"

        if rtype == "bigquery.googleapis.com/Dataset":
            # BigQuery: check if access entries contain allUsers or allAuthenticatedUsers
            access = ef.get("access", []) or []
            is_public = any(
                entry.get("specialGroup") in ("allUsers", "allAuthenticatedUsers")
                for entry in access
                if isinstance(entry, dict)
            )
            status = "FAIL" if is_public else "PASS"
            severity = "CRITICAL" if is_public else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "public_dataset_access",
                        "is_public": is_public,
                        "access_entry_count": len(access),
                        "location": ef.get("location", ""),
                    },
                )
            ]

        if rtype == "storage.googleapis.com/Bucket":
            # GCS: check iamConfiguration for uniform bucket-level access
            iam_config = ef.get("iamConfiguration", {}) or {}
            uniform_access = (iam_config.get("uniformBucketLevelAccess", {}) or {}).get("enabled", False)
            # Public access via ACLs when uniform access is disabled
            is_at_risk = not uniform_access
            status = "FAIL" if is_at_risk else "PASS"
            severity = "HIGH" if is_at_risk else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "uniform_bucket_access",
                        "uniform_bucket_level_access": uniform_access,
                        "note": "Without uniform access, per-object ACLs can expose data publicly",
                        "storage_class": ef.get("storageClass", ""),
                        "location": ef.get("location", ""),
                    },
                )
            ]

        if rtype == "secretmanager.googleapis.com/Secret":
            # Secrets are private by default; flag if replication is not managed
            replication = ef.get("replication", {}) or {}
            is_automatic = "automatic" in replication
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {
                        "check": "secret_network_isolation",
                        "note": "GCP Secret Manager secrets are VPC-isolated by default",
                        "replication_type": "automatic" if is_automatic else "user_managed",
                    },
                )
            ]

        # CloudSQL: settings.ipConfiguration.ipv4Enabled
        settings = ef.get("settings", {}) or {}
        ip_config = settings.get("ipConfiguration", {}) or {}
        ipv4_enabled = ip_config.get("ipv4Enabled", False)
        authorized_networks = ip_config.get("authorizedNetworks", [])
        open_to_world = any(
            n.get("value", "") in ("0.0.0.0/0", "::/0")
            for n in authorized_networks
            if isinstance(n, dict)
        )

        is_exposed = ipv4_enabled or open_to_world
        status = "FAIL" if is_exposed else "PASS"
        severity = "HIGH" if is_exposed else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status,
                {
                    "check": "ipv4_enabled",
                    "ipv4_enabled": ipv4_enabled,
                    "open_to_world": open_to_world,
                    "authorized_networks_count": len(authorized_networks),
                },
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"gcp.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype == "bigquery.googleapis.com/Dataset":
            # BigQuery encrypts by default; check for CMEK
            default_enc = ef.get("defaultEncryptionConfiguration", {}) or {}
            cmek = default_enc.get("kmsKeyName", "") if isinstance(default_enc, dict) else ""
            has_cmek = bool(cmek)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "MEDIUM" if not has_cmek else "INFO",
                    "FAIL" if not has_cmek else "PASS",
                    {
                        "check": "cmek_encryption",
                        "cmek_enabled": has_cmek,
                        "kms_key": cmek,
                        "note": "BigQuery datasets encrypted by default; CMEK provides additional control",
                    },
                )
            ]

        if rtype == "storage.googleapis.com/Bucket":
            # GCS: check for CMEK or default Google-managed encryption
            enc_config = ef.get("encryption", {}) or {}
            cmek = enc_config.get("defaultKmsKeyName", "") if isinstance(enc_config, dict) else ""
            has_cmek = bool(cmek)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "MEDIUM" if not has_cmek else "INFO",
                    "FAIL" if not has_cmek else "PASS",
                    {
                        "check": "cmek_encryption",
                        "cmek_enabled": has_cmek,
                        "kms_key": cmek,
                        "note": "GCS Bucket encrypted by default; CMEK provides additional control",
                    },
                )
            ]

        if rtype == "secretmanager.googleapis.com/Secret":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "secret_encryption", "note": "GCP Secret Manager encrypts secrets by default"},
                )
            ]

        # CloudSQL: CMEK check
        disk_encryption = ef.get("diskEncryptionConfiguration", {}) or {}
        cmek = disk_encryption.get("kmsKeyName", "") if isinstance(disk_encryption, dict) else ""
        has_cmek = bool(cmek)

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, "MEDIUM" if not has_cmek else "INFO",
                "FAIL" if not has_cmek else "PASS",
                {
                    "check": "cmek_encryption",
                    "cmek_enabled": has_cmek,
                    "kms_key": cmek,
                    "note": "GCP encrypts by default; CMEK provides additional control",
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"gcp.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype == "bigquery.googleapis.com/Dataset":
            # BigQuery: check if access grants are appropriately restricted
            access = ef.get("access", []) or []
            has_domain_grant = any(
                entry.get("domain") for entry in access if isinstance(entry, dict)
            )
            status = "FAIL" if has_domain_grant else "PASS"
            severity = "HIGH" if has_domain_grant else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "domain_level_access",
                        "domain_access_granted": has_domain_grant,
                        "note": "Domain-level access grants broad access to all users in the domain",
                    },
                )
            ]

        if rtype == "storage.googleapis.com/Bucket":
            # GCS: check uniform bucket level access (enforces IAM-only)
            iam_config = ef.get("iamConfiguration", {}) or {}
            uniform_access = (iam_config.get("uniformBucketLevelAccess", {}) or {}).get("enabled", False)
            status = "FAIL" if not uniform_access else "PASS"
            severity = "HIGH" if not uniform_access else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "uniform_iam_access",
                        "uniform_bucket_level_access": uniform_access,
                        "note": "Uniform access enforces IAM-only authorization without legacy ACLs",
                    },
                )
            ]

        if rtype == "secretmanager.googleapis.com/Secret":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "iam_controlled", "note": "Secret Manager access controlled via IAM"},
                )
            ]

        # CloudSQL: SSL required and IAM authentication
        settings = ef.get("settings", {}) or {}
        require_ssl = settings.get("requireSsl", settings.get("sslMode", False))
        ssl_ok = bool(require_ssl) and str(require_ssl).upper() not in ("FALSE", "ALLOW_UNENCRYPTED_AND_ENCRYPTED")
        iam_flags = settings.get("databaseFlags", []) or []
        iam_enabled = any(
            f.get("name") == "cloudsql_iam_authentication" and f.get("value") == "on"
            for f in iam_flags
            if isinstance(f, dict)
        )

        status = "FAIL" if not ssl_ok else "PASS"
        severity = "HIGH" if not ssl_ok else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status,
                {
                    "check": "ssl_required",
                    "ssl_required": ssl_ok,
                    "iam_auth_enabled": iam_enabled,
                    "ssl_mode": str(require_ssl),
                },
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"gcp.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype == "bigquery.googleapis.com/Dataset":
            # BigQuery: data access audit logs via Cloud Audit Logs
            # Check labels for any monitoring/audit tags
            labels = ef.get("labels", {}) or {}
            has_audit_label = any("audit" in k.lower() or "monitor" in k.lower() for k in labels)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {
                        "check": "data_access_audit",
                        "note": "BigQuery data access is audited via GCP Cloud Audit Logs",
                        "has_monitoring_labels": has_audit_label,
                    },
                )
            ]

        if rtype == "storage.googleapis.com/Bucket":
            # GCS: check logging configuration
            logging_config = ef.get("logging", {}) or {}
            has_access_logging = bool(logging_config.get("logBucket", "") if isinstance(logging_config, dict) else "")
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "HIGH" if not has_access_logging else "INFO",
                    "FAIL" if not has_access_logging else "PASS",
                    {
                        "check": "access_logging",
                        "access_logging_enabled": has_access_logging,
                        "log_bucket": logging_config.get("logBucket", "") if isinstance(logging_config, dict) else "",
                    },
                )
            ]

        if rtype == "secretmanager.googleapis.com/Secret":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {"check": "audit_logging", "note": "Secret Manager access audited via GCP Cloud Audit Logs"},
                )
            ]

        # CloudSQL: database flags for logging
        settings = ef.get("settings", {}) or {}
        flags = {f["name"]: f["value"] for f in settings.get("databaseFlags", []) if isinstance(f, dict)}
        log_flags = {"log_connections", "log_disconnections", "log_checkpoints"}
        enabled_logs = [f for f in log_flags if flags.get(f) == "on"]
        has_audit = len(enabled_logs) > 0

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, "HIGH" if not has_audit else "INFO",
                "FAIL" if not has_audit else "PASS",
                {
                    "check": "db_logging_flags",
                    "enabled_log_flags": enabled_logs,
                    "all_flags": flags,
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"gcp.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        if rtype == "bigquery.googleapis.com/Dataset":
            # BigQuery: check default table expiration (compliance risk if tables expire too quickly)
            default_expiry_ms = ef.get("defaultTableExpirationMs", ef.get("default_table_expiration_ms"))
            expiry_set = default_expiry_ms is not None and int(default_expiry_ms or 0) > 0
            # Having default expiration may mean data is lost without explicit retention policy
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.retention", PILLAR_COMPLIANCE,
                    "MEDIUM" if expiry_set else "INFO",
                    "FAIL" if expiry_set else "PASS",
                    {
                        "check": "table_retention_policy",
                        "default_expiration_set": expiry_set,
                        "default_expiry_ms": default_expiry_ms,
                        "note": "Default table expiration means data may be deleted automatically",
                    },
                )
            )
            return findings

        if rtype == "storage.googleapis.com/Bucket":
            # GCS: check versioning and retention policy
            versioning = ef.get("versioning", {}) or {}
            versioning_enabled = versioning.get("enabled", False) if isinstance(versioning, dict) else False
            retention_policy = ef.get("retentionPolicy", {}) or {}
            has_retention = bool(retention_policy)

            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.versioning", PILLAR_COMPLIANCE,
                    "HIGH" if not versioning_enabled else "INFO",
                    "FAIL" if not versioning_enabled else "PASS",
                    {
                        "check": "object_versioning",
                        "versioning_enabled": versioning_enabled,
                        "retention_policy_set": has_retention,
                    },
                )
            )
            return findings

        if rtype == "secretmanager.googleapis.com/Secret":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.retention", PILLAR_COMPLIANCE,
                    "INFO", "PASS",
                    {"check": "secret_retention", "note": "Secret Manager versions provide audit history"},
                )
            )
            return findings

        # CloudSQL: backup and deletion protection
        settings = ef.get("settings", {}) or {}
        backup_config = settings.get("backupConfiguration", {}) or {}
        backup_enabled = backup_config.get("enabled", False)
        pitr_enabled = backup_config.get("pointInTimeRecoveryEnabled", False)

        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.backup", PILLAR_COMPLIANCE,
                "HIGH" if not backup_enabled else "INFO",
                "FAIL" if not backup_enabled else "PASS",
                {
                    "check": "automated_backup",
                    "backup_enabled": backup_enabled,
                    "pitr_enabled": pitr_enabled,
                    "binary_log_enabled": backup_config.get("binaryLogEnabled", False),
                },
            )
        )

        deletion_protection = ef.get("deletionProtectionEnabled", False)
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.deletion_protection", PILLAR_COMPLIANCE,
                "MEDIUM", "FAIL" if not deletion_protection else "PASS",
                {"check": "deletion_protection", "deletion_protection": bool(deletion_protection)},
            )
        )

        return findings
