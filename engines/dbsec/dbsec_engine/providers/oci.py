"""OCI DBSec provider — DbSystem, AutonomousDB, MySQL, NoSQL, Object Storage.

Current OCI discovery catalog includes:
  - oci.objectstorage/Bucket  (object storage data store)
  - oci.core/Instance         (compute hosting self-managed DBs)
  - oci.core/Vcn              (network context)
  - oci.audit/Configuration   (audit configuration)

Dedicated OCI Database resource types are evaluated when present.
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

OCI_DB_RESOURCE_TYPES = [
    # Currently discovered types
    "oci.objectstorage/Bucket",
    "oci.audit/Configuration",
    "oci.core/Instance",
    # Dedicated DB types (evaluated when discovered)
    "Database::DbSystem",
    "Database::AutonomousDatabase",
    "MySQL::DbSystem",
    "NoSQL::Table",
    "database_dbsystem",
    "database_autonomousdatabase",
    "mysql_dbsystem",
    "nosql_table",
    "db_system",
    "autonomous_database",
]

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"

# Proxy types from current discovery catalog
_PROXY_TYPES = {
    "oci.objectstorage/Bucket",
    "oci.audit/Configuration",
    "oci.core/Instance",
}


class OCIDBSecProvider(BaseDBSecProvider):
    """OCI database security checks.

    Evaluates OCI Object Storage buckets and audit configuration as data
    store proxies, plus dedicated OCI Database types when available.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return OCI_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "oci"

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"oci.dbsec.{PILLAR_NETWORK}.{slug}"

        if rtype == "oci.objectstorage/Bucket":
            # Check public access type
            public_access_type = ef.get("publicAccessType", "NoPublicAccess")
            is_public = str(public_access_type).lower() not in ("nopublicaccess", "none", "false", "")
            status = "FAIL" if is_public else "PASS"
            severity = "CRITICAL" if is_public else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "public_access_type",
                        "public_access_type": public_access_type,
                        "is_public": is_public,
                        "bucket_name": ef.get("name", ""),
                    },
                )
            ]

        if rtype == "oci.audit/Configuration":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {"check": "audit_config", "note": "OCI Audit Configuration is internal; no network exposure"},
                )
            ]

        if rtype == "oci.core/Instance":
            # Check if instance has a public IP
            primary_vnic = ef.get("primaryPublicIp", ef.get("public_ip", ""))
            has_public_ip = bool(primary_vnic)
            status = "FAIL" if has_public_ip else "PASS"
            severity = "HIGH" if has_public_ip else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "public_ip_exposure",
                        "public_ip": primary_vnic,
                        "note": "Compute instance with public IP may host publicly accessible DB",
                    },
                )
            ]

        # OCI AutonomousDB: isAccessControlEnabled
        access_control = ef.get("isAccessControlEnabled", None)
        whitelisted_ips = ef.get("whitelistedIps", []) or []

        if access_control is not None:
            exposed = not access_control
            status = "FAIL" if exposed else "PASS"
            severity = "HIGH" if exposed else "INFO"
            detail = {
                "check": "access_control_enabled",
                "access_control_enabled": bool(access_control),
                "whitelisted_ips_count": len(whitelisted_ips),
            }
        else:
            subnet_id = ef.get("subnetId", "")
            private_subnet = "private" in subnet_id.lower() if subnet_id else False
            exposed = not private_subnet
            status = "FAIL" if exposed else "PASS"
            severity = "MEDIUM" if exposed else "INFO"
            detail = {
                "check": "subnet_visibility",
                "subnet_id": subnet_id,
                "private_subnet_inferred": private_subnet,
            }

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status, detail,
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"oci.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype == "oci.objectstorage/Bucket":
            # Check encryption: OCI managed key or customer managed key (kmsKeyId)
            kms_key = ef.get("kmsKeyId", "")
            has_cmk = bool(kms_key)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "MEDIUM" if not has_cmk else "INFO",
                    "FAIL" if not has_cmk else "PASS",
                    {
                        "check": "cmek_encryption",
                        "cmek_enabled": has_cmk,
                        "kms_key_id": kms_key,
                        "note": "OCI Object Storage encrypted by default; CMEK adds key management control",
                    },
                )
            ]

        if rtype == "oci.audit/Configuration":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "audit_encryption", "note": "OCI Audit logs are encrypted at rest by default"},
                )
            ]

        if rtype == "oci.core/Instance":
            # Check boot volume encryption
            boot_vol_kms = ef.get("bootVolumeKmsKeyId", "")
            has_cmk = bool(boot_vol_kms)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "MEDIUM" if not has_cmk else "INFO",
                    "FAIL" if not has_cmk else "PASS",
                    {
                        "check": "boot_volume_cmek",
                        "cmek_enabled": has_cmk,
                        "boot_volume_kms_key": boot_vol_kms,
                        "note": "Instance boot volume CMEK encryption for self-managed DB data",
                    },
                )
            ]

        # OCI DB: CMEK check
        kms_key = ef.get("kmsKeyId", ef.get("vaultId", ""))
        has_cmk = bool(kms_key)

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, "MEDIUM" if not has_cmk else "INFO",
                "FAIL" if not has_cmk else "PASS",
                {
                    "check": "cmek_encryption",
                    "cmek_enabled": has_cmk,
                    "kms_key_id": kms_key,
                    "note": "OCI encrypts at rest by default; CMEK adds control",
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"oci.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype == "oci.objectstorage/Bucket":
            # Bucket access via IAM policies
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {
                        "check": "iam_controlled",
                        "note": "OCI Object Storage access controlled via IAM policies",
                    },
                )
            ]

        if rtype == "oci.audit/Configuration":
            retention_period = ef.get("retentionPeriodDays", 0) or 0
            # Audit config with short retention is a compliance risk
            status = "FAIL" if retention_period < 90 else "PASS"
            severity = "HIGH" if retention_period < 90 else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "audit_retention",
                        "retention_period_days": retention_period,
                        "compliant_minimum": 90,
                        "note": "Audit log retention less than 90 days may not meet compliance requirements",
                    },
                )
            ]

        if rtype == "oci.core/Instance":
            lifecycle_state = ef.get("lifecycleState", "RUNNING")
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {
                        "check": "instance_auth",
                        "lifecycle_state": lifecycle_state,
                        "note": "OCI Instance authentication managed via SSH keys and IAM",
                    },
                )
            ]

        # AutonomousDB: mTLS requirement
        mtls_required = ef.get("isMtlsConnectionRequired", None)
        if mtls_required is not None:
            status = "FAIL" if not mtls_required else "PASS"
            severity = "HIGH" if not mtls_required else "INFO"
            detail = {"check": "mtls_required", "mtls_required": bool(mtls_required)}
        else:
            lifecycle = ef.get("lifecycleState", "")
            status = "PASS" if lifecycle == "AVAILABLE" else "FAIL"
            severity = "MEDIUM"
            detail = {"check": "lifecycle_state", "lifecycle_state": lifecycle}

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status, detail,
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"oci.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype == "oci.objectstorage/Bucket":
            # Object Storage logging
            object_events_enabled = ef.get("objectEventsEnabled", False)
            status = "FAIL" if not object_events_enabled else "PASS"
            severity = "HIGH" if not object_events_enabled else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, severity, status,
                    {
                        "check": "object_events_enabled",
                        "object_events_enabled": bool(object_events_enabled),
                        "note": "Object Storage events enable audit trail for data access",
                    },
                )
            ]

        if rtype == "oci.audit/Configuration":
            retention_period = ef.get("retentionPeriodDays", 0) or 0
            # 90 days minimum for enterprise compliance
            status = "FAIL" if retention_period < 90 else "PASS"
            severity = "HIGH" if retention_period < 90 else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, severity, status,
                    {
                        "check": "audit_retention_period",
                        "retention_period_days": retention_period,
                        "compliant_minimum": 90,
                    },
                )
            ]

        if rtype == "oci.core/Instance":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "MEDIUM", "FAIL",
                    {
                        "check": "instance_db_audit",
                        "note": "Self-managed DB on Compute Instance — audit logging status not determinable",
                    },
                )
            ]

        # OCI Database: DB management status
        monitoring = ef.get("databaseManagementConfig", {}) or {}
        mgmt_status = monitoring.get("databaseManagementStatus", "NOT_ENABLED") if isinstance(monitoring, dict) else "NOT_ENABLED"
        operations_insights = ef.get("operationsInsightsStatus", "NOT_ENABLED")
        audit_active = mgmt_status == "ENABLED" or operations_insights == "ENABLED"
        status = "FAIL" if not audit_active else "PASS"
        severity = "HIGH" if not audit_active else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, severity, status,
                {
                    "check": "db_management_enabled",
                    "db_management_status": mgmt_status,
                    "operations_insights": operations_insights,
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"oci.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        if rtype == "oci.objectstorage/Bucket":
            # Object Storage: versioning and replication
            object_storage_tier = ef.get("storageTier", "Standard")
            # Check for replication (disaster recovery)
            replication_sources = ef.get("replicationSources", []) or []
            has_replication = bool(replication_sources)
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.replication", PILLAR_COMPLIANCE,
                    "MEDIUM" if not has_replication else "INFO",
                    "FAIL" if not has_replication else "PASS",
                    {
                        "check": "cross_region_replication",
                        "replication_configured": has_replication,
                        "storage_tier": object_storage_tier,
                    },
                )
            )
            return findings

        if rtype == "oci.audit/Configuration":
            retention_period = ef.get("retentionPeriodDays", 0) or 0
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.retention", PILLAR_COMPLIANCE,
                    "HIGH" if retention_period < 90 else "INFO",
                    "FAIL" if retention_period < 90 else "PASS",
                    {
                        "check": "audit_log_retention",
                        "retention_period_days": retention_period,
                        "compliant_minimum": 90,
                    },
                )
            )
            return findings

        if rtype == "oci.core/Instance":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.backup", PILLAR_COMPLIANCE,
                    "MEDIUM", "FAIL",
                    {
                        "check": "backup_configuration",
                        "note": "Instance backup configuration for self-managed DB not determinable",
                    },
                )
            )
            return findings

        # OCI Database: backup retention
        backup_retention = ef.get("backupRetentionPeriodInDays", 0) or 0
        bk_status = "FAIL" if backup_retention < 7 else "PASS"
        bk_severity = "HIGH" if backup_retention < 7 else "INFO"
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.backup", PILLAR_COMPLIANCE, bk_severity, bk_status,
                {
                    "check": "backup_retention",
                    "backup_retention_days": backup_retention,
                    "compliant_minimum": 7,
                },
            )
        )

        lifecycle = ef.get("lifecycleState", "")
        delete_protected = ef.get("deletionProtection", lifecycle == "AVAILABLE")
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.deletion_protection", PILLAR_COMPLIANCE,
                "MEDIUM", "PASS" if delete_protected else "FAIL",
                {"check": "deletion_protection", "lifecycle_state": lifecycle},
            )
        )

        return findings
