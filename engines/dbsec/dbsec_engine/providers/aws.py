"""AWS DBSec provider — 5-pillar analysis for RDS, Redshift, DynamoDB, ElastiCache.

Resource types match actual discovery_findings values (lowercase, underscore-separated).
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

# discovery_findings resource_type values for AWS DB services (lowercase as stored)
AWS_DB_RESOURCE_TYPES = [
    "db_instance",        # RDS instances (postgres, mysql, oracle, neptune, etc.)
    "db_cluster",         # Aurora clusters
    "cluster",            # Redshift / MSK / ElastiCache clusters
    "table",              # DynamoDB tables
    "database",           # Glue / SSM-SAP databases
    "keyspace",           # Amazon Keyspaces (Cassandra)
    "global_table",       # DynamoDB global tables
]

# Cluster types that are known DB clusters vs general compute clusters
_REDSHIFT_HINTS = {"NodeType", "NumberOfNodes", "AutomatedSnapshotRetentionPeriod", "MasterUsername"}
_ELASTICACHE_HINTS = {"AtRestEncryptionEnabled", "TransitEncryptionEnabled", "AuthTokenEnabled", "ReplicationGroupId"}
_NON_DB_CLUSTER_KEYS = {"clusters", "failures", "VpcConnections"}  # Fargate/Kafka clusters

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"


def _is_db_cluster(ef: Dict[str, Any]) -> bool:
    """Return True if this 'cluster' resource is a database cluster (not Fargate/Kafka)."""
    keys = set(ef.keys())
    # If it contains Fargate/Kafka-specific keys, skip
    if keys & _NON_DB_CLUSTER_KEYS and not (keys & _REDSHIFT_HINTS) and not (keys & _ELASTICACHE_HINTS):
        return False
    # If it has DB-specific attributes
    if keys & _REDSHIFT_HINTS or keys & _ELASTICACHE_HINTS:
        return True
    # If virtually empty (just resource_uid, resource_type, _raw_response) — skip
    meaningful_keys = keys - {"resource_uid", "resource_type", "_raw_response", "resource_id",
                               "resource_name", "resource_arn", "account_id"}
    return len(meaningful_keys) >= 2


class AWSDBSecProvider(BaseDBSecProvider):
    """AWS database security checks across RDS, DynamoDB, Redshift, ElastiCache.

    Uses lowercase resource_type values as stored in discovery_findings by the
    AWS scanner (db_instance, cluster, table, keyspace, database).
    """

    @property
    def db_resource_types(self) -> List[str]:
        return AWS_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "aws"

    # ── Pillar 1: Network Exposure ────────────────────────────────────────────

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Check for publicly accessible databases."""
        findings = []
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"aws.dbsec.{PILLAR_NETWORK}.{slug}"

        if rtype == "db_instance":
            publicly_accessible = ef.get("PubliclyAccessible", False)
            status = "FAIL" if publicly_accessible else "PASS"
            severity = "CRITICAL" if publicly_accessible else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "publicly_accessible",
                        "publicly_accessible": publicly_accessible,
                        "endpoint": (ef.get("Endpoint") or {}).get("Address", ""),
                        "vpc_id": (ef.get("DBSubnetGroup") or {}).get("VpcId", ""),
                        "db_instance_status": ef.get("DBInstanceStatus", ""),
                    },
                )
            )

        elif rtype == "db_cluster":
            publicly_accessible = ef.get("PubliclyAccessible", False)
            status = "FAIL" if publicly_accessible else "PASS"
            severity = "CRITICAL" if publicly_accessible else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {"check": "publicly_accessible", "publicly_accessible": publicly_accessible},
                )
            )

        elif rtype == "cluster":
            if not _is_db_cluster(ef):
                return []
            publicly_accessible = ef.get("PubliclyAccessible", ef.get("ClusterPubliclyAccessible", False))
            if publicly_accessible is None:
                publicly_accessible = False
            status = "FAIL" if publicly_accessible else "PASS"
            severity = "HIGH" if publicly_accessible else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "publicly_accessible",
                        "publicly_accessible": bool(publicly_accessible),
                        "cluster_type": ef.get("ClusterType", ""),
                    },
                )
            )

        elif rtype == "table":
            # DynamoDB — access controlled via IAM; check for any resource policy hints
            table_props = ef.get("TableProperties") or ef
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {
                        "check": "public_access",
                        "note": "DynamoDB access controlled via IAM policies",
                        "table_name": ef.get("TableName", ""),
                    },
                )
            )

        elif rtype == "keyspace":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {
                        "check": "public_access",
                        "note": "Amazon Keyspaces access controlled via IAM/VPC endpoints",
                        "keyspace_name": ef.get("keyspaceName", ""),
                    },
                )
            )

        elif rtype in ("database", "global_table"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {"check": "public_access", "note": f"{rtype} access managed via IAM"},
                )
            )

        return findings

    # ── Pillar 2: Encryption ──────────────────────────────────────────────────

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Check encryption at-rest and in-transit."""
        findings = []
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"aws.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype in ("db_instance", "db_cluster"):
            storage_encrypted = ef.get("StorageEncrypted", False)
            if storage_encrypted is None:
                storage_encrypted = False
            kms_key = ef.get("KmsKeyId", "")
            status = "FAIL" if not storage_encrypted else "PASS"
            severity = "CRITICAL" if not storage_encrypted else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, severity, status,
                    {
                        "check": "storage_encrypted",
                        "storage_encrypted": bool(storage_encrypted),
                        "kms_key_id": kms_key,
                        "ca_cert": ef.get("CACertificateIdentifier", ""),
                    },
                )
            )

        elif rtype == "cluster":
            if not _is_db_cluster(ef):
                return []
            encrypted = ef.get("Encrypted", ef.get("AtRestEncryptionEnabled", None))
            transit_enc = ef.get("TransitEncryptionEnabled", None)

            if encrypted is not None:
                status = "FAIL" if not encrypted else "PASS"
                severity = "CRITICAL" if not encrypted else "INFO"
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource, rule_id,
                        PILLAR_ENCRYPT, severity, status,
                        {
                            "check": "at_rest_encrypted",
                            "encrypted": bool(encrypted),
                            "transit_encrypted": transit_enc,
                        },
                    )
                )
            elif transit_enc is not None:
                status = "FAIL" if not transit_enc else "PASS"
                severity = "HIGH" if not transit_enc else "INFO"
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource, rule_id,
                        PILLAR_ENCRYPT, severity, status,
                        {"check": "transit_encrypted", "transit_encrypted": bool(transit_enc)},
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource, rule_id,
                        PILLAR_ENCRYPT, "MEDIUM", "FAIL",
                        {"check": "encryption_unknown", "note": "Encryption status not determinable from discovery data"},
                    )
                )

        elif rtype == "table":
            # DynamoDB: SSEDescription or TableProperties
            table_props = ef.get("TableProperties") or {}
            sse = ef.get("SSEDescription") or table_props.get("SSEDescription") or {}
            sse_status = sse.get("Status", "DISABLED") if isinstance(sse, dict) else "DISABLED"
            encrypted = sse_status in ("ENABLED", "UPDATING")
            # DynamoDB tables are encrypted by default with AWS-managed keys; only flag if explicitly disabled
            status = "FAIL" if sse_status == "DISABLED" else "PASS"
            severity = "HIGH" if sse_status == "DISABLED" else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, severity, status,
                    {
                        "check": "sse_enabled",
                        "sse_status": sse_status,
                        "sse_type": sse.get("SSEType", "") if isinstance(sse, dict) else "",
                        "note": "DynamoDB tables use default encryption if SSE not explicitly configured",
                    },
                )
            )

        elif rtype == "keyspace":
            replication = ef.get("replicationStrategy", {}) or {}
            # Keyspaces encrypts at rest by default; check for custom KMS
            kms = ef.get("KmsKeyId", "")
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {
                        "check": "encryption",
                        "note": "Amazon Keyspaces encrypts at rest by default",
                        "custom_kms": bool(kms),
                        "keyspace_name": ef.get("keyspaceName", ""),
                    },
                )
            )

        elif rtype in ("database", "global_table"):
            kms = ef.get("KmsKeyId", ef.get("KmsKeyArn", ""))
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "MEDIUM" if not kms else "INFO",
                    "FAIL" if not kms else "PASS",
                    {"check": "kms_key_present", "kms_key": kms},
                )
            )

        return findings

    # ── Pillar 3: Authentication ──────────────────────────────────────────────

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Check IAM auth, password policies, default admin users."""
        findings = []
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"aws.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype in ("db_instance", "db_cluster"):
            iam_auth_enabled = ef.get("IAMDatabaseAuthenticationEnabled", False)
            if iam_auth_enabled is None:
                iam_auth_enabled = False
            master_user = ef.get("MasterUsername", "")
            default_users = {"admin", "root", "postgres", "mysql", "oracle", "sa", "masteruser"}

            status = "FAIL" if not iam_auth_enabled else "PASS"
            severity = "HIGH" if not iam_auth_enabled else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "iam_auth_enabled",
                        "iam_auth_enabled": bool(iam_auth_enabled),
                        "master_username": master_user,
                        "default_user_risk": master_user.lower() in default_users if master_user else False,
                    },
                )
            )

        elif rtype == "cluster":
            if not _is_db_cluster(ef):
                return []
            auth_token = ef.get("AuthTokenEnabled", None)
            if auth_token is not None:
                status = "FAIL" if not auth_token else "PASS"
                severity = "HIGH" if not auth_token else "INFO"
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource, rule_id,
                        PILLAR_AUTH, severity, status,
                        {"check": "auth_token_enabled", "auth_token_enabled": bool(auth_token)},
                    )
                )
            else:
                master = ef.get("MasterUsername", "")
                status = "FAIL" if not master else "PASS"
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource, rule_id,
                        PILLAR_AUTH, "MEDIUM", status,
                        {"check": "master_username_configured", "master_username": master},
                    )
                )

        elif rtype == "table":
            table_props = ef.get("TableProperties") or {}
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {
                        "check": "iam_controlled",
                        "note": "DynamoDB access inherently IAM-controlled",
                        "table_name": ef.get("TableName", ""),
                    },
                )
            )

        elif rtype == "keyspace":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "iam_controlled", "note": "Amazon Keyspaces uses IAM authentication"},
                )
            )

        elif rtype in ("database", "global_table"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "iam_controlled", "note": f"{rtype} uses IAM authentication"},
                )
            )

        return findings

    # ── Pillar 4: Audit & Activity ────────────────────────────────────────────

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Check CloudWatch logging and performance insights."""
        findings = []
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"aws.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype in ("db_instance", "db_cluster"):
            cw_logs = ef.get("EnabledCloudwatchLogsExports", []) or []
            perf_insights = ef.get("PerformanceInsightsEnabled", False)
            if perf_insights is None:
                perf_insights = False
            monitoring_interval = ef.get("MonitoringInterval", 0) or 0

            # CloudWatch logging check
            has_logs = bool(cw_logs)
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "HIGH" if not has_logs else "INFO",
                    "FAIL" if not has_logs else "PASS",
                    {
                        "check": "cloudwatch_logging",
                        "cw_logs_enabled": has_logs,
                        "enabled_log_types": list(cw_logs),
                        "performance_insights_enabled": bool(perf_insights),
                    },
                )
            )

            # Performance Insights — separate finding with unique rule_id
            pi_rule_id = f"aws.dbsec.{PILLAR_AUDIT}.{slug}.perf_insights"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    pi_rule_id, PILLAR_AUDIT,
                    "MEDIUM" if not perf_insights else "INFO",
                    "FAIL" if not perf_insights else "PASS",
                    {
                        "check": "performance_insights",
                        "performance_insights_enabled": bool(perf_insights),
                        "monitoring_interval_seconds": monitoring_interval,
                    },
                )
            )

        elif rtype == "cluster":
            if not _is_db_cluster(ef):
                return []
            log_delivery = ef.get("LogDeliveryConfigurations", []) or []
            has_logs = bool(log_delivery)
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "HIGH" if not has_logs else "INFO",
                    "FAIL" if not has_logs else "PASS",
                    {
                        "check": "log_delivery",
                        "log_delivery_configured": has_logs,
                        "log_configs": len(log_delivery),
                    },
                )
            )

        elif rtype == "table":
            # DynamoDB: CloudTrail logs all API calls by default
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {
                        "check": "cloudtrail_auditing",
                        "note": "DynamoDB API calls audited via CloudTrail by default",
                        "table_name": ef.get("TableName", ""),
                    },
                )
            )

        elif rtype == "keyspace":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {"check": "cloudtrail_auditing", "note": "Keyspaces operations audited via CloudTrail"},
                )
            )

        elif rtype in ("database", "global_table"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "MEDIUM", "FAIL",
                    {"check": "audit_logging", "note": f"{rtype} audit logging not determinable from discovery metadata"},
                )
            )

        return findings

    # ── Pillar 5: Compliance Posture ──────────────────────────────────────────

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        """Check backup retention, deletion protection, multi-AZ."""
        findings = []
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"aws.dbsec.{PILLAR_COMPLIANCE}.{slug}"

        if rtype in ("db_instance", "db_cluster"):
            backup_retention = ef.get("BackupRetentionPeriod", 0) or 0
            deletion_protection = ef.get("DeletionProtection", False)
            if deletion_protection is None:
                deletion_protection = False
            multi_az = ef.get("MultiAZ", False)
            if multi_az is None:
                multi_az = False
            auto_backup = ef.get("PreferredBackupWindow", "")

            # Backup retention
            bk_status = "FAIL" if backup_retention < 7 else "PASS"
            bk_severity = "HIGH" if backup_retention < 7 else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.backup", PILLAR_COMPLIANCE, bk_severity, bk_status,
                    {
                        "check": "backup_retention",
                        "backup_retention_days": backup_retention,
                        "preferred_backup_window": auto_backup,
                        "compliant_minimum": 7,
                    },
                )
            )

            # Deletion protection
            dp_status = "FAIL" if not deletion_protection else "PASS"
            dp_severity = "MEDIUM" if not deletion_protection else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.deletion_protection", PILLAR_COMPLIANCE,
                    dp_severity, dp_status,
                    {
                        "check": "deletion_protection",
                        "deletion_protection": bool(deletion_protection),
                    },
                )
            )

            # Multi-AZ
            maz_status = "FAIL" if not multi_az else "PASS"
            maz_severity = "MEDIUM" if not multi_az else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.multi_az", PILLAR_COMPLIANCE, maz_severity, maz_status,
                    {
                        "check": "multi_az",
                        "multi_az": bool(multi_az),
                        "availability_zone": ef.get("AvailabilityZone", ""),
                    },
                )
            )

        elif rtype == "cluster":
            if not _is_db_cluster(ef):
                return []
            # Redshift: AutomatedSnapshotRetentionPeriod
            retention = ef.get("AutomatedSnapshotRetentionPeriod", 0) or 0
            bk_status = "FAIL" if retention < 7 else "PASS"
            bk_severity = "HIGH" if retention < 7 else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.backup", PILLAR_COMPLIANCE, bk_severity, bk_status,
                    {
                        "check": "backup_retention",
                        "retention_period_days": retention,
                        "compliant_minimum": 7,
                    },
                )
            )

            # ElastiCache: SnapshotRetentionLimit
            snapshot_retention = ef.get("SnapshotRetentionLimit", None)
            if snapshot_retention is not None:
                sr_status = "FAIL" if snapshot_retention < 7 else "PASS"
                sr_severity = "HIGH" if snapshot_retention < 7 else "INFO"
                findings.append(
                    self._make_finding(
                        scan_run_id, tenant_id, account_id, resource,
                        f"{base_rule}.snapshot_retention", PILLAR_COMPLIANCE,
                        sr_severity, sr_status,
                        {
                            "check": "snapshot_retention",
                            "snapshot_retention_days": snapshot_retention,
                            "compliant_minimum": 7,
                        },
                    )
                )

        elif rtype == "table":
            # DynamoDB: PITR from TableProperties or direct field
            table_props = ef.get("TableProperties") or {}
            pitr = ef.get("ContinuousBackupsDescription") or table_props.get("ContinuousBackupsDescription") or {}
            pitr_desc = pitr.get("PointInTimeRecoveryDescription", {}) if isinstance(pitr, dict) else {}
            pitr_status_val = pitr_desc.get("PointInTimeRecoveryStatus", "DISABLED") if isinstance(pitr_desc, dict) else "DISABLED"
            pitr_enabled = pitr_status_val == "ENABLED"
            # If no PITR info in emitted_fields, conservatively report as FAIL
            status = "FAIL" if not pitr_enabled else "PASS"
            severity = "HIGH" if not pitr_enabled else "INFO"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.pitr", PILLAR_COMPLIANCE, severity, status,
                    {
                        "check": "pitr_enabled",
                        "pitr_enabled": pitr_enabled,
                        "pitr_status": pitr_status_val,
                        "table_name": ef.get("TableName", ""),
                    },
                )
            )

        elif rtype == "keyspace":
            # Keyspaces: check multi-region replication
            replication = ef.get("replicationStrategy", {}) or {}
            replication_strategy = replication.get("replicationStrategy", "") if isinstance(replication, dict) else ""
            is_multi_region = "MULTI" in str(replication_strategy).upper()
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.replication", PILLAR_COMPLIANCE,
                    "MEDIUM" if not is_multi_region else "INFO",
                    "FAIL" if not is_multi_region else "PASS",
                    {
                        "check": "multi_region_replication",
                        "replication_strategy": replication_strategy,
                        "multi_region": is_multi_region,
                    },
                )
            )

        elif rtype in ("database", "global_table"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.backup", PILLAR_COMPLIANCE,
                    "MEDIUM", "FAIL",
                    {"check": "backup_status", "note": f"{rtype} backup status not determinable from discovery metadata"},
                )
            )

        return findings
