"""AliCloud DBSec provider — RDS, PolarDB, MongoDB, Memcache, KMS, VPC, ECS.

Current AliCloud discovery catalog includes:
  - alicloud.kms/Key           (key management — encryption posture)
  - alicloud.ram/User          (identity — authentication posture)
  - alicloud.ram/Role          (role — authentication posture)
  - alicloud.ecs/SecurityGroup (network — exposure posture)
  - alicloud.vpc/Vpc           (network — isolation)
  - alicloud.actiontrail/Trail (audit — activity posture)

Dedicated RDS/PolarDB/MongoDB types are evaluated when discovered.
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

ALICLOUD_DB_RESOURCE_TYPES = [
    # Currently discovered types (produce findings now)
    "alicloud.kms/Key",
    "alicloud.ram/User",
    "alicloud.ram/Role",
    "alicloud.ecs/SecurityGroup",
    "alicloud.actiontrail/Trail",
    "alicloud.vpc/Vpc",
    # Dedicated DB types (evaluated when discovered)
    "RDS::DBInstance",
    "PolarDB::Cluster",
    "MongoDB::DBInstance",
    "Memcache::Instance",
    "rds_dbinstance",
    "polardb_cluster",
    "mongodb_dbinstance",
    "memcache_instance",
    "db_instance",
    "polardb",
]

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"

_PROXY_TYPES = {
    "alicloud.kms/Key",
    "alicloud.ram/User",
    "alicloud.ram/Role",
    "alicloud.ecs/SecurityGroup",
    "alicloud.actiontrail/Trail",
    "alicloud.vpc/Vpc",
}


class AliCloudDBSecProvider(BaseDBSecProvider):
    """AliCloud database security checks.

    Evaluates KMS keys, RAM users/roles, Security Groups, and ActionTrail
    as proxies for DB security posture when dedicated DB types are not yet
    in the discovery catalog.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return ALICLOUD_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "alicloud"

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"alicloud.dbsec.{PILLAR_NETWORK}.{slug}"

        if rtype == "alicloud.ecs/SecurityGroup":
            # Check if any inbound rules allow DB ports from 0.0.0.0/0
            permissions = ef.get("Permissions", ef.get("permissions", [])) or []
            db_ports = {3306, 5432, 1433, 27017, 6379, 9200, 9042, 1521}
            exposed_ports = []
            for perm in permissions:
                if not isinstance(perm, dict):
                    continue
                direction = str(perm.get("Direction", "")).lower()
                cidr = perm.get("SourceCidrIp", perm.get("sourceCidrIp", ""))
                port_range = perm.get("PortRange", perm.get("portRange", ""))
                if direction == "ingress" and cidr in ("0.0.0.0/0", "::/0"):
                    try:
                        start, end = (int(p) for p in str(port_range).split("/"))
                        for dp in db_ports:
                            if start <= dp <= end:
                                exposed_ports.append(dp)
                    except (ValueError, AttributeError):
                        pass

            is_exposed = bool(exposed_ports)
            status = "FAIL" if is_exposed else "PASS"
            severity = "CRITICAL" if is_exposed else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "db_ports_exposed",
                        "exposed_db_ports": exposed_ports,
                        "permission_count": len(permissions),
                        "note": "Security group with DB ports open to 0.0.0.0/0",
                    },
                )
            ]

        if rtype == "alicloud.vpc/Vpc":
            # VPC with default route or no isolation
            cidr = ef.get("CidrBlock", ef.get("cidrBlock", ""))
            status_val = ef.get("Status", ef.get("status", "Available"))
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {
                        "check": "vpc_isolation",
                        "cidr_block": cidr,
                        "vpc_status": status_val,
                        "note": "VPC provides network isolation for AliCloud DB resources",
                    },
                )
            ]

        if rtype in ("alicloud.kms/Key", "alicloud.ram/User", "alicloud.ram/Role", "alicloud.actiontrail/Trail"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} is not a network-exposed DB resource"},
                )
            ]

        # Dedicated RDS/PolarDB/MongoDB
        net_type = ef.get("DBInstanceNetType", ef.get("dbInstanceNetType", "Intranet"))
        is_internet = str(net_type).lower() in ("internet", "public")
        status = "FAIL" if is_internet else "PASS"
        severity = "CRITICAL" if is_internet else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status,
                {
                    "check": "network_type",
                    "db_instance_net_type": net_type,
                    "internet_accessible": is_internet,
                    "connection_string": ef.get("ConnectionString", ""),
                },
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"alicloud.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype == "alicloud.kms/Key":
            # Check key rotation and state
            key_state = ef.get("KeyState", ef.get("keyState", ""))
            rotation_enabled = ef.get("AutomaticRotation", ef.get("automaticRotation", "Disabled"))
            is_enabled = str(key_state).lower() == "enabled"
            rotation_on = str(rotation_enabled).lower() in ("enabled", "true")

            status = "FAIL" if not rotation_on else "PASS"
            severity = "HIGH" if not rotation_on else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, severity, status,
                    {
                        "check": "kms_key_rotation",
                        "key_state": key_state,
                        "key_enabled": is_enabled,
                        "automatic_rotation": rotation_on,
                        "note": "KMS keys without rotation reduce encryption effectiveness for DB data",
                    },
                )
            ]

        if rtype in ("alicloud.ram/User", "alicloud.ram/Role"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} is not a data encryption resource"},
                )
            ]

        if rtype in ("alicloud.ecs/SecurityGroup", "alicloud.vpc/Vpc", "alicloud.actiontrail/Trail"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} is not a data-at-rest encryption resource"},
                )
            ]

        # Dedicated RDS: TDE and SSL
        tde_status = ef.get("TDEStatus", ef.get("tdeStatus", "Disabled"))
        ssl_expired = ef.get("SSLExpireTime", ef.get("sslExpireTime", ""))
        ssl_enabled = bool(ssl_expired)
        tde_enabled = str(tde_status).lower() not in ("disabled", "false", "")

        encrypted = tde_enabled or ssl_enabled
        status = "FAIL" if not encrypted else "PASS"
        severity = "CRITICAL" if not encrypted else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, severity, status,
                {
                    "check": "tde_ssl_encryption",
                    "tde_enabled": tde_enabled,
                    "tde_status": tde_status,
                    "ssl_enabled": ssl_enabled,
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"alicloud.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype == "alicloud.ram/User":
            # Check MFA enabled and login profile
            mfa_enabled = ef.get("MFAEnabled", ef.get("mfaEnabled", False))
            if mfa_enabled is None:
                mfa_enabled = False
            console_login = ef.get("LoginProfile", ef.get("loginProfile", None))
            has_console_access = bool(console_login)

            # Non-MFA user with console access is HIGH risk
            no_mfa_risk = has_console_access and not mfa_enabled
            status = "FAIL" if no_mfa_risk else "PASS"
            severity = "HIGH" if no_mfa_risk else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "ram_user_mfa",
                        "mfa_enabled": bool(mfa_enabled),
                        "has_console_access": has_console_access,
                        "note": "RAM user with console access but no MFA can access DB credentials",
                    },
                )
            ]

        if rtype == "alicloud.ram/Role":
            # Check trust policy — overly permissive roles risk DB credential access
            trust_policy = ef.get("AssumeRolePolicyDocument", ef.get("assumeRolePolicyDocument", {})) or {}
            statements = trust_policy.get("Statement", []) if isinstance(trust_policy, dict) else []
            is_overly_permissive = any(
                stmt.get("Principal") in ("*", {"Service": "*"})
                for stmt in statements
                if isinstance(stmt, dict)
            )
            status = "FAIL" if is_overly_permissive else "PASS"
            severity = "HIGH" if is_overly_permissive else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "role_trust_policy",
                        "overly_permissive": is_overly_permissive,
                        "statement_count": len(statements),
                    },
                )
            ]

        if rtype in ("alicloud.ecs/SecurityGroup", "alicloud.vpc/Vpc",
                     "alicloud.kms/Key", "alicloud.actiontrail/Trail"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} authentication managed via RAM policies"},
                )
            ]

        # Dedicated RDS: master username check
        master_user = ef.get("MasterUserName", ef.get("masterUserName", ""))
        default_users = {"admin", "root", "test", "guest"}
        default_user_risk = master_user.lower() in default_users if master_user else False
        security_group = ef.get("SecurityGroupId", ef.get("securityGroupId", ""))

        status = "FAIL" if default_user_risk else "PASS"
        severity = "HIGH" if default_user_risk else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status,
                {
                    "check": "master_user_security",
                    "master_username": master_user,
                    "default_user_risk": default_user_risk,
                    "security_group_configured": bool(security_group),
                },
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"alicloud.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype == "alicloud.actiontrail/Trail":
            # ActionTrail is the AliCloud audit service
            trail_status = ef.get("Status", ef.get("status", ""))
            is_enabled = str(trail_status).lower() in ("enable", "enabled", "active")
            event_rw_type = ef.get("EventRW", ef.get("eventRw", "Write"))
            covers_all = str(event_rw_type).lower() == "all"

            # Trail not logging ALL events (read+write) is a gap
            gap = not is_enabled or not covers_all
            status = "FAIL" if gap else "PASS"
            severity = "HIGH" if not is_enabled else ("MEDIUM" if not covers_all else "INFO")
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, severity, status,
                    {
                        "check": "actiontrail_coverage",
                        "trail_enabled": is_enabled,
                        "event_rw_type": event_rw_type,
                        "covers_all_events": covers_all,
                        "note": "ActionTrail must log All (read+write) events for full DB audit coverage",
                    },
                )
            ]

        if rtype in ("alicloud.kms/Key", "alicloud.ram/User", "alicloud.ram/Role",
                     "alicloud.ecs/SecurityGroup", "alicloud.vpc/Vpc"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} audit covered by ActionTrail"},
                )
            ]

        # Dedicated RDS: SQL audit check
        sql_audit = ef.get("SQLAuditStatus", ef.get("sqlAuditStatus", ""))
        monitoring = ef.get("MonitoringPeriod", 0) or 0
        has_audit = bool(sql_audit) and str(sql_audit).lower() not in ("disabled", "false", "")

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, "HIGH" if not has_audit else "INFO",
                "FAIL" if not has_audit else "PASS",
                {
                    "check": "sql_audit",
                    "sql_audit_status": sql_audit,
                    "monitoring_period": monitoring,
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"alicloud.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        if rtype == "alicloud.actiontrail/Trail":
            # ActionTrail compliance: trail scope and S3 bucket retention
            is_organization_trail = ef.get("IsOrganizationTrail", ef.get("isOrganizationTrail", False))
            oss_bucket = ef.get("OssBucketName", ef.get("ossBucketName", ""))
            has_storage = bool(oss_bucket)
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.trail_storage", PILLAR_COMPLIANCE,
                    "HIGH" if not has_storage else "INFO",
                    "FAIL" if not has_storage else "PASS",
                    {
                        "check": "trail_oss_storage",
                        "oss_bucket": oss_bucket,
                        "has_persistent_storage": has_storage,
                        "organization_trail": bool(is_organization_trail),
                    },
                )
            )
            return findings

        if rtype == "alicloud.kms/Key":
            # KMS key deletion protection
            key_state = ef.get("KeyState", ef.get("keyState", ""))
            pending_delete = str(key_state).lower() == "pendingdeletion"
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.key_deletion", PILLAR_COMPLIANCE,
                    "HIGH" if pending_delete else "INFO",
                    "FAIL" if pending_delete else "PASS",
                    {
                        "check": "kms_key_pending_deletion",
                        "key_state": key_state,
                        "pending_deletion": pending_delete,
                        "note": "KMS key scheduled for deletion affects DB data decryption",
                    },
                )
            )
            return findings

        if rtype in ("alicloud.ram/User", "alicloud.ram/Role",
                     "alicloud.ecs/SecurityGroup", "alicloud.vpc/Vpc"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.iam_compliance", PILLAR_COMPLIANCE,
                    "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} compliance managed via RAM policies"},
                )
            )
            return findings

        # Dedicated RDS: backup retention and HA
        backup_retention = ef.get("BackupRetentionPeriod", ef.get("backupRetentionPeriod", 0))
        try:
            backup_retention = int(backup_retention)
        except (ValueError, TypeError):
            backup_retention = 0

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

        ha_mode = ef.get("DBInstanceType", ef.get("dbInstanceType", "Primary"))
        is_ha = (
            ha_mode.lower() in ("ha", "alwayson", "follower")
            or bool(ef.get("SlaveZones"))
        )
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.high_availability", PILLAR_COMPLIANCE,
                "MEDIUM", "FAIL" if not is_ha else "PASS",
                {"check": "high_availability", "db_instance_type": ha_mode, "ha_configured": is_ha},
            )
        )

        return findings
