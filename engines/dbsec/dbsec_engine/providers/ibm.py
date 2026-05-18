"""IBM Cloud DBSec provider — Databases for PostgreSQL/MongoDB/Redis, Cloudant, Db2.

IBM Cloud discovery catalog includes:
  - ibm.databases.*     (IBM Cloud Databases — PostgreSQL, MongoDB, Redis, RabbitMQ, etc.)
  - ibm.cloudant.*      (Cloudant NoSQL document store)
  - ibm.db2.*           (Db2 on Cloud)
  - ibm.key_protect.*   (Key Protect — encryption posture proxy)
  - ibm.iam.*           (IAM users and policies — authentication proxy)
  - ibm.activity_tracker.* (Activity Tracker — audit posture proxy)
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

IBM_DB_RESOURCE_TYPES = [
    # IBM Cloud Databases (ICD) — managed DB services
    "ibm.databases/DatabaseDeployment",
    "ibm.databases/Instance",
    "databases_for_postgresql",
    "databases_for_mongodb",
    "databases_for_redis",
    "databases_for_elasticsearch",
    "databases_for_etcd",
    "databases_for_rabbitmq",
    "messages_for_rabbitmq",
    # Cloudant
    "ibm.cloudant/Instance",
    "cloudant_instance",
    # Db2
    "ibm.db2/Instance",
    "db2_instance",
    # Proxy types for posture analysis
    "ibm.key_protect/Key",
    "ibm.iam/User",
    "ibm.iam/ServiceID",
    "ibm.activity_tracker/Instance",
]

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"

_PROXY_TYPES = {
    "ibm.key_protect/Key",
    "ibm.iam/User",
    "ibm.iam/ServiceID",
    "ibm.activity_tracker/Instance",
}


class IBMDBSecProvider(BaseDBSecProvider):
    """IBM Cloud database security checks.

    Evaluates IBM Cloud Databases (ICD), Cloudant, Db2 alongside Key Protect,
    IAM, and Activity Tracker as posture proxies when dedicated DB types
    are not yet fully covered by the discovery catalog.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return IBM_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "ibm"

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"ibm.dbsec.{PILLAR_NETWORK}.{slug}"

        # Proxy types — not network-exposed DB resources
        if rtype in _PROXY_TYPES:
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} is not a network-exposed DB resource"},
                )
            ]

        # ICD / Cloudant / Db2 — check if public endpoints are enabled
        public_endpoints = ef.get("public_connections_enabled",
                                   ef.get("publicEndpointsEnabled",
                                   ef.get("public_endpoint_enabled", False)))
        # IBM Cloudant: check if CORS allows all origins
        cors_enabled = ef.get("cors_enabled", ef.get("corsEnabled", False))
        cors_allow_all = ef.get("cors_allow_origins", []) == ["*"]

        is_exposed = bool(public_endpoints) or (bool(cors_enabled) and cors_allow_all)
        severity = "CRITICAL" if is_exposed else "INFO"
        status = "FAIL" if is_exposed else "PASS"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status,
                {
                    "check": "public_endpoint_exposure",
                    "public_endpoints_enabled": bool(public_endpoints),
                    "cors_allow_all_origins": cors_allow_all,
                    "note": "IBM Cloud DB with public endpoints reachable without VPN/private network",
                },
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"ibm.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype == "ibm.key_protect/Key":
            # Key Protect: check rotation policy
            rotation_interval = ef.get("rotation_interval", ef.get("rotationInterval", 0))
            key_state = ef.get("state", ef.get("keyState", "active"))
            try:
                rotation_months = int(rotation_interval)
            except (TypeError, ValueError):
                rotation_months = 0
            no_rotation = rotation_months == 0
            status = "FAIL" if no_rotation else "PASS"
            severity = "HIGH" if no_rotation else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, severity, status,
                    {
                        "check": "key_protect_rotation",
                        "rotation_interval_months": rotation_months,
                        "key_state": key_state,
                        "note": "Key Protect keys without rotation policy reduce encryption strength for IBM DB data",
                    },
                )
            ]

        if rtype in ("ibm.iam/User", "ibm.iam/ServiceID", "ibm.activity_tracker/Instance"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} is not a data encryption resource"},
                )
            ]

        # ICD: check encryption at rest via customer-managed keys (BYOK)
        encryption_key = ef.get("disk_encryption_key_id",
                                 ef.get("encryptionKeyId",
                                 ef.get("encryption_key", "")))
        tls_version = ef.get("tls_version", ef.get("tlsVersion", ef.get("minimum_tls_protocol", "")))
        byok = bool(encryption_key)
        has_tls = bool(tls_version) and str(tls_version).replace(".", "").isdigit()

        encrypted = byok or has_tls
        status = "FAIL" if not encrypted else "PASS"
        severity = "CRITICAL" if not encrypted else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, severity, status,
                {
                    "check": "encryption_at_rest_and_transit",
                    "byok_encryption": byok,
                    "encryption_key_id": str(encryption_key)[:64] if encryption_key else None,
                    "tls_version": tls_version,
                    "in_transit_tls": has_tls,
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"ibm.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype == "ibm.iam/User":
            # IBM IAM: check MFA settings
            mfa_enabled = ef.get("iam_id", "") != "" and ef.get("mfa", ef.get("mfaEnabled", False))
            api_key_count = ef.get("apikeys_count", ef.get("apiKeysCount", 0))
            # Long-lived API keys without MFA are high risk
            has_api_keys = int(api_key_count) > 0 if api_key_count else False
            risk = has_api_keys and not mfa_enabled
            status = "FAIL" if risk else "PASS"
            severity = "HIGH" if risk else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "iam_user_mfa",
                        "mfa_enabled": bool(mfa_enabled),
                        "api_key_count": int(api_key_count) if api_key_count else 0,
                        "note": "IBM IAM user with API keys but no MFA can access DB credentials",
                    },
                )
            ]

        if rtype == "ibm.iam/ServiceID":
            # Service IDs: check for overly permissive API keys
            locked = ef.get("locked", False)
            description = ef.get("description", "")
            has_admin_hint = any(w in str(description).lower() for w in ("admin", "full access", "all resources"))
            status = "FAIL" if (not locked and has_admin_hint) else "PASS"
            severity = "MEDIUM" if (not locked and has_admin_hint) else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "service_id_permissions",
                        "is_locked": bool(locked),
                        "admin_hint_in_description": has_admin_hint,
                        "note": "Unlocked Service ID with potential admin access to DB resources",
                    },
                )
            ]

        if rtype in ("ibm.key_protect/Key", "ibm.activity_tracker/Instance"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} authentication managed via IBM IAM"},
                )
            ]

        # ICD / Cloudant / Db2 — check authentication method
        auth_type = ef.get("authentication_method",
                            ef.get("authType",
                            ef.get("auth_method", "")))
        has_iam_auth = "iam" in str(auth_type).lower() or ef.get("iam_authentication", False)
        admin_user = ef.get("admin_user", ef.get("adminUser", ef.get("admin_username", "")))
        default_users = {"admin", "root", "ibmcloud", "ibmadmin", "cloudant", "db2inst1"}
        default_cred_risk = str(admin_user).lower() in default_users if admin_user else False

        risk = default_cred_risk or not has_iam_auth
        status = "FAIL" if risk else "PASS"
        severity = "HIGH" if default_cred_risk else ("MEDIUM" if not has_iam_auth else "INFO")

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status,
                {
                    "check": "db_authentication",
                    "iam_auth_enabled": has_iam_auth,
                    "auth_method": auth_type,
                    "default_credentials_risk": default_cred_risk,
                },
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"ibm.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype == "ibm.activity_tracker/Instance":
            # Activity Tracker: check if it covers the target region and is enabled
            activity_tracking_state = ef.get("state", ef.get("status", "active"))
            is_active = str(activity_tracking_state).lower() in ("active", "provisioned", "running")
            region = ef.get("region_id", ef.get("region", ""))

            status = "FAIL" if not is_active else "PASS"
            severity = "HIGH" if not is_active else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, severity, status,
                    {
                        "check": "activity_tracker_active",
                        "tracker_state": activity_tracking_state,
                        "region": region,
                        "note": "Activity Tracker must be active for full IBM Cloud DB audit coverage",
                    },
                )
            ]

        if rtype in ("ibm.key_protect/Key", "ibm.iam/User", "ibm.iam/ServiceID"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} audit covered by Activity Tracker"},
                )
            ]

        # ICD / Cloudant / Db2 — check logging enabled
        logging_enabled = ef.get("logging_enabled",
                                   ef.get("loggingEnabled",
                                   ef.get("audit_logging", False)))
        log_destination = ef.get("log_destination", ef.get("logDestination", ""))

        has_audit = bool(logging_enabled)
        status = "FAIL" if not has_audit else "PASS"
        severity = "HIGH" if not has_audit else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, severity, status,
                {
                    "check": "db_audit_logging",
                    "logging_enabled": has_audit,
                    "log_destination": log_destination,
                    "note": "IBM Cloud DB without audit logging cannot detect unauthorized access patterns",
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"ibm.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        if rtype == "ibm.key_protect/Key":
            key_state = ef.get("state", ef.get("keyState", "active"))
            deactivated = str(key_state).lower() in ("deactivated", "destroyed", "purged")
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.key_state", PILLAR_COMPLIANCE,
                    "CRITICAL" if deactivated else "INFO",
                    "FAIL" if deactivated else "PASS",
                    {
                        "check": "key_protect_key_state",
                        "key_state": key_state,
                        "deactivated_or_destroyed": deactivated,
                        "note": "Deactivated/destroyed Key Protect key prevents decryption of IBM DB data",
                    },
                )
            )
            return findings

        if rtype == "ibm.activity_tracker/Instance":
            # Check Activity Tracker has a LogDNA/Log Analysis destination (persistent storage)
            cos_bucket = ef.get("cos_bucket", ef.get("cosBucket", ""))
            has_persistent = bool(cos_bucket)
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.persistent_storage", PILLAR_COMPLIANCE,
                    "HIGH" if not has_persistent else "INFO",
                    "FAIL" if not has_persistent else "PASS",
                    {
                        "check": "activity_tracker_cos_archival",
                        "cos_bucket": cos_bucket,
                        "has_persistent_archival": has_persistent,
                        "note": "Activity Tracker without COS archival loses audit trail after 30 days",
                    },
                )
            )
            return findings

        if rtype in ("ibm.iam/User", "ibm.iam/ServiceID"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.iam_compliance", PILLAR_COMPLIANCE,
                    "INFO", "PASS",
                    {"check": "not_applicable", "note": f"{rtype} compliance managed via IBM IAM policy"},
                )
            )
            return findings

        # ICD / Cloudant / Db2 — backup retention and HA
        backup_retention = ef.get("backup_retention_days",
                                   ef.get("backupRetentionDays",
                                   ef.get("backup_retention_period", 0)))
        try:
            backup_days = int(backup_retention)
        except (TypeError, ValueError):
            backup_days = 0

        bk_status = "FAIL" if backup_days < 7 else "PASS"
        bk_severity = "HIGH" if backup_days < 7 else "INFO"
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.backup_retention", PILLAR_COMPLIANCE, bk_severity, bk_status,
                {
                    "check": "backup_retention",
                    "backup_retention_days": backup_days,
                    "compliant_minimum": 7,
                    "note": "IBM Cloud DB backup retention < 7 days violates basic recovery SLAs",
                },
            )
        )

        # HA: check if multi-zone or read replica configured
        members_count = ef.get("members_count", ef.get("membersCount", ef.get("replicas", 1)))
        try:
            members = int(members_count)
        except (TypeError, ValueError):
            members = 1
        is_ha = members > 1 or bool(ef.get("multi_zone", ef.get("multiZone", False)))

        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.high_availability", PILLAR_COMPLIANCE,
                "MEDIUM", "FAIL" if not is_ha else "PASS",
                {
                    "check": "high_availability",
                    "members_count": members,
                    "multi_zone": bool(ef.get("multi_zone", ef.get("multiZone", False))),
                    "ha_configured": is_ha,
                },
            )
        )

        return findings
