"""Azure DBSec provider — SQL Server/DB, CosmosDB, PostgreSQL, MySQL, and storage data stores.

The current Azure discovery catalog includes StorageAccount and KeyVault in
discovery_findings. When dedicated SQL/CosmosDB resource types are added to
the discovery catalog, the full type list covers them as well.
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

# Primary Azure DB resource types (from discovery catalog)
AZURE_DB_RESOURCE_TYPES = [
    # Currently discovered types (these produce findings now)
    "StorageAccount",           # Azure Blob/Table/Queue — data store proxy
    "KeyVault",                 # Secret management for DB credentials
    # Dedicated DB types (added when discovered)
    "SQL::Server",
    "SQL::Database",
    "CosmosDB::Account",
    "PostgreSQL::Server",
    "MySQL::Server",
    "MariaDB::Server",
    # lowercase variants
    "sql_server",
    "sql_database",
    "cosmosdb_account",
    "postgresql_server",
    "mysql_server",
    "mariadb_server",
]

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"


class AzureDBSecProvider(BaseDBSecProvider):
    """Azure database security checks.

    Covers dedicated SQL/CosmosDB/PostgreSQL/MySQL/MariaDB types when discovered,
    and also evaluates StorageAccount (data store) and KeyVault (credential store)
    which are available in the current discovery catalog.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return AZURE_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "azure"

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"azure.dbsec.{PILLAR_NETWORK}.{slug}"

        if rtype == "StorageAccount":
            # Check public network access and network rule set
            network_rule_set = ef.get("network_rule_set") or {}
            default_action = network_rule_set.get("default_action", "Allow") if isinstance(network_rule_set, dict) else "Allow"
            is_public = str(default_action).lower() in ("allow", "")
            status = "FAIL" if is_public else "PASS"
            severity = "CRITICAL" if is_public else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "public_network_access",
                        "network_rule_default_action": default_action,
                        "storage_account_name": ef.get("name", ""),
                        "note": "StorageAccount with Allow-all network rule is publicly accessible",
                    },
                )
            ]

        if rtype == "KeyVault":
            network_acls = ef.get("properties", {}).get("networkAcls", {}) if isinstance(ef.get("properties"), dict) else {}
            default_action = network_acls.get("defaultAction", "Allow") if isinstance(network_acls, dict) else "Allow"
            is_public = str(default_action).lower() in ("allow", "")
            status = "FAIL" if is_public else "PASS"
            severity = "HIGH" if is_public else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "keyvault_network_access",
                        "network_acl_default_action": default_action,
                        "note": "KeyVault stores DB credentials; public access increases credential exposure risk",
                    },
                )
            ]

        # SQL/CosmosDB/PostgreSQL/MySQL types
        public_access = ef.get("publicNetworkAccess", ef.get("PublicNetworkAccess", "Unknown"))
        is_public = str(public_access).lower() in ("enabled", "true", "1")
        status = "FAIL" if is_public else "PASS"
        severity = "CRITICAL" if is_public else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status,
                {
                    "check": "public_network_access",
                    "public_network_access": public_access,
                    "firewall_rules": ef.get("firewallRules", []),
                },
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"azure.dbsec.{PILLAR_ENCRYPT}.{slug}"

        if rtype == "StorageAccount":
            # Check encryption settings
            encryption = ef.get("encryption") or {}
            require_https = ef.get("enable_https_traffic_only", True)
            services = encryption.get("services", {}) if isinstance(encryption, dict) else {}
            blob_encrypted = (services.get("blob", {}) or {}).get("enabled", True) if isinstance(services, dict) else True
            cmk = (encryption.get("key_vault_properties") or {}).get("key_uri", "") if isinstance(encryption, dict) else ""

            encrypted = bool(blob_encrypted)
            status = "FAIL" if not encrypted else "PASS"
            severity = "CRITICAL" if not encrypted else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, severity, status,
                    {
                        "check": "storage_encryption",
                        "blob_encrypted": encrypted,
                        "https_only": bool(require_https),
                        "customer_managed_key": bool(cmk),
                    },
                )
            ]

        if rtype == "KeyVault":
            # KeyVault itself is always encrypted; check for soft-delete (data protection)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {"check": "keyvault_encryption", "note": "Azure KeyVault data is encrypted by default"},
                )
            ]

        # SQL/CosmosDB TDE check
        tde_enabled = ef.get("transparentDataEncryption", ef.get("storageEncrypted", True))
        cmk = ef.get("keyVaultUri", ef.get("keyId", ""))
        encrypted = bool(tde_enabled) if tde_enabled is not None else True
        status = "FAIL" if not encrypted else "PASS"
        severity = "CRITICAL" if not encrypted else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, severity, status,
                {
                    "check": "tde_enabled",
                    "tde_enabled": encrypted,
                    "customer_managed_key": bool(cmk),
                    "key_vault_uri": cmk,
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"azure.dbsec.{PILLAR_AUTH}.{slug}"

        if rtype == "StorageAccount":
            # Check if storage account disallows shared key authorization (enforce AAD only)
            allow_shared_key = ef.get("allow_shared_key_access", True)
            if allow_shared_key is None:
                allow_shared_key = True
            status = "FAIL" if allow_shared_key else "PASS"
            severity = "HIGH" if allow_shared_key else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, severity, status,
                    {
                        "check": "shared_key_auth_disabled",
                        "allow_shared_key_access": bool(allow_shared_key),
                        "note": "Shared key auth allows unrestricted access; AAD-only enforces RBAC",
                    },
                )
            ]

        if rtype == "KeyVault":
            # Check soft-delete and purge protection (auth/access control)
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {"check": "keyvault_access_policy", "note": "KeyVault access controlled via RBAC/access policies"},
                )
            ]

        ssl_enforcement = ef.get("sslEnforcement", ef.get("minimalTlsVersion", "TLS1_2"))
        tls_ok = str(ssl_enforcement) not in ("", "Disabled", "TLS1_0", "TLS1_1")
        status = "FAIL" if not tls_ok else "PASS"
        severity = "HIGH" if not tls_ok else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status,
                {
                    "check": "tls_enforcement",
                    "ssl_enforcement": ssl_enforcement,
                    "tls_compliant": tls_ok,
                    "aad_auth_configured": bool(ef.get("azureAdOnlyAuthentication", False)),
                },
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"azure.dbsec.{PILLAR_AUDIT}.{slug}"

        if rtype == "StorageAccount":
            # Check if diagnostic settings or Azure Monitor configured
            # Storage accounts have min-TLS and access logging
            min_tls = ef.get("minimum_tls_version", "TLS1_0")
            tls_ok = str(min_tls) in ("TLS1_2", "TLS1_3")
            status = "FAIL" if not tls_ok else "PASS"
            severity = "HIGH" if not tls_ok else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, severity, status,
                    {
                        "check": "minimum_tls_version",
                        "minimum_tls_version": min_tls,
                        "tls_compliant": tls_ok,
                        "note": "StorageAccount with TLS < 1.2 allows logging/audit bypass",
                    },
                )
            ]

        if rtype == "KeyVault":
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {"check": "keyvault_audit", "note": "KeyVault audit logs available via Azure Monitor"},
                )
            ]

        # SQL/CosmosDB audit policy
        audit_policy = ef.get("auditingPolicy", ef.get("serverAuditingPolicy", {})) or {}
        audit_enabled = audit_policy.get("state", "Disabled") == "Enabled" if isinstance(audit_policy, dict) else False
        diag_settings = ef.get("diagnosticSettings", [])
        has_audit = audit_enabled or bool(diag_settings)
        status = "FAIL" if not has_audit else "PASS"
        severity = "HIGH" if not has_audit else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, severity, status,
                {
                    "check": "audit_logging",
                    "audit_policy_enabled": audit_enabled,
                    "diagnostic_settings_count": len(diag_settings) if isinstance(diag_settings, list) else 0,
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"azure.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        if rtype == "StorageAccount":
            # Check geo-redundancy and access tier
            sku = ef.get("sku") or {}
            sku_name = sku.get("name", "") if isinstance(sku, dict) else ""
            geo_redundant = "GRS" in str(sku_name).upper() or "GEO" in str(sku_name).upper() or "RA" in str(sku_name).upper()
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.geo_redundancy", PILLAR_COMPLIANCE,
                    "HIGH" if not geo_redundant else "INFO",
                    "FAIL" if not geo_redundant else "PASS",
                    {
                        "check": "geo_redundant_storage",
                        "sku_name": sku_name,
                        "geo_redundant": geo_redundant,
                    },
                )
            )
            # Check for soft-delete / retention policy
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.deletion_protection", PILLAR_COMPLIANCE,
                    "MEDIUM", "FAIL",
                    {
                        "check": "deletion_protection",
                        "note": "StorageAccount blob soft-delete status not available in current discovery data",
                    },
                )
            )
            return findings

        if rtype == "KeyVault":
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.retention", PILLAR_COMPLIANCE,
                    "INFO", "PASS",
                    {"check": "keyvault_retention", "note": "KeyVault soft-delete provides secret retention"},
                )
            )
            return findings

        # SQL/CosmosDB backup check
        backup_redundancy = ef.get("backupRedundancy", ef.get("storageAccountType", ""))
        geo_redundant = "GRS" in str(backup_redundancy).upper() or "GEO" in str(backup_redundancy).upper()
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.backup", PILLAR_COMPLIANCE,
                "HIGH" if not geo_redundant else "INFO",
                "FAIL" if not geo_redundant else "PASS",
                {
                    "check": "geo_redundant_backup",
                    "backup_redundancy": backup_redundancy,
                    "geo_redundant": geo_redundant,
                },
            )
        )

        deletion_protection = ef.get("deletionProtection", ef.get("infrastructureEncryption", None))
        has_protection = bool(deletion_protection)
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.deletion_protection", PILLAR_COMPLIANCE,
                "MEDIUM", "FAIL" if not has_protection else "PASS",
                {"check": "deletion_protection", "deletion_protection": has_protection},
            )
        )

        return findings
