"""
Azure Discovery Scanner

DB-driven multi-service discovery for Azure subscriptions.
Service enumeration is driven by rule_discoveries table — no hardcoded handlers.

Authentication: ClientSecretCredential resolved from AWS Secrets Manager
via credential_ref (e.g. 'threat-engine/azure/{subscription_id}').

Implementation stories:
  AZ-01/AZ-01b  — this skeleton
  AZ-02          — AzureClientFactory (client_factory.py)
  AZ-02b         — _call_with_timeout
  AZ-04          — scan_service, extract_resource_identifier, normalize
  AZ-17b         — _resolve_credentials (Secrets Manager → ClientSecretCredential)
"""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List, Optional

from common.models.provider_interface import (
    AuthenticationError,
    DiscoveryError,
    DiscoveryScanner,
)
from providers.azure.client_factory import AzureClientFactory
from providers.azure.pagination import azure_list_all

logger = logging.getLogger(__name__)

# Per-call timeout (seconds) — matches AWS scanner OPERATION_TIMEOUT
OPERATION_TIMEOUT = 10

# Thread pool for blocking Azure SDK calls
_AZURE_EXECUTOR = ThreadPoolExecutor(max_workers=10, thread_name_prefix="azure-sdk")

# Normalize Azure resource type strings → short names for downstream engines
_RESOURCE_TYPE_MAP: Dict[str, str] = {
    "Microsoft.Compute/virtualMachines":              "VirtualMachine",
    "Microsoft.Compute/virtualMachineScaleSets":      "VMSS",
    "Microsoft.Compute/disks":                        "ManagedDisk",
    "Microsoft.Compute/snapshots":                    "Snapshot",
    "Microsoft.Network/virtualNetworks":              "VirtualNetwork",
    "Microsoft.Network/networkSecurityGroups":        "NetworkSecurityGroup",
    "Microsoft.Network/loadBalancers":                "LoadBalancer",
    "Microsoft.Network/applicationGateways":          "ApplicationGateway",
    "Microsoft.Network/subnets":                      "Subnet",
    "Microsoft.Network/publicIPAddresses":            "PublicIPAddress",
    "Microsoft.Network/networkInterfaces":            "NetworkInterface",
    "Microsoft.Network/firewallPolicies":             "FirewallPolicy",
    "Microsoft.Storage/storageAccounts":              "StorageAccount",
    "Microsoft.KeyVault/vaults":                      "KeyVault",
    "Microsoft.Sql/servers":                          "SQLServer",
    "Microsoft.Sql/servers/databases":                "SQLDatabase",
    "Microsoft.ContainerService/managedClusters":     "AKSCluster",
    "Microsoft.Web/sites":                            "AppService",
    "Microsoft.DocumentDB/databaseAccounts":          "CosmosDB",
    "Microsoft.DBforPostgreSQL/servers":              "PostgreSQLServer",
    "Microsoft.DBforMySQL/servers":                   "MySQLServer",
    "Microsoft.Authorization/roleAssignments":        "RoleAssignment",
    "Microsoft.Authorization/roleDefinitions":        "RoleDefinition",
    "Microsoft.Insights/activityLogAlerts":           "ActivityLogAlert",
    "Microsoft.Insights/diagnosticSettings":          "DiagnosticSetting",
    "Microsoft.Security/securityContacts":            "SecurityContact",
    "Microsoft.Security/pricings":                    "SecurityPricing",
}


# ─── Service Handler Registry ──────────────────────────────────────────────────
#
# Each handler: fn(factory, subscription_id, region) -> List[Dict]
# Handlers call Azure SDK directly — no DB config parsing needed.
# Add new services by defining a handler and decorating with @azure_handler.
#
AZURE_SERVICE_HANDLERS: Dict[str, Any] = {}


def azure_handler(service_name: str):
    """Decorator to register an Azure service discovery handler."""
    def decorator(fn):
        AZURE_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


def _enrich_azure_item(item: Dict, service: str, subscription_id: str,
                       discovery_id: Optional[str] = None) -> Dict:
    """Inject standard resource identifier fields from Azure SDK as_dict() output."""
    resource_uid = item.get("id", "")
    raw_type = item.get("type", "")
    resource_type = _RESOURCE_TYPE_MAP.get(raw_type) or raw_type or service
    item["resource_uid"] = resource_uid
    item["resource_id"] = resource_uid
    item["resource_type"] = resource_type
    item["resource_name"] = item.get("name", "")
    item["account_id"] = subscription_id
    if discovery_id:
        item["_discovery_id"] = discovery_id
    item["_raw_response"] = {k: v for k, v in item.items()
                             if not k.startswith("_") and k not in
                             ("resource_uid", "resource_id", "resource_type",
                              "resource_name", "account_id")}
    return item


# ─── Service Handlers ──────────────────────────────────────────────────────────

@azure_handler("compute")
def _scan_compute(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("compute")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.virtual_machines.list_all):
        if _normalize_location(item.get("location", "")) == region_norm:
            resources.append(_enrich_azure_item(item, "compute", subscription_id,
                                                discovery_id="azure.compute.virtualmachines.list"))
    logger.info("  compute/%s: %d VMs found", region, len(resources))
    return resources


@azure_handler("storage")
def _scan_storage(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("storage")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.storage_accounts.list):
        if _normalize_location(item.get("location", "")) != region_norm:
            continue
        # Fetch full storage account properties (encryption, blob access, etc.)
        # storage_accounts.list() returns only basic metadata; get_properties() returns full config.
        try:
            vault_id = item.get("id", "")
            id_parts = vault_id.split("/")
            rg_index = next((i for i, p in enumerate(id_parts) if p.lower() == "resourcegroups"), None)
            if rg_index is not None and rg_index + 1 < len(id_parts):
                rg_name = id_parts[rg_index + 1]
                account_name = item.get("name", "")
                full_account = client.storage_accounts.get_properties(rg_name, account_name)
                if hasattr(full_account, "as_dict"):
                    item = full_account.as_dict()
        except Exception as _e:
            logger.debug("storage get_properties(%s) failed, using list data: %s", item.get("name"), _e)
        resources.append(_enrich_azure_item(item, "storage", subscription_id,
                                            discovery_id="azure.storage.storageaccounts.list"))
    logger.info("  storage/%s: %d accounts found", region, len(resources))
    return resources


@azure_handler("network")
def _scan_network(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("network")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for method, label, disc_id in [
        (client.virtual_networks.list_all,        "vnets", "azure.network.virtualnetworks.list_all"),
        (client.network_security_groups.list_all,  "nsgs",  "azure.network.networksecuritygroups.list_all"),
        (client.public_ip_addresses.list_all,      "pips",  "azure.network.publicipaddresses.list_all"),
        (client.load_balancers.list_all,           "lbs",   "azure.network.loadbalancers.list_all"),
    ]:
        try:
            for item in azure_list_all(method):
                if _normalize_location(item.get("location", "")) == region_norm:
                    resources.append(_enrich_azure_item(item, "network", subscription_id,
                                                        discovery_id=disc_id))
        except Exception as exc:
            logger.warning("  network/%s %s failed: %s", region, label, exc)
    logger.info("  network/%s: %d resources found", region, len(resources))
    return resources


@azure_handler("keyvault")
def _scan_keyvault(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("keyvault")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.vaults.list):
        if _normalize_location(item.get("location", "")) != region_norm:
            continue
        # Fetch full vault properties (SKU, enableSoftDelete, accessPolicies, etc.)
        # The list operation only returns basic metadata; get() returns full properties.
        try:
            vault_id = item.get("id", "")
            # Parse resource group from ID:
            # /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}
            id_parts = vault_id.split("/")
            rg_index = next((i for i, p in enumerate(id_parts) if p.lower() == "resourcegroups"), None)
            if rg_index is not None and rg_index + 1 < len(id_parts):
                rg_name = id_parts[rg_index + 1]
                vault_name = item.get("name", "")
                full_vault = client.vaults.get(rg_name, vault_name)
                if hasattr(full_vault, "as_dict"):
                    item = full_vault.as_dict()
        except Exception as _e:
            logger.debug("keyvault get(%s) failed, using list data: %s", item.get("name"), _e)
        resources.append(_enrich_azure_item(item, "keyvault", subscription_id,
                                            discovery_id="azure.keyvault.vaults.list_by_subscription"))
    logger.info("  keyvault/%s: %d vaults found", region, len(resources))
    return resources


@azure_handler("sql")
def _scan_sql(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("sql")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for server in azure_list_all(client.servers.list):
        if _normalize_location(server.get("location", "")) == region_norm:
            resources.append(_enrich_azure_item(server, "sql", subscription_id,
                                                discovery_id="azure.sql.servers.list"))
    logger.info("  sql/%s: %d servers found", region, len(resources))
    return resources


@azure_handler("authorization")
def _scan_authorization(factory, subscription_id: str, region: str) -> List[Dict]:
    # Role assignments/definitions are global — only scan once (eastus equivalent)
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("authorization")
    resources = []
    for item in azure_list_all(client.role_assignments.list_for_subscription):
        resources.append(_enrich_azure_item(item, "authorization", subscription_id,
                                            discovery_id="azure.authorization.roleassignments.list_for_subscription"))
    logger.info("  authorization: %d role assignments found", len(resources))
    return resources


@azure_handler("security")
def _scan_security(factory, subscription_id: str, region: str) -> List[Dict]:
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("security")
    resources = []
    for method, label, disc_id in [
        (lambda: client.security_contacts.list(), "contacts", "azure.security.root.list"),
        (lambda: client.pricings.list(), "pricings", "azure.security.tasks.list"),
    ]:
        try:
            for item in azure_list_all(method):
                resources.append(_enrich_azure_item(item, "security", subscription_id,
                                                    discovery_id=disc_id))
        except Exception as exc:
            logger.warning("  security %s failed: %s", label, exc)
    logger.info("  security: %d resources found", len(resources))
    return resources


@azure_handler("monitor")
def _scan_monitor(factory, subscription_id: str, region: str) -> List[Dict]:
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("monitor")
    resources = []
    try:
        for item in azure_list_all(client.activity_log_alerts.list_by_subscription_id):
            resources.append(_enrich_azure_item(item, "monitor", subscription_id,
                                                discovery_id="azure.monitor.activitylogalerts.list_by_resource_group"))
    except Exception as exc:
        logger.warning("  monitor activity_log_alerts failed: %s", exc)
    logger.info("  monitor: %d resources found", len(resources))
    return resources


@azure_handler("resource")
def _scan_resource(factory, subscription_id: str, region: str) -> List[Dict]:
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("resource")
    resources = []
    for item in azure_list_all(client.resource_groups.list):
        resources.append(_enrich_azure_item(item, "resource", subscription_id,
                                            discovery_id="azure.resources.resources.resources_list"))
    logger.info("  resource: %d resource groups found", len(resources))
    return resources


@azure_handler("containerservice")
def _scan_containerservice(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("containerservice")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.managed_clusters.list):
        if _normalize_location(item.get("location", "")) == region_norm:
            resources.append(_enrich_azure_item(item, "containerservice", subscription_id,
                                                discovery_id="azure.containerservice.managedclusters.list"))
    logger.info("  containerservice/%s: %d AKS clusters found", region, len(resources))
    return resources


@azure_handler("web")
def _scan_web(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("web")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.web_apps.list):
        if _normalize_location(item.get("location", "")) != region_norm:
            continue
        # Fetch full web app config (site_config, virtualNetworkSubnetId, etc.)
        # web_apps.list() returns only basic metadata; web_apps.get(rg, name) returns full config.
        try:
            app_id = item.get("id", "")
            id_parts = app_id.split("/")
            rg_index = next((i for i, p in enumerate(id_parts) if p.lower() == "resourcegroups"), None)
            if rg_index is not None and rg_index + 1 < len(id_parts):
                rg_name = id_parts[rg_index + 1]
                app_name = item.get("name", "")
                full_app = client.web_apps.get(rg_name, app_name)
                if hasattr(full_app, "as_dict"):
                    item = full_app.as_dict()
        except Exception as _e:
            logger.debug("web_apps.get(%s) failed, using list data: %s", item.get("name"), _e)
        resources.append(_enrich_azure_item(item, "web", subscription_id,
                                            discovery_id="azure.web.webapps.list"))
    logger.info("  web/%s: %d app services found", region, len(resources))
    return resources


@azure_handler("cosmosdb")
def _scan_cosmosdb(factory, subscription_id: str, region: str) -> List[Dict]:
    client = factory.get_client("cosmosdb")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.database_accounts.list):
        if _normalize_location(item.get("location", "")) == region_norm:
            resources.append(_enrich_azure_item(item, "cosmosdb", subscription_id,
                                                discovery_id="azure.cosmosdb.databaseaccounts.list"))
    logger.info("  cosmosdb/%s: %d accounts found", region, len(resources))
    return resources


@azure_handler("dns")
def _scan_dns(factory, subscription_id: str, region: str) -> List[Dict]:
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("dns")
    resources = []
    for item in azure_list_all(client.zones.list):
        resources.append(_enrich_azure_item(item, "dns", subscription_id,
                                            discovery_id="azure.dns.zones.list"))
    logger.info("  dns: %d zones found", len(resources))
    return resources


@azure_handler("disk")
def _scan_disk(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure managed disks."""
    client = factory.get_client("compute")
    region_norm = region.lower().replace(" ", "")
    resources = []
    for item in azure_list_all(client.disks.list):
        if _normalize_location(item.get("location", "")) == region_norm:
            resources.append(_enrich_azure_item(item, "disk", subscription_id,
                                                discovery_id="azure.compute.disks.list"))
    logger.info("  disk/%s: %d managed disks found", region, len(resources))
    return resources


@azure_handler("securitycenter")
def _scan_securitycenter(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure Security Center / Defender for Cloud settings."""
    if region not in ("eastus", "global"):
        return []
    client = factory.get_client("security")
    resources = []
    for method, label in [
        (lambda: client.pricings.list(), "pricings"),
        (lambda: client.security_contacts.list(), "contacts"),
        (lambda: client.settings.list(), "settings"),
    ]:
        try:
            for item in azure_list_all(method):
                resources.append(_enrich_azure_item(item, "securitycenter", subscription_id,
                                                    discovery_id="azure.securitycenter.list"))
        except Exception as exc:
            logger.debug("  securitycenter %s failed: %s", label, exc)
    logger.info("  securitycenter: %d resources found", len(resources))
    return resources


@azure_handler("postgresql")
def _scan_postgresql(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure PostgreSQL servers (single server and flexible server)."""
    region_norm = region.lower().replace(" ", "")
    resources = []
    # Single server
    try:
        client = factory.get_client("postgresql")
        for item in azure_list_all(client.servers.list):
            if _normalize_location(item.get("location", "")) == region_norm:
                enriched = _enrich_azure_item(item, "postgresql", subscription_id,
                                              discovery_id="azure.postgresql.servers.servers_list")
                resources.append(enriched)
                dup = dict(enriched)
                dup["_discovery_id"] = "azure.rdbms_postgresql.servers.list"
                resources.append(dup)
    except Exception as exc:
        logger.debug("  postgresql single server failed: %s", exc)
    # Flexible server
    try:
        client = factory.get_client("postgresql_flex")
        for item in azure_list_all(client.servers.list):
            if _normalize_location(item.get("location", "")) == region_norm:
                resources.append(_enrich_azure_item(item, "postgresql", subscription_id,
                                                    discovery_id="azure.postgresql.servers.servers_list"))
    except Exception as exc:
        logger.debug("  postgresql flexible server failed: %s", exc)
    logger.info("  postgresql/%s: %d servers found", region, len(resources))
    return resources


@azure_handler("redis")
def _scan_redis(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure Cache for Redis."""
    region_norm = region.lower().replace(" ", "")
    resources = []
    try:
        client = factory.get_client("redis")
        for item in azure_list_all(client.redis.list_by_subscription):
            if _normalize_location(item.get("location", "")) == region_norm:
                enriched = _enrich_azure_item(item, "redis", subscription_id,
                                              discovery_id="azure.redis.redis.list_by_subscription")
                resources.append(enriched)
                dup = dict(enriched)
                dup["_discovery_id"] = "azure.redis.redis.list_by_resource_group"
                resources.append(dup)
    except Exception as exc:
        logger.warning("  redis list_by_subscription failed: %s", exc)
    logger.info("  redis/%s: %d Redis caches found", region, len(resources))
    return resources


@azure_handler("containerregistry")
def _scan_containerregistry(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure Container Registry."""
    region_norm = region.lower().replace(" ", "")
    resources = []
    try:
        client = factory.get_client("containerregistry")
        for item in azure_list_all(client.registries.list):
            if _normalize_location(item.get("location", "")) == region_norm:
                enriched = _enrich_azure_item(item, "containerregistry", subscription_id,
                                              discovery_id="azure.containerregistry.root.list")
                resources.append(enriched)
    except Exception as exc:
        logger.warning("  containerregistry list failed: %s", exc)
    logger.info("  containerregistry/%s: %d registries found", region, len(resources))
    return resources


@azure_handler("recoveryservices")
def _scan_recoveryservices(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure Recovery Services Vaults."""
    region_norm = region.lower().replace(" ", "")
    resources = []
    try:
        client = factory.get_client("recoveryservices")
        for item in azure_list_all(client.vaults.list_by_subscription_id):
            if _normalize_location(item.get("location", "")) == region_norm:
                resources.append(_enrich_azure_item(item, "recoveryservices", subscription_id,
                                                    discovery_id="azure.recoveryservices.vaults.list_by_subscription_id"))
    except Exception as exc:
        logger.warning("  recoveryservices list failed: %s", exc)
    logger.info("  recoveryservices/%s: %d vaults found", region, len(resources))
    return resources


@azure_handler("aad")
def _scan_aad(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure AD (AAD) resources via Resource Graph / Graph API stub.

    Full Microsoft Graph API requires a separate client (not ARM SDK).
    We emit a placeholder resource so check rules with for_each=azure.aad.list
    receive at least one context item — the actual AAD data fields are populated
    by the check engine pulling from the tenant-level Graph API directly.
    """
    if region not in ("eastus", "global"):
        return []
    # Return a single tenant-scope resource representing the AAD tenant
    item = {
        "id": f"/tenants/{subscription_id}/aad",
        "type": "Microsoft.AzureActiveDirectory/tenants",
        "name": "aad_tenant",
        "subscription_id": subscription_id,
        "_discovery_id": "azure.aad.list",
    }
    item["resource_uid"] = item["id"]
    item["resource_id"] = item["id"]
    item["resource_type"] = "AADTenant"
    item["resource_name"] = "aad_tenant"
    item["account_id"] = subscription_id
    item["_raw_response"] = {}
    dup = dict(item); dup["_discovery_id"] = "azure.aad.list_aads"
    logger.info("  aad: emitted tenant AAD stub")
    return [item, dup]


@azure_handler("grafana")
def _scan_grafana(factory, subscription_id: str, region: str) -> List[Dict]:
    """Discover Azure Managed Grafana instances."""
    region_norm = region.lower().replace(" ", "")
    resources = []
    try:
        client = factory.get_client("grafana")
        for item in azure_list_all(client.grafana.list):
            if _normalize_location(item.get("location", "")) == region_norm:
                resources.append(_enrich_azure_item(item, "grafana", subscription_id,
                                                    discovery_id="azure.dashboard.grafana.list"))
    except Exception as exc:
        logger.debug("  grafana list failed (SDK may not support): %s", exc)
    logger.info("  grafana/%s: %d Grafana instances found", region, len(resources))
    return resources


# ───────────────────────────────────────────────────────────────────────────────


def _call_with_timeout(future: Future, service: str, region: str) -> Optional[Any]:
    """Execute a submitted future with timeout, returning None on timeout/error.

    Prevents hung Azure API calls from blocking executor threads indefinitely.
    Every Azure SDK call submitted to _AZURE_EXECUTOR must use this wrapper.

    Args:
        future: Submitted concurrent.futures.Future
        service: Service name for logging context (e.g. 'compute')
        region: Region name for logging context (e.g. 'eastus')

    Returns:
        Future result, or None if timed out or errored
    """
    try:
        return future.result(timeout=OPERATION_TIMEOUT)
    except FuturesTimeoutError:
        logger.warning(
            "Azure API call timed out after %ds: service=%s region=%s",
            OPERATION_TIMEOUT, service, region,
        )
        return None
    except Exception as exc:
        logger.error(
            "Azure API call failed: service=%s region=%s error=%s",
            service, region, exc,
        )
        return None


def _normalize_location(location: str) -> str:
    """Normalize Azure location string for comparison.

    Azure API returns 'eastus', 'East US', 'eastus2' etc. interchangeably.
    Normalize to lowercase with spaces stripped.

    Args:
        location: Raw Azure location string

    Returns:
        Lowercase no-space location string
    """
    return location.lower().replace(" ", "")


class AzureDiscoveryScanner(DiscoveryScanner):
    """Azure cloud resource discovery scanner.

    Implements DB-driven service discovery for Azure subscriptions.
    All service enumeration is driven by rule_discoveries table, not hardcoded.

    Credential resolution: credential_ref → AWS Secrets Manager →
    ClientSecretCredential(tenant_id, client_id, client_secret).

    Usage::

        scanner = AzureDiscoveryScanner(credentials=creds, provider="azure")
        scanner.authenticate()
        resources = asyncio.run(scanner.scan_service("compute", "eastus", config))
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs) -> None:
        """Initialize Azure scanner.

        Args:
            credentials: Credential dict, expected to contain either:
                - Pre-resolved keys: tenant_id, client_id, client_secret, subscription_id
                - Or: credential_ref, credential_type (resolved via _resolve_credentials)
            **kwargs: provider (str), account_id (str)
        """
        super().__init__(credentials=credentials, **kwargs)
        self.subscription_id: Optional[str] = credentials.get("subscription_id")
        self.credential_ref: Optional[str] = credentials.get("credential_ref")
        self.credential_type: Optional[str] = credentials.get("credential_type")
        self._factory: Optional[AzureClientFactory] = None  # Set by authenticate()

    # ── Authentication ──────────────────────────────────────────────────────

    def authenticate(self) -> AzureClientFactory:
        """Authenticate using Azure SP credentials or Azure CLI (DefaultAzureCredential).

        Three resolution paths (checked in order):
        1. credential_type == 'cli' → DefaultAzureCredential (az login)
        2. credentials dict already has all 4 SP keys → ClientSecretCredential
        3. credential_ref provided → fetch from AWS Secrets Manager

        Returns:
            AzureClientFactory (also stored as self._factory)

        Raises:
            AuthenticationError: If credentials are missing or auth fails.
        """
        cred_type = (self.credential_type or "").lower()

        # Path 1: Azure CLI / DefaultAzureCredential
        if cred_type == "cli":
            if not self.subscription_id:
                raise AuthenticationError(
                    "subscription_id is required for CLI authentication"
                )
            try:
                self._factory = AzureClientFactory(
                    credentials={"subscription_id": self.subscription_id}
                )
                self.session = self._factory
                logger.info(
                    "Azure CLI authentication successful: subscription=%s",
                    self.subscription_id,
                )
                return self._factory
            except Exception as exc:
                raise AuthenticationError(
                    f"Azure DefaultAzureCredential failed: {exc}"
                ) from exc

        # Path 2 & 3: SP credentials (direct or via Secrets Manager)
        required = {"tenant_id", "client_id", "client_secret", "subscription_id"}
        creds = self.credentials

        if not required.issubset(creds.keys()):
            if not self.credential_ref:
                raise AuthenticationError(
                    "Azure credentials missing required keys and no credential_ref provided. "
                    f"Expected: {required}"
                )
            try:
                resolved = self._resolve_credentials(self.credential_ref)
                creds = {**creds, **resolved}
            except Exception as exc:
                raise AuthenticationError(
                    f"Failed to resolve Azure credentials from {self.credential_ref!r}: {exc}"
                ) from exc

        missing = required - set(creds.keys())
        if missing:
            raise AuthenticationError(
                f"Azure credentials missing required keys after resolution: {missing}"
            )

        try:
            self._factory = AzureClientFactory(credentials=creds)
            self.subscription_id = creds["subscription_id"]
            self.session = self._factory  # base class compat
            logger.info(
                "Azure authentication successful: subscription=%s",
                self.subscription_id,
            )
            return self._factory
        except Exception as exc:
            raise AuthenticationError(f"Azure ClientSecretCredential failed: {exc}") from exc

    def _resolve_credentials(self, credential_ref: str) -> dict:
        """Resolve Azure SP credentials from AWS Secrets Manager.

        Args:
            credential_ref: e.g. 'threat-engine/azure/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e'

        Returns:
            Dict with: tenant_id, client_id, client_secret, subscription_id

        Raises:
            ValueError: If secret is missing required keys.

        Full implementation: AZ-17b.
        """
        import boto3  # lazy — only needed for Azure credential resolution
        import os

        client = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION", "us-east-1"))
        secret = client.get_secret_value(SecretId=credential_ref)
        creds = json.loads(secret["SecretString"])

        required_keys = {"tenant_id", "client_id", "client_secret", "subscription_id"}
        missing = required_keys - set(creds.keys())
        if missing:
            raise ValueError(
                f"Azure credentials at {credential_ref!r} missing keys: {missing}"
            )
        return creds

    # ── Client factory ──────────────────────────────────────────────────────

    def get_client(self, service: str, region: str) -> Any:
        """Return Azure management client for the given service.

        Args:
            service: Service name from rule_discoveries (e.g. 'compute', 'storage')
            region: Azure location — not used for client creation (Azure clients
                    are subscription-scoped, not region-scoped), kept for interface compat.

        Returns:
            Azure management client

        Raises:
            DiscoveryError: If authenticate() has not been called.
        """
        if self._factory is None:
            raise DiscoveryError("authenticate() must be called before get_client()")
        return self._factory.get_client(service)

    def get_service_client_name(self, service: str) -> str:
        """Map rule_discoveries service name to Azure SDK client class name.

        Args:
            service: Service name (e.g. 'compute', 'storage', 'keyvault')

        Returns:
            Azure SDK client class name (e.g. 'ComputeManagementClient')
        """
        if self._factory is None:
            from providers.azure.client_factory import _CLIENT_MAP
            _, class_name = _CLIENT_MAP.get(service, ("", service))
            return class_name
        return self._factory.get_client_name(service)

    # ── Discovery ───────────────────────────────────────────────────────────

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any],
        skip_dependents: bool = False,
    ) -> List[Dict[str, Any]]:
        """Execute Azure service discovery for one service in one region.

        Dispatches to a registered handler in AZURE_SERVICE_HANDLERS.
        Handlers call Azure SDK directly — no DB config parsing.

        Args:
            service: Azure service name (e.g. 'compute', 'storage', 'keyvault')
            region: Azure location (e.g. 'eastus', 'westeurope')
            config: Unused — kept for interface compatibility with other providers
            skip_dependents: Unused — kept for interface compatibility

        Returns:
            List of normalized resource dicts with standard fields.

        Raises:
            DiscoveryError: If authenticate() has not been called.
        """
        if self._factory is None:
            raise DiscoveryError("authenticate() must be called before scan_service()")

        handler = AZURE_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.debug("No Azure handler for service=%s, skipping region=%s", service, region)
            return []

        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                _AZURE_EXECUTOR,
                handler,
                self._factory,
                self.subscription_id,
                region,
            )
            return results or []
        except Exception as exc:
            logger.error("Azure %s/%s handler failed: %s", service, region, exc)
            return []

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None,
    ) -> Dict[str, str]:
        """Extract Azure resource identifiers from SDK response item.

        Azure resource_uid = full Azure Resource ID:
        /subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}

        Args:
            item: Azure SDK resource dict (from as_dict())
            service: Service name
            region: Azure location
            account_id: Subscription ID
            resource_type: Optional resource type override

        Returns:
            Dict with resource_uid, resource_id, resource_name
        """
        resource_uid = item.get("id", "")
        resource_name = item.get("name", "")

        # Fallback resource_uid if 'id' is absent
        if not resource_uid and resource_name and self.subscription_id:
            resource_uid = (
                f"/subscriptions/{self.subscription_id}"
                f"/providers/Microsoft.{service.capitalize()}/{resource_name}"
            )

        # Normalize resource type from the 'type' field in the response
        raw_type = item.get("type", "")
        normalized_type = _RESOURCE_TYPE_MAP.get(raw_type, raw_type or service)

        return {
            "resource_uid": resource_uid,
            "resource_id": resource_uid,  # Azure uses full Resource ID as both
            "resource_name": resource_name,
            "resource_type": normalized_type,
        }

    # ── Optional overrides ──────────────────────────────────────────────────

    async def list_available_regions(self) -> List[str]:
        """Return list of Azure locations from SubscriptionClient.

        Returns empty list on error — DiscoveryEngine uses DB-configured regions.
        """
        if self._factory is None:
            return []
        try:
            loop = asyncio.get_event_loop()
            # SubscriptionClient (azure.mgmt.subscription) has .subscriptions.list_locations
            # ResourceManagementClient does NOT have .subscriptions — wrong client
            sub_client = self._factory.get_client("subscription")

            locations = await loop.run_in_executor(
                _AZURE_EXECUTOR,
                lambda: azure_list_all(
                    sub_client.subscriptions.list_locations,
                    subscription_id=self.subscription_id,
                ),
            )
            return sorted({loc.get("name", "") for loc in locations if loc.get("name")})
        except Exception as exc:
            logger.warning("Could not list Azure regions: %s — using defaults", exc)
            return []

    def get_account_id(self) -> str:
        """Return Azure subscription ID."""
        if not self.subscription_id:
            raise DiscoveryError(
                "subscription_id not set — call authenticate() first"
            )
        return self.subscription_id

    # ── Private helpers ─────────────────────────────────────────────────────

    def _resolve_sdk_method(self, client: Any, action: str) -> Optional[Any]:
        """Resolve a dot-notation action string to an SDK method on client.

        Examples:
            'virtual_machines.list_all' → client.virtual_machines.list_all
            'storage_accounts.list'     → client.storage_accounts.list
            'servers.list'              → client.servers.list

        Args:
            client: Azure management client instance
            action: Dot-notation method path (e.g. 'virtual_machines.list_all')

        Returns:
            Callable method, or None if the path cannot be resolved
        """
        parts = action.split(".")
        obj: Any = client
        for part in parts:
            obj = getattr(obj, part, None)
            if obj is None:
                logger.debug(
                    "Cannot resolve action path %r: attribute %r not found on %s",
                    action, part, type(client).__name__,
                )
                return None
        return obj if callable(obj) else None

    def _normalize_resource(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        resource_type_hint: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Normalize an Azure SDK resource dict to the standard discovery output.

        Args:
            item: Azure SDK resource dict (from as_dict())
            service: Service name for fallback resource_type
            region: Azure location
            resource_type_hint: Optional resource type from action spec override

        Returns:
            Standard resource dict, or None if resource_uid is missing/empty
        """
        resource_uid = item.get("id", "")
        if not resource_uid:
            logger.debug(
                "Skipping Azure resource with no 'id' field: service=%s name=%s",
                service, item.get("name", "<unknown>"),
            )
            return None

        raw_type = item.get("type", "")
        resource_type = (
            resource_type_hint
            or _RESOURCE_TYPE_MAP.get(raw_type)
            or raw_type
            or service
        )

        return {
            "resource_uid":  resource_uid,
            "resource_type": resource_type,
            "resource_name": item.get("name", ""),
            "provider":      "azure",
            "region":        item.get("location", region),
            "account_id":    self.subscription_id or "",
            "raw_data":      item,
        }
