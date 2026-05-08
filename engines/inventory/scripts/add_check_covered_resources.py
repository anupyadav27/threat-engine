#!/usr/bin/env python3
"""
Add and enable resource_inventory_identifier rows for Azure and GCP services
that have check rules but are missing from (or disabled in) the inventory table.

Two-phase approach:
  Phase 1 — ENABLE existing rows whose SDK operations are referenced by check rules
             (e.g. containerservice.managedclusters for the `aks` check)
  Phase 2 — INSERT brand-new rows for services whose resources don't exist
             in any SDK service entry (e.g. aad, ad, entra, gke_audit, etc.)

Usage:
    python add_check_covered_resources.py --dry-run    # show counts, no writes
    python add_check_covered_resources.py              # apply to DB
    python add_check_covered_resources.py --csp azure  # only Azure
    python add_check_covered_resources.py --csp gcp    # only GCP
"""

import argparse
import json
import logging
import os
import sys

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not found. Install: pip install psycopg2-binary")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── helpers ───────────────────────────────────────────────────────────────────

def _az_ops(*operations: str) -> list:
    """Build Azure root_ops list from operation strings."""
    result = []
    for op in operations:
        method = op.rsplit(".", 1)[-1]
        kind = "read_list" if method.startswith("list") else "read_get"
        result.append({
            "kind": kind,
            "operation": op,
            "independent": True,
            "python_method": method,
            "required_params": [],
        })
    return result


def _gcp_ops(*operations: str) -> list:
    """Build GCP root_ops list from operation strings (simplified, no HTTP path)."""
    result = []
    for op in operations:
        method = op.rsplit(".", 1)[-1]
        kind = "read_list" if "list" in method else "read_get"
        result.append({
            "op": op,
            "kind": kind,
            "independent": True,
            "python_call": f"svc.{method}().execute()",
        })
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — rows to ENABLE  (exist in DB but should_inventory=false)
# ─────────────────────────────────────────────────────────────────────────────

# Format: (csp, service, resource_type|None)  — None means ALL resource_types in that service

AZURE_ENABLE: list[tuple[str, str | None]] = [
    # aks check → containerservice.managedclusters
    ("containerservice", "managedclusters"),
    # appservice / function / functionapp / functions / webapp checks → web.*
    ("web", None),                                 # enable entire web service
    # iam / rbac / policy checks → authorization.*
    ("authorization", "roleassignments"),
    ("authorization", "roledefinitions"),
    # event checks → eventhub + eventgrid
    ("eventhub", "namespaces"),
    ("eventgrid", "eventsubscriptions"),
    ("eventgrid", "topics"),
    ("eventgrid", "domains"),
    # front check → frontdoor.policies
    ("frontdoor", "policies"),
    # iot check → iothub.iothubresource
    ("iothub", "iothubresource"),
    # machine check → machinelearningservices.workspaces
    ("machinelearningservices", "workspaces"),
    # notification check → notificationhubs.*
    ("notificationhubs", "namespaces"),
    ("notificationhubs", "notificationhubs"),
    # postgresql check → rdbms_postgresql.servers
    ("rdbms_postgresql", "servers"),
    # site check → recoveryservicessiterecovery (key sub-resources)
    ("recoveryservicessiterecovery", "replicationalertsettings"),
    ("recoveryservicessiterecovery", "replicationpolicies"),
    ("recoveryservicessiterecovery", "replicationrecoveryplans"),
    # traffic check → trafficmanager.profiles
    ("trafficmanager", "profiles"),
    # config check → appconfiguration.configurationstores
    ("appconfiguration", "configurationstores"),
    # cost check → costmanagement.alerts
    ("costmanagement", "alerts"),
    # data check → datafactory + datalakeanalytics + streamanalytics
    ("datafactory", "factories"),
    ("datalakeanalytics", "accounts"),
    ("streamanalytics", "streamingjobs"),
    # policy check → policyinsights
    ("policyinsights", "policyevents"),
]

GCP_ENABLE: list[tuple[str, str | None]] = [
    # bigtable check → bigtableadmin.*
    ("bigtableadmin", None),
    # billing check → cloudbilling.*
    ("cloudbilling", None),
    # resourcemanager check → cloudresourcemanager.*
    ("cloudresourcemanager", None),
    # trace check → cloudtrace.*
    ("cloudtrace", None),
    # filestore check → file.*
    ("file", None),
    # cloudrun check → run.*
    ("run", None),
    # scc + security_command_center checks → securitycenter.*
    ("securitycenter", None),
    # cloudsql + sql checks → sqladmin.*
    ("sqladmin", None),
]


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — new rows to INSERT
#
#  Each entry: (service, resource_type, classification, can_inventory_from_roots,
#               root_ops_list, identifier_type, primary_param, identifier_pattern)
# ─────────────────────────────────────────────────────────────────────────────

#  Azure — resources that have NO corresponding SDK service rows at all
AZURE_INSERT: list[dict] = [
    # ── aad (Azure AD tenant) ─────────────────────────────────────────────
    {
        "service": "aad",
        "resource_type": "directory",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.aad.list"),
        "identifier_type": "id",
        "primary_param": "tenantId",
        "identifier_pattern": "/tenants/{tenantId}",
    },
    # ── ad (Azure AD Graph objects) ───────────────────────────────────────
    {
        "service": "ad",
        "resource_type": "user",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_users"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/users/{userId}",
    },
    {
        "service": "ad",
        "resource_type": "group",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_groups"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/groups/{groupId}",
    },
    {
        "service": "ad",
        "resource_type": "conditional_access_policy",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_conditional_access_policies"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/identity/conditionalAccess/policies/{id}",
    },
    {
        "service": "ad",
        "resource_type": "role_assignment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_role_assignments"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/roleManagement/directory/roleAssignments/{id}",
    },
    {
        "service": "ad",
        "resource_type": "role_definition",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_role_definitions"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/roleManagement/directory/roleDefinitions/{id}",
    },
    {
        "service": "ad",
        "resource_type": "guest_user",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.ad.list_guest_users"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/users/{userId}",
    },
    # ── entra (Microsoft Entra ID) ────────────────────────────────────────
    {
        "service": "entra",
        "resource_type": "user",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.entra.list_users", "azure.entra.users.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/users/{userId}",
    },
    {
        "service": "entra",
        "resource_type": "group",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.entra.list_groups"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/groups/{groupId}",
    },
    {
        "service": "entra",
        "resource_type": "app_registration",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.entra.id.list_app_registrations"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/applications/{applicationId}",
    },
    {
        "service": "entra",
        "resource_type": "conditional_access_policy",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops(
            "azure.entra.id.list_tenant_policies",
            "azure.graph.identity_conditional_access_policies.list",
        ),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/identity/conditionalAccess/policies/{id}",
    },
    {
        "service": "entra",
        "resource_type": "named_location",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.entra.named_locations.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/identity/conditionalAccess/namedLocations/{id}",
    },
    {
        "service": "entra",
        "resource_type": "diagnostic_setting",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops(
            "azure.entra.list_diagnostic_settings",
            "azure.entra.id.list_diagnostic_settings",
        ),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/providers/microsoft.aadiam/diagnosticSettings/{name}",
    },
    # ── entrad (Entra device/admin config) ───────────────────────────────
    {
        "service": "entrad",
        "resource_type": "device",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.entrad.list_devices"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/devices/{deviceId}",
    },
    {
        "service": "entrad",
        "resource_type": "global_admin_role",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.entrad.list_global_admin_roles"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/roleManagement/directory/roleAssignments/{id}",
    },
    {
        "service": "entrad",
        "resource_type": "password_policy",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.entrad.get_password_policy"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/policies/authorizationPolicy",
    },
    # ── graph (Microsoft Graph standalone) ───────────────────────────────
    {
        "service": "graph",
        "resource_type": "conditional_access_policy",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.graph.identity_conditional_access_policies.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/identity/conditionalAccess/policies/{id}",
    },
    # ── intune ────────────────────────────────────────────────────────────
    {
        "service": "intune",
        "resource_type": "diagnostic_setting",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.intune.list_diagnostic_settings"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/providers/microsoft.intune/diagnosticSettings/{name}",
    },
    # ── power (Power BI) ──────────────────────────────────────────────────
    {
        "service": "power",
        "resource_type": "workspace",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.power.bi.list_workspaces", "azure.power.bi_workspaces.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/groups/{groupId}",
    },
    {
        "service": "power",
        "resource_type": "dataset",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.power.bi.list_datasets", "azure.power.bi_dataset.list_datasets"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/groups/{groupId}/datasets/{datasetId}",
    },
    {
        "service": "power",
        "resource_type": "dashboard",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.power.bi_dashboard.list_dashboards", "azure.power.bi_dashboards.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/groups/{groupId}/dashboards/{dashboardId}",
    },
    # ── aisearch (mapped to search service ops) ───────────────────────────
    # search.services already enabled above, but check service is "aisearch"
    {
        "service": "aisearch",
        "resource_type": "service",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.search.services.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Search/searchServices/{name}",
    },
    # ── cosmos (databaseaccounts already enabled via cosmosdb.databaseaccounts) ──
    # Add cosmos-aliased entry so `cosmos` check service links
    {
        "service": "cosmos",
        "resource_type": "databaseaccount",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.cosmosdb.databaseaccounts.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{name}",
    },
    # ── disk (compute.disks already enabled; add disk-aliased entry) ──────
    {
        "service": "disk",
        "resource_type": "disk",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.compute.disks.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/disks/{name}",
    },
    # ── virtualmachines + vm (compute.virtualmachines already enabled) ────
    {
        "service": "virtualmachines",
        "resource_type": "virtualmachine",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.compute.virtualmachines.list", "azure.compute.virtualmachines.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{name}",
    },
    {
        "service": "vm",
        "resource_type": "virtualmachine",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.compute.virtualmachines.list", "azure.compute.virtualmachines.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{name}",
    },
    {
        "service": "vm",
        "resource_type": "disk",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.compute.disks.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/disks/{name}",
    },
    # ── defender (security.tasks already enabled; add alias) ─────────────
    {
        "service": "defender",
        "resource_type": "security_task",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.security.tasks.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Security/tasks/{name}",
    },
    # ── application (network.applicationgateways + WAF policies) ─────────
    {
        "service": "application",
        "resource_type": "applicationgateway",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.applicationgateways.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/applicationGateways/{name}",
    },
    {
        "service": "application",
        "resource_type": "webapplicationfirewallpolicy",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.webapplicationfirewallpolicies.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/{name}",
    },
    # ── appservice (alias for web.webapps) ────────────────────────────────
    {
        "service": "appservice",
        "resource_type": "webapp",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.web.webapps.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}",
    },
    # ── function / functionapp / functions / webapp ───────────────────────
    {
        "service": "function",
        "resource_type": "webapp",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.web.webapps.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}",
    },
    {
        "service": "function",
        "resource_type": "function",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.web.webapps.list_functions"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/functions/{name}",
    },
    {
        "service": "function",
        "resource_type": "slot",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.web.webapps.list_slots"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots/{name}",
    },
    {
        "service": "functionapp",
        "resource_type": "webapp",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.web.webapps.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}",
    },
    {
        "service": "functionapp",
        "resource_type": "slot",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.web.webapps.list_slots"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots/{name}",
    },
    {
        "service": "functions",
        "resource_type": "function",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.web.webapps.list_functions"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/functions/{name}",
    },
    {
        "service": "webapp",
        "resource_type": "webapp",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.web.webapps.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}",
    },
    {
        "service": "webapp",
        "resource_type": "slot",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.web.webapps.list_slots"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots/{name}",
    },
    # ── config (appconfiguration alias) ───────────────────────────────────
    {
        "service": "config",
        "resource_type": "configurationstore",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.appconfiguration.configurationstores.configurationstores_list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AppConfiguration/configurationStores/{name}",
    },
    # ── cost (costmanagement alias with billing) ───────────────────────────
    {
        "service": "cost",
        "resource_type": "billingaccount",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.billing.billingaccounts.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/providers/Microsoft.Billing/billingAccounts/{billingAccountId}",
    },
    {
        "service": "cost",
        "resource_type": "alert",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.costmanagement.alerts.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/alerts/{name}",
    },
    {
        "service": "cost",
        "resource_type": "export",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.costmanagement.exports.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/exports/{name}",
    },
    # ── data (lake analytics + datafactory + streamanalytics) ─────────────
    {
        "service": "data",
        "resource_type": "lake_analytics_account",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.data.lake_analytics.list_accounts", "azure.data_lake_analytics.list_accounts"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{name}",
    },
    {
        "service": "data",
        "resource_type": "factory",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.datafactory.factories.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataFactory/factories/{name}",
    },
    {
        "service": "data",
        "resource_type": "streamingjob",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.streamanalytics.streamingjobs.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.StreamAnalytics/streamingjobs/{name}",
    },
    # ── event (eventhub + eventgrid aliases) ──────────────────────────────
    {
        "service": "event",
        "resource_type": "eventhub_namespace",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.eventhub.namespaces.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{name}",
    },
    {
        "service": "event",
        "resource_type": "eventhub",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.eventhub.eventhubs.list_by_namespace"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.EventHub/namespaces/{namespaceName}/eventhubs/{name}",
    },
    {
        "service": "event",
        "resource_type": "eventsubscription",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.eventgrid.eventsubscriptions.list_by_resource"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.EventGrid/eventSubscriptions/{name}",
    },
    # ── front (frontdoor WAF policies) ────────────────────────────────────
    {
        "service": "front",
        "resource_type": "waf_policy",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.frontdoor.policies.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/{name}",
    },
    # ── iam (authorization aliases) ───────────────────────────────────────
    {
        "service": "iam",
        "resource_type": "role_assignment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.authorization.roleassignments.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{id}",
    },
    {
        "service": "iam",
        "resource_type": "role_definition",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.authorization.roledefinitions.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{id}",
    },
    {
        "service": "iam",
        "resource_type": "user",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.iam.list_users"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/users/{userId}",
    },
    # ── iot (IoT Hub) ─────────────────────────────────────────────────────
    {
        "service": "iot",
        "resource_type": "iothub",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.iothub.iothubresource.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{name}",
    },
    # ── key (keyvault aliases — keyvault.vaults already enabled) ─────────
    {
        "service": "key",
        "resource_type": "vault",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.keyvault.vaults.list", "azure.keyvault.vaults.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{name}",
    },
    {
        "service": "key",
        "resource_type": "key",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.keyvault.keys.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/keys/{name}",
    },
    # ── load / loadbalancer (network.loadbalancers already enabled) ───────
    {
        "service": "load",
        "resource_type": "loadbalancer",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.loadbalancers.list", "azure.network.loadbalancers.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/loadBalancers/{name}",
    },
    {
        "service": "loadbalancer",
        "resource_type": "loadbalancer",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.loadbalancers.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/loadBalancers/{name}",
    },
    # ── machine (ML workspaces) ───────────────────────────────────────────
    {
        "service": "machine",
        "resource_type": "workspace",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.machinelearningservices.workspaces.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MachineLearningServices/workspaces/{name}",
    },
    # ── managementgroup (subscription.subscriptions already enabled) ──────
    {
        "service": "managementgroup",
        "resource_type": "subscription",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.subscription.subscriptions.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}",
    },
    # ── networksecuritygroup (network.networksecuritygroups already enabled)
    {
        "service": "networksecuritygroup",
        "resource_type": "networksecuritygroup",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.networksecuritygroups.list_all"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups/{name}",
    },
    # ── notification ──────────────────────────────────────────────────────
    {
        "service": "notification",
        "resource_type": "namespace",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.notificationhubs.notificationhubs.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NotificationHubs/namespaces/{namespaceName}/notificationHubs/{name}",
    },
    # ── policy (authorization + policyinsights aliases) ───────────────────
    {
        "service": "policy",
        "resource_type": "policy_assignment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.resources.policyassignments.policyassignments_list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments/{name}",
    },
    {
        "service": "policy",
        "resource_type": "policy_definition",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.resources.policydefinitions.policydefinitions_list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/{name}",
    },
    {
        "service": "policy",
        "resource_type": "role_assignment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.authorization.roleassignments.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{id}",
    },
    # ── postgresql (rdbms_postgresql.servers alias) ───────────────────────
    {
        "service": "postgresql",
        "resource_type": "server",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.postgresql.servers.servers_list", "azure.rdbms_postgresql.servers.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DBforPostgreSQL/servers/{name}",
    },
    # ── purview (purview.accounts already enabled) ────────────────────────
    {
        "service": "purview",
        "resource_type": "account",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.purview.accounts.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Purview/accounts/{name}",
    },
    # ── rbac (authorization aliases) ──────────────────────────────────────
    {
        "service": "rbac",
        "resource_type": "role_assignment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.authorization.roleassignments.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{id}",
    },
    {
        "service": "rbac",
        "resource_type": "role_definition",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.authorization.roledefinitions.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{id}",
    },
    # ── site (recoveryservicessiterecovery aliases) ───────────────────────
    {
        "service": "site",
        "resource_type": "vault",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.recoveryservices.vaults.list_by_subscription_id"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{name}",
    },
    {
        "service": "site",
        "resource_type": "replication_policy",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.recoveryservicessiterecovery.replicationpolicies.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/replicationPolicies/{name}",
    },
    {
        "service": "site",
        "resource_type": "recovery_plan",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _az_ops("azure.recoveryservicessiterecovery.replicationrecoveryplans.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/replicationRecoveryPlans/{name}",
    },
    # ── subscription (subscription.subscriptions already enabled) ─────────
    {
        "service": "subscription",
        "resource_type": "subscription",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.subscription.subscriptions.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}",
    },
    # ── synapse (synapse.workspaces already enabled) ───────────────────────
    {
        "service": "synapse",
        "resource_type": "workspace",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.synapse.workspaces.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{name}",
    },
    # ── traffic (trafficmanager.profiles) ─────────────────────────────────
    {
        "service": "traffic",
        "resource_type": "profile",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.trafficmanager.profiles.list_by_subscription"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{name}",
    },
    # ── vpn (network.vpngateways already enabled) ─────────────────────────
    {
        "service": "vpn",
        "resource_type": "vpngateway",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _az_ops("azure.network.vpngateways.list"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/vpnGateways/{name}",
    },
]


#  GCP — resources with no corresponding SDK service rows
GCP_INSERT: list[dict] = [
    # ── gke_audit (K8s audit within GKE) ─────────────────────────────────
    {
        "service": "gke_audit",
        "resource_type": "clusterrole",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_clusterrole"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/rbac/clusterroles/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "clusterrolebinding",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_clusterrolebindings"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/rbac/clusterrolebindings/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "deployment",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_deployments"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/deployments/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "daemonset",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_daemonsets"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/daemonsets/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "secret",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_secrets"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/secrets/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "serviceaccount",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_serviceaccounts"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/serviceaccounts/{name}",
    },
    {
        "service": "gke_audit",
        "resource_type": "rolebinding",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.gke_audit.list_rolebindings"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/rbac/rolebindings/{name}",
    },
    # ── datastudio (Looker Studio dashboards) ─────────────────────────────
    {
        "service": "datastudio",
        "resource_type": "dashboard",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.datastudio.list_dashboards", "gcp.datastudio.dashboards.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/dashboards/{dashboardId}",
    },
    # ── endpoints (Cloud Endpoints) ───────────────────────────────────────
    {
        "service": "endpoints",
        "resource_type": "service",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.endpoints.list_services", "gcp.endpoints.services.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "services/{serviceName}",
    },
    # ── services (Cloud API Services) ─────────────────────────────────────
    {
        "service": "services",
        "resource_type": "enabled_service",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.services.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/services/{serviceName}",
    },
    {
        "service": "services",
        "resource_type": "api_key",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.services.list_keys", "gcp.services.service.list_keys"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/services/{serviceName}/apiKeys/{keyId}",
    },
    # ── ciem (internal CIEM correlation engine) ───────────────────────────
    {
        "service": "ciem",
        "resource_type": "identity",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.ciem.list_identities", "gcp.ciem.list_correlated_identities"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "projects/{project}/identities/{identityId}",
    },
    {
        "service": "ciem",
        "resource_type": "correlated_event",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.ciem.list_correlated_events"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "projects/{project}/events/{eventId}",
    },
    # ── billing (alias entries — cloudbilling being enabled above) ─────────
    {
        "service": "billing",
        "resource_type": "budget",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.billing.list_budgets", "gcp.billing.budgets.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "billingAccounts/{billingAccountId}/budgets/{budgetId}",
    },
    {
        "service": "billing",
        "resource_type": "anomaly",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.billing.list_anomalies", "gcp.billing.anomaly.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "billingAccounts/{billingAccountId}/anomalies/{anomalyId}",
    },
    # ── kms (alias entries — cloudkms already enabled) ────────────────────
    {
        "service": "kms",
        "resource_type": "crypto_key",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.kms.list_crypto_keys", "gcp.kms.crypto_keys.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{name}",
    },
    # ── cloudrun (alias — run.* being enabled) ────────────────────────────
    {
        "service": "cloudrun",
        "resource_type": "service",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.cloudrun.list_services"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/services/{name}",
    },
    # ── cloudsql (alias — sqladmin.* being enabled) ───────────────────────
    {
        "service": "cloudsql",
        "resource_type": "instance",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.cloudsql.list_instances"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/instances/{name}",
    },
    {
        "service": "cloudsql",
        "resource_type": "user",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.cloudsql.list_users"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/instances/{instance}/users/{name}",
    },
    # ── sql (alias — sqladmin.* being enabled) ────────────────────────────
    {
        "service": "sql",
        "resource_type": "instance",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.sql.list_instances", "gcp.sql.instances.list", "gcp.sqladmin.instances.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/instances/{name}",
    },
    {
        "service": "sql",
        "resource_type": "user",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.sql.list_users"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/instances/{instance}/users/{name}",
    },
    # ── resourcemanager (alias — cloudresourcemanager.* being enabled) ────
    {
        "service": "resourcemanager",
        "resource_type": "organization",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.resourcemanager.list_organizations", "gcp.resourcemanager.organizations.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}",
    },
    {
        "service": "resourcemanager",
        "resource_type": "project",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.resourcemanager.list_projects"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}",
    },
    {
        "service": "resourcemanager",
        "resource_type": "folder",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.resourcemanager.list_folders"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "folders/{folderId}",
    },
    {
        "service": "resourcemanager",
        "resource_type": "organization_policy",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.resourcemanager.list_organization_policies"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/policies/{constraint}",
    },
    # ── scc (alias — securitycenter.* being enabled) ──────────────────────
    {
        "service": "scc",
        "resource_type": "finding",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.scc.list_findings"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/sources/{sourceId}/findings/{findingId}",
    },
    {
        "service": "scc",
        "resource_type": "source",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.scc.list_sources", "gcp.scc.list_organization_sources"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/sources/{sourceId}",
    },
    {
        "service": "scc",
        "resource_type": "notification_config",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.scc.list_notification_configs"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/notificationConfigs/{name}",
    },
    # ── security_command_center (alias — securitycenter.* being enabled) ──
    {
        "service": "security_command_center",
        "resource_type": "finding",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.security_command_center.list_findings"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/sources/{sourceId}/findings/{findingId}",
    },
    {
        "service": "security_command_center",
        "resource_type": "source",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops(
            "gcp.security_command_center.list_sources",
            "gcp.security_command_center.sources.list",
        ),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/sources/{sourceId}",
    },
    {
        "service": "security_command_center",
        "resource_type": "organization_settings",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.security_command_center.organization_settings.get"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "organizations/{organizationId}/organizationSettings",
    },
    # ── gke (alias — container.* already enabled) ─────────────────────────
    {
        "service": "gke",
        "resource_type": "cluster",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops(
            "gcp.gke.list_clusters",
            "gcp.container.clusters.list",
            "gcp.container.projects.locations.clusters.list",
        ),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{name}",
    },
    {
        "service": "gke",
        "resource_type": "node_pool",
        "classification": "SUB_RESOURCE",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops(
            "gcp.gke.list_node_pools",
            "gcp.container.projects.zones.clusters.nodePools.list",
        ),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/clusters/{cluster}/nodePools/{name}",
    },
    # ── lb (alias — compute.* already enabled) ────────────────────────────
    {
        "service": "lb",
        "resource_type": "backend_service",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.lb.list_backend_services", "gcp.compute.list_backend_services"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/global/backendServices/{name}",
    },
    {
        "service": "lb",
        "resource_type": "forwarding_rule",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.lb.list_load_balancers", "gcp.compute.list_forwarding_rules"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/global/forwardingRules/{name}",
    },
    # ── function (alias — cloudfunctions already enabled) ─────────────────
    {
        "service": "function",
        "resource_type": "function",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.function.list_functions"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/functions/{name}",
    },
    # ── filestore (alias — file.* being enabled) ──────────────────────────
    {
        "service": "filestore",
        "resource_type": "instance",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.filestore.list_instances"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/locations/{location}/instances/{name}",
    },
    # ── bigtable (alias — bigtableadmin.* being enabled) ─────────────────
    {
        "service": "bigtable",
        "resource_type": "table",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.bigtable.list_tables", "gcp.bigtable.tables.list"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/instances/{instance}/tables/{name}",
    },
    # ── trace (alias — cloudtrace.* being enabled) ────────────────────────
    {
        "service": "trace",
        "resource_type": "sink",
        "classification": "PRIMARY_RESOURCE",
        "can_inventory_from_roots": True,
        "root_ops": _gcp_ops("gcp.trace.list_trace_sinks", "gcp.trace.get_trace_sink"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/traceSinks/{name}",
    },
    # ── audit (cross-service — own entry for audit config) ────────────────
    {
        "service": "audit",
        "resource_type": "audit_config",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.audit.get_audit_config"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "//cloudresourcemanager.googleapis.com/projects/{project}",
    },
    # ── data_access (cross-service) ───────────────────────────────────────
    {
        "service": "data_access",
        "resource_type": "egress_event",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.data_access.list_egress_events"),
        "identifier_type": "id",
        "primary_param": "id",
        "identifier_pattern": "projects/{project}/dataaccessEvents/{eventId}",
    },
    # ── flow (cross-service VPC flow) ─────────────────────────────────────
    {
        "service": "flow",
        "resource_type": "firewall",
        "classification": "CONFIGURATION",
        "can_inventory_from_roots": False,
        "root_ops": _gcp_ops("gcp.compute.list_firewalls"),
        "identifier_type": "id",
        "primary_param": "name",
        "identifier_pattern": "projects/{project}/global/firewalls/{name}",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  DB operations
# ─────────────────────────────────────────────────────────────────────────────

def phase1_enable(conn, csp: str, enable_list: list, dry_run: bool) -> int:
    """Enable (should_inventory=true) for specified (service, resource_type) pairs."""
    cur = conn.cursor()
    total = 0
    for service, resource_type in enable_list:
        if resource_type is None:
            cur.execute(
                "SELECT COUNT(*) FROM resource_inventory_identifier WHERE csp=%s AND service=%s AND NOT should_inventory",
                (csp, service),
            )
            count = cur.fetchone()[0]
            if not dry_run and count > 0:
                cur.execute(
                    "UPDATE resource_inventory_identifier SET should_inventory=true, updated_at=NOW() WHERE csp=%s AND service=%s AND NOT should_inventory",
                    (csp, service),
                )
            logger.info("%-6s ENABLE %-40s all resource_types → %d rows", csp, service, count)
            total += count
        else:
            cur.execute(
                "SELECT COUNT(*) FROM resource_inventory_identifier WHERE csp=%s AND service=%s AND resource_type=%s AND NOT should_inventory",
                (csp, service, resource_type),
            )
            count = cur.fetchone()[0]
            if not dry_run and count > 0:
                cur.execute(
                    "UPDATE resource_inventory_identifier SET should_inventory=true, updated_at=NOW() WHERE csp=%s AND service=%s AND resource_type=%s",
                    (csp, service, resource_type),
                )
            if count > 0:
                logger.info("%-6s ENABLE %-40s %-30s → %d rows", csp, service, resource_type, count)
            total += count
    cur.close()
    return total


def phase2_insert(conn, csp: str, insert_list: list, dry_run: bool) -> tuple[int, int]:
    """INSERT new rows; skip if (csp, service, resource_type) already exists."""
    cur = conn.cursor()
    inserted = skipped = 0
    for row in insert_list:
        cur.execute(
            "SELECT 1 FROM resource_inventory_identifier WHERE csp=%s AND service=%s AND resource_type=%s",
            (csp, row["service"], row["resource_type"]),
        )
        if cur.fetchone():
            logger.debug("%-6s SKIP   %s.%s (already exists)", csp, row["service"], row["resource_type"])
            skipped += 1
            continue

        if not dry_run:
            cur.execute(
                """
                INSERT INTO resource_inventory_identifier
                  (csp, service, resource_type, classification, has_arn,
                   identifier_type, primary_param, identifier_pattern,
                   can_inventory_from_roots, should_inventory,
                   root_ops, enrich_ops, loaded_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
                """,
                (
                    csp,
                    row["service"],
                    row["resource_type"],
                    row["classification"],
                    False,                          # has_arn (Azure/GCP use IDs)
                    row["identifier_type"],
                    row["primary_param"],
                    row["identifier_pattern"],
                    row["can_inventory_from_roots"],
                    True,                           # should_inventory = TRUE
                    psycopg2.extras.Json(row["root_ops"]),
                    psycopg2.extras.Json([]),       # enrich_ops empty (discovery handles later)
                ),
            )
        logger.info("%-6s INSERT %s.%s", csp, row["service"], row["resource_type"])
        inserted += 1

    cur.close()
    return inserted, skipped


def build_db_url(args) -> str:
    if args.db_url:
        return args.db_url
    host = os.getenv("INVENTORY_DB_HOST", "localhost")
    port = os.getenv("INVENTORY_DB_PORT", "5432")
    db   = os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory")
    user = os.getenv("INVENTORY_DB_USER", "inventory_user")
    pw   = os.getenv("INVENTORY_DB_PASSWORD", "inventory_password")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--csp", choices=["azure", "gcp", "both"], default="both")
    parser.add_argument("--db-url", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.dry_run:
        logger.info("DRY RUN — no DB changes")

    conn = psycopg2.connect(build_db_url(args))
    conn.autocommit = False

    totals: dict[str, dict] = {}
    try:
        if args.csp in ("azure", "both"):
            e = phase1_enable(conn, "azure", AZURE_ENABLE, args.dry_run)
            i, s = phase2_insert(conn, "azure", AZURE_INSERT, args.dry_run)
            totals["azure"] = {"enabled": e, "inserted": i, "skipped": s}

        if args.csp in ("gcp", "both"):
            e = phase1_enable(conn, "gcp", GCP_ENABLE, args.dry_run)
            i, s = phase2_insert(conn, "gcp", GCP_INSERT, args.dry_run)
            totals["gcp"] = {"enabled": e, "inserted": i, "skipped": s}

        if not args.dry_run:
            conn.commit()
            logger.info("Transaction committed.")
        else:
            conn.rollback()
    except Exception as exc:
        conn.rollback()
        logger.error("Rolled back: %s", exc)
        raise
    finally:
        conn.close()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for csp, t in totals.items():
        print(f"  {csp.upper():<8} enabled={t['enabled']:>4}  inserted={t['inserted']:>4}  skipped={t['skipped']:>4}")
    print("=" * 60)


if __name__ == "__main__":
    main()
