#!/usr/bin/env python3
"""
Validate and fix Azure check rule for_each + var against step4 field catalogs.

Two-phase approach:
  Phase 1: Assign for_each to checks missing it (using metadata resource_type)
  Phase 2: Validate var fields against step4 final_union for the for_each service

Usage:
  python3 validate_and_fix_checks_vs_step4.py --dry-run   # audit only, no file changes
  python3 validate_and_fix_checks_vs_step4.py              # fix files in place
"""

import json
import yaml
import glob
import os
import re
import sys
from collections import defaultdict

DRY_RUN = '--dry-run' in sys.argv

CHECK_DIR = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rule_check"
STEP4_DIR = "/Users/apple/Desktop/threat-engine/catalog/python_field_generator/azure"
META_DIR = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rule_metadata"

# ═══════════════════════════════════════════════════════════════════════════════
# 1. LOAD ALL DATA SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

# Step4 fields per service
svc_fields = {}
svc_ops = {}  # service → list of discovery ops from response_emit_map
for f in glob.glob(f"{STEP4_DIR}/*/step4_fields_produced_index.json"):
    svc_dir = os.path.basename(os.path.dirname(f))
    with open(f) as fh:
        data = json.load(fh)
    fields = set(data.get("final_union", []))
    svc_fields[svc_dir] = fields
    rem = data.get("response_emit_map", {})
    ops = list(rem.keys()) if isinstance(rem, dict) else (rem if isinstance(rem, list) else [])
    svc_ops[svc_dir] = ops

# Metadata: rule_id → resource_type
rule_meta = {}
for f in glob.glob(f"{META_DIR}/*/*.yaml"):
    try:
        with open(f) as fh:
            m = yaml.safe_load(fh)
        if m and m.get('rule_id'):
            rule_meta[m['rule_id']] = m
    except:
        pass

print(f"Loaded: {len(svc_fields)} step4 services, {len(rule_meta)} metadata rules")

# ═══════════════════════════════════════════════════════════════════════════════
# 2. ARM RESOURCE TYPE → DISCOVERY OPERATION MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

# ARM namespace → step4 directory
ARM_NS_MAP = {
    'microsoft.aad': 'azureactivedirectory',
    'microsoft.apimanagement': 'apimanagement',
    'microsoft.app': 'app',
    'microsoft.appconfiguration': 'appconfiguration',
    'microsoft.appplatform': 'appplatform',
    'microsoft.attestation': 'attestation',
    'microsoft.authorization': 'authorization',
    'microsoft.automation': 'automation',
    'microsoft.azureactivedirectory': 'azureactivedirectory',
    'microsoft.azurearcdata': 'azurearcdata',
    'microsoft.azurestackhci': 'azurestackhci',
    'microsoft.batch': 'batch',
    'microsoft.billing': 'billing',
    'microsoft.botservice': 'botservice',
    'microsoft.cache': 'redis',
    'microsoft.cdn': 'cdn',
    'microsoft.changeanalysis': 'changeanalysis',
    'microsoft.cognitiveservices': 'cognitiveservices',
    'microsoft.communication': 'communication',
    'microsoft.compute': 'compute',
    'microsoft.containerinstance': 'containerinstance',
    'microsoft.containerregistry': 'containerregistry',
    'microsoft.containerservice': 'containerservice',
    'microsoft.costmanagement': 'costmanagement',
    'microsoft.dashboard': 'dashboard',
    'microsoft.databox': 'databox',
    'microsoft.databoxedge': 'databoxedge',
    'microsoft.databricks': 'databricks',
    'microsoft.datafactory': 'datafactory',
    'microsoft.datalakeanalytics': 'datalake-analytics',
    'microsoft.datalakestore': 'datalake-store',
    'microsoft.dbformariadb': 'rdbms_mariadb',
    'microsoft.dbformysql': 'rdbms_mysql',
    'microsoft.dbforpostgresql': 'rdbms_postgresql',
    'microsoft.desktopvirtualization': 'desktopvirtualization',
    'microsoft.devcenter': 'devcenter',
    'microsoft.devices': 'iothub',
    'microsoft.digitaltwins': 'digitaltwins',
    'microsoft.documentdb': 'cosmosdb',
    'microsoft.elasticsan': 'elasticsan',
    'microsoft.eventgrid': 'eventgrid',
    'microsoft.eventhub': 'eventhub',
    'microsoft.frontdoor': 'frontdoor',
    'microsoft.guestconfiguration': 'guestconfiguration',
    'microsoft.hdinsight': 'hdinsight',
    'microsoft.healthbot': 'healthbot',
    'microsoft.healthcareapis': 'healthcareapis',
    'microsoft.hybridcompute': 'hybridcompute',
    'microsoft.insights': 'monitor',
    'microsoft.keyvault': 'keyvault',
    'microsoft.kusto': 'kusto',
    'microsoft.labservices': 'labservices',
    'microsoft.logic': 'logic',
    'microsoft.machinelearningservices': 'machinelearningservices',
    'microsoft.maintenance': 'maintenance',
    'microsoft.managedidentity': 'msi',
    'microsoft.managedservices': 'managedservices',
    'microsoft.management': 'managementgroups',
    'microsoft.maps': 'maps',
    'microsoft.media': 'media',
    'microsoft.mobilenetwork': 'mobilenetwork',
    'microsoft.monitor': 'monitor',
    'microsoft.network': 'network',
    'microsoft.operationalinsights': 'loganalytics',
    'microsoft.policyinsights': 'policyinsights',
    'microsoft.portal': 'portal',
    'microsoft.powerbidedicated': 'powerbidedicated',
    'microsoft.purview': 'purview',
    'microsoft.recoveryservices': 'recoveryservices',
    'microsoft.resources': 'resources',
    'microsoft.search': 'search',
    'microsoft.security': 'security',
    'microsoft.servicebus': 'servicebus',
    'microsoft.servicefabric': 'servicefabric',
    'microsoft.signalrservice': 'signalr',
    'microsoft.sql': 'sql',
    'microsoft.storage': 'storage',
    'microsoft.streamanalytics': 'streamanalytics',
    'microsoft.subscription': 'subscription',
    'microsoft.synapse': 'synapse',
    'microsoft.web': 'web',
    'microsoft.webpubsub': 'webpubsub',
}

# Check service directory → step4 directory
SVC_MAP = {
    'active_directory': 'azureactivedirectory',
    'aks': 'containerservice',
    'api': 'apimanagement',
    'api_for_fhir': 'healthcareapis',
    'api_management': 'apimanagement',
    'app_configuration': 'appconfiguration',
    'app_platform': 'appplatform',
    'app_service': 'web',
    'attestation': 'attestation',
    'authorization': 'authorization',
    'automanage': 'compute',
    'automatic_update': 'maintenance',
    'automation': 'automation',
    'azure_active_directory': 'azureactivedirectory',
    'azure_ai_services': 'cognitiveservices',
    'azure_arc': 'hybridcompute',
    'azure_data_explorer': 'kusto',
    'azure_databricks': 'databricks',
    'azure_edge_hardware_center': 'edgeorder',
    'azure_load_testing': 'loadtesting',
    'azure_stack_edge': 'databoxedge',
    'azure_update_manager': 'compute',
    'backup': 'recoveryservices',
    'batch': 'batch',
    'billing': 'billing',
    'bot_service': 'botservice',
    'cache': 'redis',
    'cdn': 'cdn',
    'changetrackingandinventory': 'compute',
    'cognitive_services': 'cognitiveservices',
    'communication': 'communication',
    'compute': 'compute',
    'container': 'containerinstance',
    'container_apps': 'app',
    'container_instance': 'containerinstance',
    'container_instances': 'containerinstance',
    'container_registry': 'containerregistry',
    'cosmos_db': 'cosmosdb',
    'cost_management': 'costmanagement',
    'data_box': 'databox',
    'data_factory': 'datafactory',
    'data_lake': 'datalake-store',
    'data_lake_analytics': 'datalake-analytics',
    'desktop_virtualization': 'desktopvirtualization',
    'devcenter': 'devcenter',
    'dns': 'dns',
    'elasticsan': 'elasticsan',
    'event_grid': 'eventgrid',
    'event_hub': 'eventhub',
    'event_hubs': 'eventhub',
    'front_door': 'frontdoor',
    'guest_configuration': 'compute',
    'hdinsight': 'hdinsight',
    'health_bot': 'healthbot',
    'health_deidentification_service': 'healthcareapis',
    'healthcare_apis': 'healthcareapis',
    'internet_of_things': 'iothub',
    'key_vault': 'keyvault',
    'kubernetes': 'containerservice',
    'kusto': 'kusto',
    'lab_services': 'labservices',
    'lighthouse': 'managedservices',
    'logic_apps': 'logic',
    'loganalytics': 'loganalytics',
    'machine_learning': 'machinelearningservices',
    'managed_application': 'resource',
    'managed_grafana': 'dashboard',
    'managed_identity': 'msi',
    'management_groups': 'managementgroups',
    'maps': 'maps',
    'mariadb': 'rdbms_mariadb',
    'media_services': 'media',
    'mobile_network': 'mobilenetwork',
    'monitor': 'monitor',
    'monitoring': 'monitor',
    'mysql': 'rdbms_mysql',
    'network': 'network',
    'policy': 'policyinsights',
    'postgresql': 'rdbms_postgresql',
    'power_bi': 'powerbidedicated',
    'purview': 'purview',
    'rbac': 'authorization',
    'resilience': 'advisor',
    'resource_groups': 'resources',
    'search': 'search',
    'security_center': 'security',
    'security_center_-_granular_pricing': 'security',
    'service_bus': 'servicebus',
    'service_fabric': 'servicefabric',
    'signalr': 'signalr',
    'site_recovery': 'recoveryservices',
    'sql': 'sql',
    'sql_managed_instance': 'sql',
    'sql_server': 'sql',
    'stack_hci': 'azurestackhci',
    'storage': 'storage',
    'stream_analytics': 'streamanalytics',
    'subscription': 'subscription',
    'synapse': 'synapse',
    'tags': 'resources',
    'traffic_manager': 'trafficmanager',
    'trusted_launch': 'compute',
    'vm_image_builder': 'imagebuilder',
    'web': 'web',
    'web_pubsub': 'webpubsub',
}

# Services where checks are inherently assertion-only (no ARM discovery possible)
ASSERTION_ONLY_SERVICES = {
    'active_directory', 'azure_active_directory',  # Needs Microsoft Graph API
    'data_lake_analytics',  # Deprecated service
}

# Universal fields present in ARM responses
UNIVERSAL_FIELDS = {
    'id', 'name', 'type', 'location', 'tags', 'properties',
    'provisioning_state', 'etag', 'identity', 'sku', 'kind', 'zones',
}


# ═══════════════════════════════════════════════════════════════════════════════
# 3. BUILD for_each RESOLUTION: resource_type → best list operation
# ═══════════════════════════════════════════════════════════════════════════════

def find_list_op_for_resource(resource_type):
    """Find the best step4 list operation for an ARM resource type."""
    if not resource_type:
        return None, None

    parts = resource_type.split('/')
    if len(parts) < 2:
        return None, None

    arm_ns = parts[0].lower()
    res_name = parts[1].lower()

    step4_ns = ARM_NS_MAP.get(arm_ns)
    if not step4_ns or step4_ns not in svc_ops:
        return None, None

    ops = [o for o in svc_ops[step4_ns] if '..' not in o]

    # Find list ops matching the resource type
    candidates = []
    for op in ops:
        op_parts = op.split('.')
        if len(op_parts) >= 4 and op_parts[0] == 'azure':
            op_res = op_parts[2].lower()
            op_action = op_parts[3]
            if 'list' in op_action and (
                op_res == res_name or
                res_name in op_res or
                op_res in res_name
            ):
                # Prefer broader list operations
                priority = {
                    'list': 1, 'list_by_subscription': 2,
                    'list_all': 3, 'list_by_resource_group': 4,
                }
                p = priority.get(op_action, 10)
                candidates.append((op, p, abs(len(op_res) - len(res_name))))

    if candidates:
        # Sort by priority then by name distance
        candidates.sort(key=lambda x: (x[1], x[2]))
        return candidates[0][0], step4_ns

    # Fallback: any list op for the namespace's primary resource
    primary_ops = [op for op in ops if '.list' in op and
                   not op.endswith('.list') or 'list_by' in op or 'list_all' in op]
    if primary_ops:
        return primary_ops[0], step4_ns

    return None, step4_ns


# Manual overrides for common resource types that don't match well
RESOURCE_TYPE_TO_OP = {
    'Microsoft.Compute/virtualMachines': 'azure.compute.virtualmachines.list_all',
    'Microsoft.Compute/virtualMachineScaleSets': 'azure.compute.virtualmachinescalesets.list_all',
    'Microsoft.Compute/disks': 'azure.compute.disks.list',
    'Microsoft.Web/sites': 'azure.web.webapps.list_by_resource_group',
    'Microsoft.Web/serverfarms': 'azure.web.appserviceplans.list',
    'Microsoft.ApiManagement/service': 'azure.apimanagement.apimanagementservice.list',
    'Microsoft.Storage/storageAccounts': 'azure.storage.storageaccounts.list',
    'Microsoft.Network/networkSecurityGroups': 'azure.network.networksecuritygroups.list_all',
    'Microsoft.Network/virtualNetworks': 'azure.network.virtualnetworks.list_all',
    'Microsoft.Network/publicIPAddresses': 'azure.network.publicipaddresses.list_all',
    'Microsoft.Network/loadBalancers': 'azure.network.loadbalancers.list_all',
    'Microsoft.Network/applicationGateways': 'azure.network.applicationgateways.list_all',
    'Microsoft.Network/azureFirewalls': 'azure.network.azurefirewalls.list_all',
    'Microsoft.KeyVault/vaults': 'azure.keyvault.vaults.list_by_subscription',
    'Microsoft.Sql/servers': 'azure.sql.servers.list',
    'Microsoft.Sql/managedInstances': 'azure.sql.managedinstances.list',
    'Microsoft.ContainerService/managedClusters': 'azure.containerservice.managedclusters.list',
    'Microsoft.ContainerInstance/containerGroups': 'azure.containerinstance.containergroups.list',
    'Microsoft.DocumentDB/databaseAccounts': 'azure.cosmosdb.databaseaccounts.list',
    'Microsoft.ContainerRegistry/registries': 'azure.containerregistry.registries.list',
    'Microsoft.EventHub/namespaces': 'azure.eventhub.namespaces.list',
    'Microsoft.ServiceBus/namespaces': 'azure.servicebus.namespaces.list',
    'Microsoft.Logic/workflows': 'azure.logic.workflows.list_by_subscription',
    'Microsoft.Automation/automationAccounts': 'azure.automation.automationaccount.list',
    'Microsoft.Batch/batchAccounts': 'azure.batch.batchaccount.list',
    'Microsoft.CognitiveServices/accounts': 'azure.cognitiveservices.accounts.list',
    'Microsoft.SignalRService/SignalR': 'azure.signalr.signalr.list_by_subscription',
    'Microsoft.Kusto/clusters': 'azure.kusto.clusters.list',
    'Microsoft.DesktopVirtualization/hostpools': 'azure.desktopvirtualization.hostpools.list',
    'Microsoft.Synapse/workspaces': 'azure.synapse.workspaces.list',
    'Microsoft.HDInsight/clusters': 'azure.hdinsight.clusters.list',
    'Microsoft.StreamAnalytics/streamingjobs': 'azure.streamanalytics.streamingjobs.list',
    'Microsoft.Insights/components': 'azure.applicationinsights.components.list',
    'Microsoft.OperationalInsights/workspaces': 'azure.loganalytics.workspaces.list',
    'Microsoft.MachineLearningServices/workspaces': 'azure.machinelearningservices.workspaces.list_by_subscription',
    'Microsoft.DataFactory/factories': 'azure.datafactory.factories.list',
    'Microsoft.DBforMySQL/servers': 'azure.rdbms_mysql.servers.servers_list',
    'Microsoft.DBforMySQL/flexibleServers': 'azure.rdbms_mysql_flexibleservers.servers.list',
    'Microsoft.DBforPostgreSQL/servers': 'azure.rdbms_postgresql.servers.servers_list',
    'Microsoft.DBforPostgreSQL/flexibleServers': 'azure.rdbms_postgresql_flexibleservers.servers.list',
    'Microsoft.DBforMariaDB/servers': 'azure.rdbms_mariadb.servers.servers_list',
    'Microsoft.Cache/Redis': 'azure.redis.redis.list',
    'Microsoft.Cache/redis': 'azure.redis.redis.list',
    'Microsoft.Cdn/profiles': 'azure.cdn.profiles.list',
    'Microsoft.Cdn/Profiles': 'azure.cdn.profiles.list',
    'Microsoft.Network/frontDoors': 'azure.frontdoor.frontdoors.list',
    'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies': 'azure.frontdoor.policies.list',
    'Microsoft.HybridCompute/machines': 'azure.hybridcompute.machines.list_by_resource_group',
    'Microsoft.RecoveryServices/vaults': 'azure.recoveryservices.vaults.list_by_subscription_id',
    'Microsoft.ManagedIdentity/userAssignedIdentities': 'azure.msi.userassignedidentities.list_by_subscription',
    'Microsoft.Authorization/roleDefinitions': 'azure.authorization.roledefinitions.list',
    'Microsoft.Authorization/roleAssignments': 'azure.authorization.roleassignments.list',
    'Microsoft.EventGrid/topics': 'azure.eventgrid.topics.list_by_subscription',
    'Microsoft.EventGrid/domains': 'azure.eventgrid.domains.list_by_subscription',
    'Microsoft.App/containerApps': 'azure.app.containerapps.list_by_subscription',
    'Microsoft.App/managedEnvironments': 'azure.app.managedenvironments.list_by_subscription',
    'Microsoft.Databricks/workspaces': 'azure.databricks.workspaces.list_by_resource_group',
    'Microsoft.Purview/accounts': 'azure.purview.accounts.list_by_subscription',
    'Microsoft.Communication/CommunicationServices': 'azure.communication.communicationservices.list_by_subscription',
    'Microsoft.BotService/botServices': 'azure.botservice.bots.list',
    'Microsoft.Search/searchServices': 'azure.search.services.list_by_subscription',
    'Microsoft.Maps/accounts': 'azure.maps.accounts.list_by_subscription',
    'Microsoft.HealthcareApis/services': 'azure.healthcareapis.services.list',
    'Microsoft.Devices/IotHubs': 'azure.iothub.iothubresource.list_by_subscription',
    'Microsoft.Monitor/accounts': 'azure.monitor.azuremonitorworkspaces.list_by_subscription',
    'Microsoft.HybridCompute/machines': 'azure.hybridcompute.machines.list_by_resource_group',
    'Microsoft.Insights/scheduledQueryRules': 'azure.monitor.scheduledqueryrules.list_by_subscription',
    'Microsoft.Insights/activityLogAlerts': 'azure.monitor.activitylogalerts.list_by_subscription_id',
    'Microsoft.Insights/metricAlerts': 'azure.monitor.metricalerts.list_by_subscription',
    'Microsoft.Insights/dataCollectionRules': 'azure.monitor.datacollectionrules.list_by_subscription',
    'Microsoft.Network/frontdoorWebApplicationFirewallPolicies': 'azure.frontdoor.policies.list',
    'Microsoft.Compute/virtualMachines/extensions': 'azure.compute.virtualmachineextensions.list',
    'Microsoft.Security/pricings': 'azure.security.pricings.list',
    'Microsoft.DataProtection/backupVaults': 'azure.dataprotection.backupvaults.list_by_resource_group',
    'Microsoft.DataProtection/backupvaults': 'azure.dataprotection.backupvaults.list_by_resource_group',
    'Microsoft.RecoveryServices/vaults': 'azure.recoveryservices.vaults.list_by_subscription_id',
    'Microsoft.RecoveryServices/Vaults': 'azure.recoveryservices.vaults.list_by_subscription_id',
    'Microsoft.StreamAnalytics/StreamingJobs': 'azure.streamanalytics.streamingjobs.list',
    'Microsoft.Sql/servers/databases': 'azure.sql.databases.list_by_server',
    'Microsoft.AppConfiguration/configurationStores': 'azure.appconfiguration.configurationstores.list',
    'Microsoft.ContainerService/managedClusters': 'azure.containerservice.managedclusters.list',
    'microsoft.insights/components': 'azure.applicationinsights.components.list',
    'microsoft.compute/virtualmachines': 'azure.compute.virtualmachines.list_all',
    'microsoft.compute/virtualmachinescalesets': 'azure.compute.virtualmachinescalesets.list_all',
    'microsoft.hybridcompute/machines': 'azure.hybridcompute.machines.list_by_resource_group',
    'microsoft.network/azurefirewalls': 'azure.network.azurefirewalls.list_all',
    'microsoft.desktopvirtualization/applicationgroups': 'azure.desktopvirtualization.applicationgroups.list_by_resource_group',
    'microsoft.aad/domainservices': 'azure.azureactivedirectory.domainservices.list',
    'microsoft.dbforpostgresql/flexibleservers': 'azure.rdbms_postgresql_flexibleservers.servers.list',
    'microsoft.dbformysql/flexibleservers': 'azure.rdbms_mysql_flexibleservers.servers.list',
}


def get_for_each_for_rule(rule_id, check_svc):
    """Determine the best for_each for a rule."""
    meta = rule_meta.get(rule_id, {})
    resource_type = meta.get('resource_type')

    # Try manual override first
    if resource_type and resource_type in RESOURCE_TYPE_TO_OP:
        op = RESOURCE_TYPE_TO_OP[resource_type]
        ns = op.split('.')[1] if len(op.split('.')) >= 2 else None
        return op, ns

    # Try to resolve from resource_type
    if resource_type:
        op, ns = find_list_op_for_resource(resource_type)
        if op:
            return op, ns

    # Fallback: use check service → step4 mapping
    step4_ns = SVC_MAP.get(check_svc)
    if step4_ns and step4_ns in svc_ops:
        # Find the primary list operation (skip malformed double-dot ops)
        ops = svc_ops[step4_ns]
        list_ops = [o for o in ops if '.list' in o and '..' not in o]
        # Prefer list_by_subscription or list
        for suffix in ['list_by_subscription', 'list', 'list_all', 'list_by_resource_group']:
            matches = [o for o in list_ops if o.endswith('.' + suffix)]
            if matches:
                return matches[0], step4_ns

    return None, SVC_MAP.get(check_svc)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FIELD MATCHING LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def find_best_field(var_field, available_fields):
    """Try to find the best matching step4 field for a check var field."""
    if var_field in available_fields:
        return var_field

    lower_map = {f.lower(): f for f in available_fields}
    if var_field.lower() in lower_map:
        return lower_map[var_field.lower()]

    # camelCase → snake_case
    snake = re.sub(r'(?<!^)(?=[A-Z])', '_', var_field).lower()
    if snake in available_fields:
        return snake

    # Fix common ARM → step4 patterns
    # image_s_k_u → sku (Azure Policy artifact)
    if var_field == 'image_s_k_u':
        if 'sku' in available_fields:
            return 'sku'
    if var_field == 'image_publisher':
        if 'publisher' in available_fields:
            return 'publisher'
    if var_field == 'image_offer':
        if 'offer' in available_fields:
            return 'offer'
    if var_field == 'image_sku':
        if 'sku' in available_fields:
            return 'sku'

    # azure_a_d_only_authentication → active_directory_auth or similar
    if 'azure_a_d_only' in var_field:
        candidates = [f for f in available_fields if 'active_directory' in f.lower() or 'azure_ad' in f.lower()]
        if len(candidates) == 1:
            return candidates[0]

    # Remove common prefixes
    for prefix in ['is_', 'enable_', 'disable_', 'allow_', 'has_']:
        if var_field.startswith(prefix):
            without = var_field[len(prefix):]
            if without in available_fields:
                return without
        with_prefix = prefix + var_field
        if with_prefix in available_fields:
            return with_prefix

    # Substring match (if unique)
    matches = [f for f in available_fields if var_field.lower() in f.lower()]
    if len(matches) == 1:
        return matches[0]

    return None


def get_step4_fields(for_each_op, check_svc):
    """Get the step4 fields for a given for_each operation."""
    if for_each_op:
        # Extract namespace from for_each: azure.{namespace}.{resource}.{op}
        parts = for_each_op.split('.')
        if len(parts) >= 2:
            ns = parts[1]
            if ns in svc_fields:
                return svc_fields[ns] | UNIVERSAL_FIELDS, ns

    # Fallback to check service mapping
    step4_ns = SVC_MAP.get(check_svc)
    if step4_ns and step4_ns in svc_fields:
        return svc_fields[step4_ns] | UNIVERSAL_FIELDS, step4_ns

    return UNIVERSAL_FIELDS, None


def validate_var(var_str, available_fields):
    """
    Validate and fix a var string against step4 fields.
    Returns (new_var, status) where status is 'valid', 'fixed', or 'invalid'.
    """
    if not var_str or not var_str.startswith('item.'):
        return var_str, 'valid'

    # Skip Azure Policy template expressions (not real fields)
    if '[concat(' in var_str or '[parameters(' in var_str:
        return None, 'invalid'

    # Skip array indexing patterns that are Azure Policy artifacts
    if '[*]' in var_str:
        return None, 'invalid'

    rest = var_str[5:]  # strip 'item.'
    parts = rest.split('.')
    top_field = parts[0]

    # Already valid
    if top_field in available_fields:
        return var_str, 'valid'

    # Try fuzzy match
    match = find_best_field(top_field, available_fields)
    if match:
        parts[0] = match
        return 'item.' + '.'.join(parts), 'fixed'

    # Flatten item.properties.X → item.X
    if top_field == 'properties' and len(parts) > 1:
        sub_field = parts[1]
        sub_match = find_best_field(sub_field, available_fields)
        if sub_match:
            remaining = parts[2:]
            new_parts = [sub_match] + remaining
            return 'item.' + '.'.join(new_parts), 'fixed'

    # Try joining parts with underscore (e.g., security_profile → security_profile)
    if len(parts) >= 2:
        joined = '_'.join(parts[:2])
        jmatch = find_best_field(joined, available_fields)
        if jmatch:
            remaining = parts[2:]
            new_parts = [jmatch] + remaining
            return 'item.' + '.'.join(new_parts), 'fixed'

    return None, 'invalid'


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PROCESS ALL CHECK FILES
# ═══════════════════════════════════════════════════════════════════════════════

stats = defaultdict(int)
fix_log = []
fe_log = []  # for_each assignments
invalid_log = []
ao_services = []  # services marked entirely assertion_only

for svc_dir_path in sorted(glob.glob(f'{CHECK_DIR}/*/')):
    svc = os.path.basename(svc_dir_path.rstrip('/'))
    cf = os.path.join(svc_dir_path, f'{svc}.checks.yaml')
    if not os.path.exists(cf):
        continue

    with open(cf) as f:
        data = yaml.safe_load(f)

    if data.get('status') == 'assertion_only':
        stats['svc_already_ao'] += 1
        continue

    # Mark assertion-only services
    if svc in ASSERTION_ONLY_SERVICES:
        stats['svc_assertion_only'] += 1
        ao_services.append(svc)
        continue

    modified = False

    for check in data.get('checks', []):
        if check.get('status') == 'assertion_only':
            stats['check_already_ao'] += 1
            continue

        rule_id = check.get('rule_id', '')

        # --- Phase 1: Ensure for_each is set ---
        if not check.get('for_each'):
            fe_op, fe_ns = get_for_each_for_rule(rule_id, svc)
            if fe_op:
                if not DRY_RUN:
                    check['for_each'] = fe_op
                stats['fe_assigned'] += 1
                fe_log.append((svc, rule_id, fe_op))
                modified = True
            else:
                # No discovery op available
                stats['fe_not_found'] += 1
                invalid_log.append((svc, rule_id, 'NO_FOR_EACH', '', 'no_discovery_op'))
                if not DRY_RUN:
                    check['status'] = 'assertion_only'
                    check['note'] = f'No discovery operation found for {svc}'
                    if 'conditions' in check:
                        del check['conditions']
                modified = True
                continue

        # --- Phase 2: Validate vars ---
        fe_op = check.get('for_each', fe_op if not check.get('for_each') else check['for_each'])
        available_fields, step4_ns = get_step4_fields(fe_op, svc)

        if not available_fields or available_fields == UNIVERSAL_FIELDS:
            # Step4 has no real fields for this service
            step4_ns_check = SVC_MAP.get(svc)
            if step4_ns_check and step4_ns_check in svc_fields and len(svc_fields[step4_ns_check]) == 0:
                # Empty step4 → assertion_only
                if not DRY_RUN:
                    check['status'] = 'assertion_only'
                    check['note'] = f'Step4 for {step4_ns_check} has no fields'
                    if 'conditions' in check:
                        del check['conditions']
                    if 'for_each' in check:
                        del check['for_each']
                stats['empty_step4'] += 1
                modified = True
                continue

        cond = check.get('conditions')
        if not cond:
            stats['no_conditions'] += 1
            continue

        state = {'invalid': False, 'modified': False}

        def process_condition(c):
            if not isinstance(c, dict) or state['invalid']:
                return

            if 'var' in c:
                var = c['var']
                if var and var.startswith('item.'):
                    new_var, status = validate_var(var, available_fields)
                    if status == 'valid':
                        stats['var_valid'] += 1
                    elif status == 'fixed':
                        if not DRY_RUN:
                            c['var'] = new_var
                        stats['var_fixed'] += 1
                        fix_log.append((svc, rule_id, var, new_var))
                        state['modified'] = True
                    else:  # invalid
                        stats['var_invalid'] += 1
                        invalid_log.append((svc, rule_id, var, step4_ns or '', 'no_match'))
                        state['invalid'] = True
                        return

            if 'all' in c:
                for sub in c['all']:
                    process_condition(sub)
            if 'any' in c:
                for sub in c['any']:
                    process_condition(sub)

        process_condition(cond)
        if state['modified']:
            modified = True

        if state['invalid']:
            if not DRY_RUN:
                check['status'] = 'assertion_only'
                check['note'] = f'Var field not in step4 for {step4_ns or svc}'
                if 'conditions' in check:
                    del check['conditions']
                if 'for_each' in check:
                    del check['for_each']
            stats['check_assertion_only'] += 1
            modified = True

    if modified:
        if not DRY_RUN:
            with open(cf, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=200)
        stats['files_modified'] += 1


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════════

print("=" * 70)
print("AZURE CHECK vs STEP4 VALIDATION RESULTS")
print("=" * 70)

print(f"\n  FOR_EACH:")
print(f"    Assigned:              {stats['fe_assigned']}")
print(f"    No discovery op:       {stats['fe_not_found']}")

print(f"\n  VAR FIELDS:")
print(f"    Valid (in step4):      {stats['var_valid']}")
print(f"    Fixed (remapped):      {stats['var_fixed']}")
print(f"    Invalid (no match):    {stats['var_invalid']}")

print(f"\n  CHECKS:")
print(f"    Already assertion_only:{stats['check_already_ao']}")
print(f"    → assertion_only:      {stats['check_assertion_only']}")
print(f"    Empty step4:           {stats['empty_step4']}")
print(f"    No conditions:         {stats['no_conditions']}")

print(f"\n  FILES modified:          {stats['files_modified']}")

if fix_log:
    print(f"\nFIELD REMAPPINGS ({len(fix_log)} total):")
    by_pattern = defaultdict(int)
    for svc, rid, old, new in fix_log:
        by_pattern[f"{old} → {new}"] += 1
    for pattern, count in sorted(by_pattern.items(), key=lambda x: -x[1])[:30]:
        print(f"  {pattern}: {count}")

if fe_log:
    print(f"\nFOR_EACH ASSIGNMENTS ({len(fe_log)} total):")
    by_op = defaultdict(int)
    for svc, rid, op in fe_log:
        by_op[op] += 1
    for op, count in sorted(by_op.items(), key=lambda x: -x[1])[:30]:
        print(f"  {op}: {count}")

if invalid_log:
    print(f"\nINVALID → assertion_only ({len(invalid_log)} total):")
    by_svc = defaultdict(int)
    for svc, rid, var, s4, reason in invalid_log:
        by_svc[svc] += 1
    for svc, count in sorted(by_svc.items(), key=lambda x: -x[1])[:20]:
        print(f"  {svc}: {count}")

    print(f"\nTOP UNMATCHED FIELD PATTERNS:")
    field_counts = defaultdict(int)
    for svc, rid, var, s4, reason in invalid_log:
        if var.startswith('item.'):
            top = var[5:].split('.')[0]
            field_counts[top] += 1
        elif var == 'NO_FOR_EACH':
            field_counts['NO_FOR_EACH'] += 1
    for field, count in sorted(field_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"  {field}: {count}")

total_active = stats['var_valid'] + stats['var_fixed']
total_checked = total_active + stats['var_invalid']
if total_checked:
    print(f"\nSUCCESS RATE: {total_active}/{total_checked} ({100*total_active/total_checked:.1f}%) vars validated")

if DRY_RUN:
    print(f"\n*** DRY RUN — no files were modified ***")
