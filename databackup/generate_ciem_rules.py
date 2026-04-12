#!/usr/bin/env python3
"""
CIEM Log Rule Generator — Azure / GCP / OCI / IBM
Generates INSERT SQL for rule_checks + rule_metadata.
Run: python generate_ciem_rules.py

Parser → log_events field mapping:
  Azure  — service=lowercased ARM provider, operation=full ARM operationName
           check_config: source_type=azure_activity + operation=<full ARM op>
  GCP    — service=full googleapis.com URI, operation=full methodName
           check_config: source_type=gcp_audit + service=<full.googleapis.com> + operation contains <method>
  OCI    — service=full CADF domain (lowercased), operation=PascalCase last segment
           check_config: source_type=oci_audit + service=<com.oraclecloud.x> + operation=<PascalCase>
  IBM    — service=first CADF segment underscored, operation=full CADF action
           check_config: source_type=ibm_activity + service=<first_seg> + operation contains .<verb>
"""

import json
import re
import os
from typing import Dict, List, Tuple


def to_snake(s: str) -> str:
    s = re.sub(r'[/\.\-]', '_', s)
    s = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', s)
    s = re.sub(r'__+', '_', s)
    return s.lower().strip('_')


def infer_action_category(tokens: str) -> str:
    t = tokens.lower()
    if any(w in t for w in ['delete','remove','deregister','detach','terminate','disable',
                             'cancel','revoke','deprovision','destroy','drop','purge']):
        return 'delete'
    if any(w in t for w in ['create','insert','add','put','register','attach','launch',
                             'allocate','publish','write','grant','deploy','enable']):
        return 'create'
    if any(w in t for w in ['update','modify','change','set','patch','replace','rotate',
                             'restore','resize','scale','tag','untag','reset','reboot',
                             'start','stop','suspend','flush','move','link','alter']):
        return 'modify'
    if any(w in t for w in ['get','list','describe','read','show','query','search',
                             'validate','export','download','fetch']):
        return 'read'
    return 'modify'


MITRE = {
    'create': ('["persistence"]',  '["T1136"]'),
    'delete': ('["impact"]',        '["T1485"]'),
    'modify': ('["persistence"]',   '["T1098"]'),
    'read':   ('["discovery"]',     '["T1526"]'),
}
SEVERITY   = {'create': 'high', 'delete': 'high', 'modify': 'medium', 'read': 'low'}
RISK_SCORE = {'create': 70,     'delete': 75,     'modify': 55,       'read': 30}


def sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _cfg(conds: list) -> str:
    return sql_str(json.dumps({"conditions": {"all": conds}}, separators=(',', ':')))


def azure_cfg(arm_op: str) -> str:
    return _cfg([
        {"op": "equals",   "field": "source_type", "value": "azure_activity"},
        {"op": "equals",   "field": "operation",   "value": arm_op},
    ])


def gcp_cfg(full_uri: str, method: str) -> str:
    return _cfg([
        {"op": "equals",   "field": "source_type", "value": "gcp_audit"},
        {"op": "equals",   "field": "service",     "value": full_uri},
        {"op": "contains", "field": "operation",   "value": method},
    ])


def oci_cfg(cadf: str, op: str) -> str:
    return _cfg([
        {"op": "equals", "field": "source_type", "value": "oci_audit"},
        {"op": "equals", "field": "service",     "value": cadf},
        {"op": "equals", "field": "operation",   "value": op},
    ])


def ibm_cfg(svc: str, verb: str) -> str:
    return _cfg([
        {"op": "equals",   "field": "source_type", "value": "ibm_activity"},
        {"op": "equals",   "field": "service",     "value": svc},
        {"op": "contains", "field": "operation",   "value": f".{verb}"},
    ])


def emit(f, rule_id, service, provider, title, desc, domain, cat, log_src, audit_event, cfg):
    tactics, techniques = MITRE.get(cat, ('["persistence"]', '["T1098"]'))
    sev  = SEVERITY.get(cat, 'medium')
    risk = RISK_SCORE.get(cat, 55)
    f.write(
        f"INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)\n"
        f"VALUES ({sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},'log',true,{cfg})\n"
        f"ON CONFLICT DO NOTHING;\n\n"
    )
    f.write(
        f"INSERT INTO rule_metadata (\n"
        f"  rule_id,service,provider,severity,title,description,\n"
        f"  domain,subcategory,log_source_type,audit_log_event,action_category,\n"
        f"  rule_source,engines,primary_engine,\n"
        f"  mitre_tactics,mitre_techniques,risk_score,quality,csp\n"
        f") VALUES (\n"
        f"  {sql_str(rule_id)},{sql_str(service)},{sql_str(provider)},\n"
        f"  {sql_str(sev)},{sql_str(title)},{sql_str(desc)},\n"
        f"  {sql_str(domain)},{sql_str(cat)},{sql_str(log_src)},\n"
        f"  {sql_str(audit_event)},{sql_str(cat)},\n"
        f"  'log','{{\"ciem_engine\"}}','ciem_engine',\n"
        f"  '{tactics}','{techniques}',{risk},'auto',{sql_str(provider)}\n"
        f") ON CONFLICT DO NOTHING;\n\n"
    )


# ---------------------------------------------------------------------------
# GCP service short → full googleapis.com URI
# ---------------------------------------------------------------------------
GCP_SVC: Dict[str, str] = {
    "compute":              "compute.googleapis.com",
    "iam":                  "iam.googleapis.com",
    "storage":              "storage.googleapis.com",
    "container":            "container.googleapis.com",
    "sqladmin":             "sqladmin.googleapis.com",
    "cloudkms":             "cloudkms.googleapis.com",
    "pubsub":               "pubsub.googleapis.com",
    "cloudfunctions":       "cloudfunctions.googleapis.com",
    "run":                  "run.googleapis.com",
    "bigquery":             "bigquery.googleapis.com",
    "spanner":              "spanner.googleapis.com",
    "logging":              "logging.googleapis.com",
    "dns":                  "dns.googleapis.com",
    "appengine":            "appengine.googleapis.com",
    "redis":                "redis.googleapis.com",
    "dataproc":             "dataproc.googleapis.com",
    "bigtableadmin":        "bigtableadmin.googleapis.com",
    "firestore":            "firestore.googleapis.com",
    "secretmanager":        "secretmanager.googleapis.com",
    "accesscontextmanager": "accesscontextmanager.googleapis.com",
    "artifactregistry":     "artifactregistry.googleapis.com",
    "cloudbuild":           "cloudbuild.googleapis.com",
    "servicemanagement":    "servicemanagement.googleapis.com",
    "monitoring":           "monitoring.googleapis.com",
    "cloudscheduler":       "cloudscheduler.googleapis.com",
    "datacatalog":          "datacatalog.googleapis.com",
    "aiplatform":           "aiplatform.googleapis.com",
}

# ---------------------------------------------------------------------------
# OCI service short → full CADF domain (lowercased)
# ---------------------------------------------------------------------------
OCI_SVC: Dict[str, str] = {
    "identity":              "com.oraclecloud.identitycontrolplane",
    "compute":               "com.oraclecloud.computeapi",
    "network":               "com.oraclecloud.virtualnetwork",
    "storage":               "com.oraclecloud.objectstorage",
    "database":              "com.oraclecloud.database",
    "keymanagement":         "com.oraclecloud.keymanagement",
    "vault":                 "com.oraclecloud.vaultmng",
    "functions":             "com.oraclecloud.functions",
    "containerengine":       "com.oraclecloud.containerengine",
    "loadbalancer":          "com.oraclecloud.loadbalancer",
    "apigateway":            "com.oraclecloud.apigateway",
    "streaming":             "com.oraclecloud.streaming",
    "events":                "com.oraclecloud.events",
    "ons":                   "com.oraclecloud.ons",
    "monitoring":            "com.oraclecloud.monitoring",
    "logging":               "com.oraclecloud.logging",
    "resourcemanager":       "com.oraclecloud.resourcemanager",
    "datacatalog":           "com.oraclecloud.datacatalog",
    "analytics":             "com.oraclecloud.analyticsservice",
    "integration":           "com.oraclecloud.integration",
    "email":                 "com.oraclecloud.emaildelivery",
    "waf":                   "com.oraclecloud.waf",
    "bastion":               "com.oraclecloud.bastion",
    "vulnerabilityscanning": "com.oraclecloud.vulnerabilityscanning",
    "devops":                "com.oraclecloud.devops",
    "servicemesh":           "com.oraclecloud.servicemesh",
    "redis":                 "com.oraclecloud.redis",
    "sch":                   "com.oraclecloud.serviceconnector",
    "blockstorage":          "com.oraclecloud.blockstorage",
    "filestorage":           "com.oraclecloud.filestorage",
    "dns":                   "com.oraclecloud.dns",
    "waas":                  "com.oraclecloud.waas",
}

# ===========================================================================
# AZURE RULES  (provider, resource_display, arm_operationName, action_display)
# ===========================================================================
AZURE_RULES: List[Tuple[str, str, str, str]] = [
    # Compute
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/write","Create/Update VM"),
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/delete","Delete VM"),
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/start/action","Start VM"),
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/deallocate/action","Deallocate VM"),
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/restart/action","Restart VM"),
    ("compute","Virtual Machines","Microsoft.Compute/virtualMachines/powerOff/action","Power Off VM"),
    ("compute","VM Extensions","Microsoft.Compute/virtualMachines/extensions/write","Install VM Extension"),
    ("compute","VM Extensions","Microsoft.Compute/virtualMachines/extensions/delete","Remove VM Extension"),
    ("compute","VM Scale Sets","Microsoft.Compute/virtualMachineScaleSets/write","Create/Update VMSS"),
    ("compute","VM Scale Sets","Microsoft.Compute/virtualMachineScaleSets/delete","Delete VMSS"),
    ("compute","Disks","Microsoft.Compute/disks/write","Create/Update Disk"),
    ("compute","Disks","Microsoft.Compute/disks/delete","Delete Disk"),
    ("compute","Snapshots","Microsoft.Compute/snapshots/write","Create/Update Snapshot"),
    ("compute","Snapshots","Microsoft.Compute/snapshots/delete","Delete Snapshot"),
    ("compute","Images","Microsoft.Compute/images/write","Create/Update Image"),
    ("compute","Images","Microsoft.Compute/images/delete","Delete Image"),
    ("compute","SSH Public Keys","Microsoft.Compute/sshPublicKeys/write","Create/Update SSH Key"),
    ("compute","SSH Public Keys","Microsoft.Compute/sshPublicKeys/delete","Delete SSH Key"),
    ("compute","Galleries","Microsoft.Compute/galleries/write","Create/Update Gallery"),
    ("compute","Galleries","Microsoft.Compute/galleries/delete","Delete Gallery"),
    # Network
    ("network","Virtual Networks","Microsoft.Network/virtualNetworks/write","Create/Update VNet"),
    ("network","Virtual Networks","Microsoft.Network/virtualNetworks/delete","Delete VNet"),
    ("network","Subnets","Microsoft.Network/virtualNetworks/subnets/write","Create/Update Subnet"),
    ("network","Subnets","Microsoft.Network/virtualNetworks/subnets/delete","Delete Subnet"),
    ("network","NSGs","Microsoft.Network/networkSecurityGroups/write","Create/Update NSG"),
    ("network","NSGs","Microsoft.Network/networkSecurityGroups/delete","Delete NSG"),
    ("network","NSG Rules","Microsoft.Network/networkSecurityGroups/securityRules/write","Create/Update NSG Rule"),
    ("network","NSG Rules","Microsoft.Network/networkSecurityGroups/securityRules/delete","Delete NSG Rule"),
    ("network","Public IP Addresses","Microsoft.Network/publicIPAddresses/write","Create/Update Public IP"),
    ("network","Public IP Addresses","Microsoft.Network/publicIPAddresses/delete","Delete Public IP"),
    ("network","Load Balancers","Microsoft.Network/loadBalancers/write","Create/Update Load Balancer"),
    ("network","Load Balancers","Microsoft.Network/loadBalancers/delete","Delete Load Balancer"),
    ("network","Application Gateways","Microsoft.Network/applicationGateways/write","Create/Update Application Gateway"),
    ("network","Application Gateways","Microsoft.Network/applicationGateways/delete","Delete Application Gateway"),
    ("network","Azure Firewalls","Microsoft.Network/azureFirewalls/write","Create/Update Azure Firewall"),
    ("network","Azure Firewalls","Microsoft.Network/azureFirewalls/delete","Delete Azure Firewall"),
    ("network","VPN Gateways","Microsoft.Network/virtualNetworkGateways/write","Create/Update VPN Gateway"),
    ("network","VPN Gateways","Microsoft.Network/virtualNetworkGateways/delete","Delete VPN Gateway"),
    ("network","Route Tables","Microsoft.Network/routeTables/write","Create/Update Route Table"),
    ("network","Route Tables","Microsoft.Network/routeTables/delete","Delete Route Table"),
    ("network","Private DNS Zones","Microsoft.Network/privateDnsZones/write","Create/Update Private DNS Zone"),
    ("network","Private DNS Zones","Microsoft.Network/privateDnsZones/delete","Delete Private DNS Zone"),
    ("network","Private Endpoints","Microsoft.Network/privateEndpoints/write","Create/Update Private Endpoint"),
    ("network","Private Endpoints","Microsoft.Network/privateEndpoints/delete","Delete Private Endpoint"),
    ("network","NAT Gateways","Microsoft.Network/natGateways/write","Create/Update NAT Gateway"),
    ("network","NAT Gateways","Microsoft.Network/natGateways/delete","Delete NAT Gateway"),
    ("network","Network Interfaces","Microsoft.Network/networkInterfaces/write","Create/Update Network Interface"),
    ("network","Network Interfaces","Microsoft.Network/networkInterfaces/delete","Delete Network Interface"),
    ("network","Bastion Hosts","Microsoft.Network/bastionHosts/write","Create/Update Bastion Host"),
    ("network","Bastion Hosts","Microsoft.Network/bastionHosts/delete","Delete Bastion Host"),
    ("network","Express Route Circuits","Microsoft.Network/expressRouteCircuits/write","Create/Update ExpressRoute Circuit"),
    ("network","Express Route Circuits","Microsoft.Network/expressRouteCircuits/delete","Delete ExpressRoute Circuit"),
    ("network","Network Watchers","Microsoft.Network/networkWatchers/write","Create/Update Network Watcher"),
    ("network","Network Watchers","Microsoft.Network/networkWatchers/delete","Delete Network Watcher"),
    # Storage
    ("storage","Storage Accounts","Microsoft.Storage/storageAccounts/write","Create/Update Storage Account"),
    ("storage","Storage Accounts","Microsoft.Storage/storageAccounts/delete","Delete Storage Account"),
    ("storage","Blob Containers","Microsoft.Storage/storageAccounts/blobServices/containers/write","Create/Update Blob Container"),
    ("storage","Blob Containers","Microsoft.Storage/storageAccounts/blobServices/containers/delete","Delete Blob Container"),
    ("storage","File Shares","Microsoft.Storage/storageAccounts/fileServices/shares/write","Create/Update File Share"),
    ("storage","File Shares","Microsoft.Storage/storageAccounts/fileServices/shares/delete","Delete File Share"),
    ("storage","Queue Services","Microsoft.Storage/storageAccounts/queueServices/queues/write","Create/Update Storage Queue"),
    ("storage","Queue Services","Microsoft.Storage/storageAccounts/queueServices/queues/delete","Delete Storage Queue"),
    # Key Vault
    ("keyvault","Key Vaults","Microsoft.KeyVault/vaults/write","Create/Update Key Vault"),
    ("keyvault","Key Vaults","Microsoft.KeyVault/vaults/delete","Delete Key Vault"),
    ("keyvault","Keys","Microsoft.KeyVault/vaults/keys/write","Create/Update Key"),
    ("keyvault","Keys","Microsoft.KeyVault/vaults/keys/delete","Delete Key"),
    ("keyvault","Secrets","Microsoft.KeyVault/vaults/secrets/write","Create/Update Secret"),
    ("keyvault","Secrets","Microsoft.KeyVault/vaults/secrets/delete","Delete Secret"),
    ("keyvault","Certificates","Microsoft.KeyVault/vaults/certificates/write","Create/Update Certificate"),
    ("keyvault","Certificates","Microsoft.KeyVault/vaults/certificates/delete","Delete Certificate"),
    ("keyvault","Access Policies","Microsoft.KeyVault/vaults/accessPolicies/write","Update Key Vault Access Policy"),
    # Authorization / IAM
    ("authorization","Role Assignments","Microsoft.Authorization/roleAssignments/write","Create Role Assignment"),
    ("authorization","Role Assignments","Microsoft.Authorization/roleAssignments/delete","Delete Role Assignment"),
    ("authorization","Role Definitions","Microsoft.Authorization/roleDefinitions/write","Create/Update Role Definition"),
    ("authorization","Role Definitions","Microsoft.Authorization/roleDefinitions/delete","Delete Role Definition"),
    ("authorization","Policy Assignments","Microsoft.Authorization/policyAssignments/write","Create/Update Policy Assignment"),
    ("authorization","Policy Assignments","Microsoft.Authorization/policyAssignments/delete","Delete Policy Assignment"),
    ("authorization","Policy Definitions","Microsoft.Authorization/policyDefinitions/write","Create/Update Policy Definition"),
    ("authorization","Policy Definitions","Microsoft.Authorization/policyDefinitions/delete","Delete Policy Definition"),
    ("authorization","Locks","Microsoft.Authorization/locks/write","Create/Update Management Lock"),
    ("authorization","Locks","Microsoft.Authorization/locks/delete","Delete Management Lock"),
    # Container Service / AKS
    ("containerservice","AKS Clusters","Microsoft.ContainerService/managedClusters/write","Create/Update AKS Cluster"),
    ("containerservice","AKS Clusters","Microsoft.ContainerService/managedClusters/delete","Delete AKS Cluster"),
    ("containerservice","Node Pools","Microsoft.ContainerService/managedClusters/agentPools/write","Create/Update AKS Node Pool"),
    ("containerservice","Node Pools","Microsoft.ContainerService/managedClusters/agentPools/delete","Delete AKS Node Pool"),
    # SQL
    ("sql","SQL Servers","Microsoft.Sql/servers/write","Create/Update SQL Server"),
    ("sql","SQL Servers","Microsoft.Sql/servers/delete","Delete SQL Server"),
    ("sql","SQL Databases","Microsoft.Sql/servers/databases/write","Create/Update SQL Database"),
    ("sql","SQL Databases","Microsoft.Sql/servers/databases/delete","Delete SQL Database"),
    ("sql","SQL Firewall Rules","Microsoft.Sql/servers/firewallRules/write","Create/Update SQL Firewall Rule"),
    ("sql","SQL Firewall Rules","Microsoft.Sql/servers/firewallRules/delete","Delete SQL Firewall Rule"),
    ("sql","SQL Managed Instances","Microsoft.Sql/managedInstances/write","Create/Update SQL Managed Instance"),
    ("sql","SQL Managed Instances","Microsoft.Sql/managedInstances/delete","Delete SQL Managed Instance"),
    ("sql","SQL Server Admins","Microsoft.Sql/servers/administrators/write","Set SQL Server AD Administrator"),
    ("sql","SQL Auditing","Microsoft.Sql/servers/auditingSettings/write","Update SQL Server Audit Settings"),
    # Web
    ("web","App Service Plans","Microsoft.Web/serverfarms/write","Create/Update App Service Plan"),
    ("web","App Service Plans","Microsoft.Web/serverfarms/delete","Delete App Service Plan"),
    ("web","Web Apps","Microsoft.Web/sites/write","Create/Update Web App"),
    ("web","Web Apps","Microsoft.Web/sites/delete","Delete Web App"),
    ("web","App Service Auth","Microsoft.Web/sites/config/write","Update Web App Config"),
    # PostgreSQL
    ("dbforpostgresql","PostgreSQL Servers","Microsoft.DBforPostgreSQL/servers/write","Create/Update PostgreSQL Server"),
    ("dbforpostgresql","PostgreSQL Servers","Microsoft.DBforPostgreSQL/servers/delete","Delete PostgreSQL Server"),
    ("dbforpostgresql","PostgreSQL Flexible Servers","Microsoft.DBforPostgreSQL/flexibleServers/write","Create/Update PostgreSQL Flexible Server"),
    ("dbforpostgresql","PostgreSQL Flexible Servers","Microsoft.DBforPostgreSQL/flexibleServers/delete","Delete PostgreSQL Flexible Server"),
    # MySQL
    ("dbformysql","MySQL Servers","Microsoft.DBforMySQL/servers/write","Create/Update MySQL Server"),
    ("dbformysql","MySQL Servers","Microsoft.DBforMySQL/servers/delete","Delete MySQL Server"),
    ("dbformysql","MySQL Flexible Servers","Microsoft.DBforMySQL/flexibleServers/write","Create/Update MySQL Flexible Server"),
    ("dbformysql","MySQL Flexible Servers","Microsoft.DBforMySQL/flexibleServers/delete","Delete MySQL Flexible Server"),
    # Cache / Redis
    ("cache","Redis Caches","Microsoft.Cache/redis/write","Create/Update Redis Cache"),
    ("cache","Redis Caches","Microsoft.Cache/redis/delete","Delete Redis Cache"),
    # Cosmos DB
    ("documentdb","Cosmos DB Accounts","Microsoft.DocumentDB/databaseAccounts/write","Create/Update Cosmos DB Account"),
    ("documentdb","Cosmos DB Accounts","Microsoft.DocumentDB/databaseAccounts/delete","Delete Cosmos DB Account"),
    ("documentdb","Cosmos DB SQL Databases","Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write","Create/Update Cosmos DB SQL Database"),
    ("documentdb","Cosmos DB SQL Databases","Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete","Delete Cosmos DB SQL Database"),
    # Service Bus
    ("servicebus","Service Bus Namespaces","Microsoft.ServiceBus/namespaces/write","Create/Update Service Bus Namespace"),
    ("servicebus","Service Bus Namespaces","Microsoft.ServiceBus/namespaces/delete","Delete Service Bus Namespace"),
    ("servicebus","Service Bus Topics","Microsoft.ServiceBus/namespaces/topics/write","Create/Update Service Bus Topic"),
    ("servicebus","Service Bus Topics","Microsoft.ServiceBus/namespaces/topics/delete","Delete Service Bus Topic"),
    # Event Hub
    ("eventhub","Event Hub Namespaces","Microsoft.EventHub/namespaces/write","Create/Update Event Hub Namespace"),
    ("eventhub","Event Hub Namespaces","Microsoft.EventHub/namespaces/delete","Delete Event Hub Namespace"),
    ("eventhub","Event Hubs","Microsoft.EventHub/namespaces/eventhubs/write","Create/Update Event Hub"),
    ("eventhub","Event Hubs","Microsoft.EventHub/namespaces/eventhubs/delete","Delete Event Hub"),
    # Monitor / Insights
    ("insights","Diagnostic Settings","Microsoft.Insights/diagnosticSettings/write","Create/Update Diagnostic Settings"),
    ("insights","Diagnostic Settings","Microsoft.Insights/diagnosticSettings/delete","Delete Diagnostic Settings"),
    ("insights","Alert Rules","Microsoft.Insights/scheduledqueryrules/write","Create/Update Alert Rule"),
    ("insights","Alert Rules","Microsoft.Insights/scheduledqueryrules/delete","Delete Alert Rule"),
    ("insights","Activity Log Alerts","Microsoft.Insights/activityLogAlerts/write","Create/Update Activity Log Alert"),
    ("insights","Activity Log Alerts","Microsoft.Insights/activityLogAlerts/delete","Delete Activity Log Alert"),
    ("insights","Action Groups","Microsoft.Insights/actionGroups/write","Create/Update Action Group"),
    ("insights","Action Groups","Microsoft.Insights/actionGroups/delete","Delete Action Group"),
    # Logic Apps
    ("logic","Logic Apps","Microsoft.Logic/workflows/write","Create/Update Logic App"),
    ("logic","Logic Apps","Microsoft.Logic/workflows/delete","Delete Logic App"),
    # API Management
    ("apimanagement","API Management","Microsoft.ApiManagement/service/write","Create/Update API Management"),
    ("apimanagement","API Management","Microsoft.ApiManagement/service/delete","Delete API Management"),
    # Container Registry
    ("containerregistry","Container Registries","Microsoft.ContainerRegistry/registries/write","Create/Update Container Registry"),
    ("containerregistry","Container Registries","Microsoft.ContainerRegistry/registries/delete","Delete Container Registry"),
    # Managed Identity
    ("managedidentity","User Assigned Identities","Microsoft.ManagedIdentity/userAssignedIdentities/write","Create/Update Managed Identity"),
    ("managedidentity","User Assigned Identities","Microsoft.ManagedIdentity/userAssignedIdentities/delete","Delete Managed Identity"),
    # Recovery Services
    ("recoveryservices","Recovery Vaults","Microsoft.RecoveryServices/vaults/write","Create/Update Recovery Services Vault"),
    ("recoveryservices","Recovery Vaults","Microsoft.RecoveryServices/vaults/delete","Delete Recovery Services Vault"),
    # IoT Hub
    ("devices","IoT Hubs","Microsoft.Devices/IotHubs/write","Create/Update IoT Hub"),
    ("devices","IoT Hubs","Microsoft.Devices/IotHubs/delete","Delete IoT Hub"),
    # Event Grid
    ("eventgrid","Event Grid Topics","Microsoft.EventGrid/topics/write","Create/Update Event Grid Topic"),
    ("eventgrid","Event Grid Topics","Microsoft.EventGrid/topics/delete","Delete Event Grid Topic"),
    ("eventgrid","Event Grid Subscriptions","Microsoft.EventGrid/eventSubscriptions/write","Create/Update Event Subscription"),
    ("eventgrid","Event Grid Subscriptions","Microsoft.EventGrid/eventSubscriptions/delete","Delete Event Subscription"),
    # Security Center
    ("security","Defender Pricing","Microsoft.Security/pricings/write","Update Defender Pricing"),
    ("security","Security Contacts","Microsoft.Security/securityContacts/write","Create/Update Security Contact"),
    ("security","Security Contacts","Microsoft.Security/securityContacts/delete","Delete Security Contact"),
    # Sentinel
    ("securityinsights","Sentinel Alert Rules","Microsoft.SecurityInsights/alertRules/write","Create/Update Sentinel Alert Rule"),
    ("securityinsights","Sentinel Alert Rules","Microsoft.SecurityInsights/alertRules/delete","Delete Sentinel Alert Rule"),
    # Resource Groups
    ("resources","Resource Groups","Microsoft.Resources/resourceGroups/write","Create/Update Resource Group"),
    ("resources","Resource Groups","Microsoft.Resources/resourceGroups/delete","Delete Resource Group"),
    ("resources","Deployments","Microsoft.Resources/deployments/write","Create/Update Resource Deployment"),
    # Data Factory
    ("datafactory","Data Factories","Microsoft.DataFactory/factories/write","Create/Update Data Factory"),
    ("datafactory","Data Factories","Microsoft.DataFactory/factories/delete","Delete Data Factory"),
    # Synapse
    ("synapse","Synapse Workspaces","Microsoft.Synapse/workspaces/write","Create/Update Synapse Workspace"),
    ("synapse","Synapse Workspaces","Microsoft.Synapse/workspaces/delete","Delete Synapse Workspace"),
    # Databricks
    ("databricks","Databricks Workspaces","Microsoft.Databricks/workspaces/write","Create/Update Databricks Workspace"),
    ("databricks","Databricks Workspaces","Microsoft.Databricks/workspaces/delete","Delete Databricks Workspace"),
    # Log Analytics
    ("operationalinsights","Log Analytics Workspaces","Microsoft.OperationalInsights/workspaces/write","Create/Update Log Analytics Workspace"),
    ("operationalinsights","Log Analytics Workspaces","Microsoft.OperationalInsights/workspaces/delete","Delete Log Analytics Workspace"),
    # Cognitive Services
    ("cognitiveservices","Cognitive Services","Microsoft.CognitiveServices/accounts/write","Create/Update Cognitive Service"),
    ("cognitiveservices","Cognitive Services","Microsoft.CognitiveServices/accounts/delete","Delete Cognitive Service"),
    # Machine Learning
    ("machinelearningservices","ML Workspaces","Microsoft.MachineLearningServices/workspaces/write","Create/Update ML Workspace"),
    ("machinelearningservices","ML Workspaces","Microsoft.MachineLearningServices/workspaces/delete","Delete ML Workspace"),
    # Graph RBAC
    ("graphrbac","Service Principals","Microsoft.GraphRbac/servicePrincipals/write","Create/Update Service Principal"),
    ("graphrbac","Service Principals","Microsoft.GraphRbac/servicePrincipals/delete","Delete Service Principal"),
    ("graphrbac","Applications","Microsoft.GraphRbac/applications/write","Create/Update Application Registration"),
    ("graphrbac","Applications","Microsoft.GraphRbac/applications/delete","Delete Application Registration"),
    # CDN
    ("cdn","CDN Profiles","Microsoft.Cdn/profiles/write","Create/Update CDN Profile"),
    ("cdn","CDN Profiles","Microsoft.Cdn/profiles/delete","Delete CDN Profile"),
    # Search
    ("search","Search Services","Microsoft.Search/searchServices/write","Create/Update Search Service"),
    ("search","Search Services","Microsoft.Search/searchServices/delete","Delete Search Service"),
]


# ===========================================================================
# GCP RULES  (service_short, method_contains, op_display, resource_display)
# ===========================================================================
GCP_RULES: List[Tuple[str, str, str, str]] = [
    # Compute Engine
    ("compute","compute.instances.insert","Insert Instance","Compute Instances"),
    ("compute","compute.instances.delete","Delete Instance","Compute Instances"),
    ("compute","compute.instances.start","Start Instance","Compute Instances"),
    ("compute","compute.instances.stop","Stop Instance","Compute Instances"),
    ("compute","compute.instances.setMetadata","Set Instance Metadata","Compute Instances"),
    ("compute","compute.instances.setServiceAccount","Set Service Account","Compute Instances"),
    ("compute","compute.instances.setIamPolicy","Set Instance IAM Policy","Compute Instances"),
    ("compute","compute.firewalls.insert","Create Firewall Rule","VPC Firewall Rules"),
    ("compute","compute.firewalls.delete","Delete Firewall Rule","VPC Firewall Rules"),
    ("compute","compute.firewalls.patch","Update Firewall Rule","VPC Firewall Rules"),
    ("compute","compute.networks.insert","Create VPC Network","VPC Networks"),
    ("compute","compute.networks.delete","Delete VPC Network","VPC Networks"),
    ("compute","compute.networks.addPeering","Add VPC Peering","VPC Networks"),
    ("compute","compute.networks.removePeering","Remove VPC Peering","VPC Networks"),
    ("compute","compute.subnetworks.insert","Create Subnet","VPC Subnetworks"),
    ("compute","compute.subnetworks.delete","Delete Subnet","VPC Subnetworks"),
    ("compute","compute.routers.insert","Create Cloud Router","Cloud Routers"),
    ("compute","compute.routers.delete","Delete Cloud Router","Cloud Routers"),
    ("compute","compute.disks.insert","Create Persistent Disk","Persistent Disks"),
    ("compute","compute.disks.delete","Delete Persistent Disk","Persistent Disks"),
    ("compute","compute.snapshots.insert","Create Disk Snapshot","Disk Snapshots"),
    ("compute","compute.snapshots.delete","Delete Disk Snapshot","Disk Snapshots"),
    ("compute","compute.snapshots.setIamPolicy","Set Snapshot IAM Policy","Disk Snapshots"),
    ("compute","compute.instanceGroups.insert","Create Instance Group","Instance Groups"),
    ("compute","compute.instanceGroups.delete","Delete Instance Group","Instance Groups"),
    ("compute","compute.instanceTemplates.insert","Create Instance Template","Instance Templates"),
    ("compute","compute.instanceTemplates.delete","Delete Instance Template","Instance Templates"),
    ("compute","compute.addresses.insert","Create IP Address","Compute IP Addresses"),
    ("compute","compute.addresses.delete","Delete IP Address","Compute IP Addresses"),
    ("compute","compute.vpnGateways.insert","Create VPN Gateway","VPN Gateways"),
    ("compute","compute.vpnGateways.delete","Delete VPN Gateway","VPN Gateways"),
    ("compute","compute.vpnTunnels.insert","Create VPN Tunnel","VPN Tunnels"),
    ("compute","compute.vpnTunnels.delete","Delete VPN Tunnel","VPN Tunnels"),
    ("compute","compute.routes.insert","Create Route","Routes"),
    ("compute","compute.routes.delete","Delete Route","Routes"),
    ("compute","compute.images.insert","Create Custom Image","Compute Images"),
    ("compute","compute.images.delete","Delete Custom Image","Compute Images"),
    ("compute","compute.images.setIamPolicy","Set Image IAM Policy","Compute Images"),
    ("compute","compute.securityPolicies.insert","Create Security Policy","Cloud Armor Policies"),
    ("compute","compute.securityPolicies.delete","Delete Security Policy","Cloud Armor Policies"),
    ("compute","compute.securityPolicies.patch","Update Security Policy","Cloud Armor Policies"),
    # IAM
    ("iam","IAMPolicy.SetIamPolicy","Set IAM Policy","IAM Policies"),
    ("iam","google.iam.admin.v1.CreateServiceAccount","Create Service Account","Service Accounts"),
    ("iam","google.iam.admin.v1.DeleteServiceAccount","Delete Service Account","Service Accounts"),
    ("iam","google.iam.admin.v1.CreateServiceAccountKey","Create Service Account Key","Service Account Keys"),
    ("iam","google.iam.admin.v1.DeleteServiceAccountKey","Delete Service Account Key","Service Account Keys"),
    ("iam","google.iam.admin.v1.EnableServiceAccount","Enable Service Account","Service Accounts"),
    ("iam","google.iam.admin.v1.DisableServiceAccount","Disable Service Account","Service Accounts"),
    ("iam","google.iam.admin.v1.CreateRole","Create Custom IAM Role","IAM Roles"),
    ("iam","google.iam.admin.v1.DeleteRole","Delete IAM Role","IAM Roles"),
    ("iam","google.iam.admin.v1.UpdateRole","Update IAM Role","IAM Roles"),
    ("iam","google.iam.admin.v1.PatchServiceAccount","Update Service Account","Service Accounts"),
    # Cloud Storage
    ("storage","storage.buckets.create","Create Storage Bucket","Cloud Storage Buckets"),
    ("storage","storage.buckets.delete","Delete Storage Bucket","Cloud Storage Buckets"),
    ("storage","storage.buckets.update","Update Storage Bucket","Cloud Storage Buckets"),
    ("storage","storage.setIamPermissions","Set Storage IAM Permissions","Cloud Storage Buckets"),
    ("storage","storage.objects.delete","Delete Storage Object","Cloud Storage Objects"),
    # GKE
    ("container","ClusterManager.CreateCluster","Create GKE Cluster","GKE Clusters"),
    ("container","ClusterManager.DeleteCluster","Delete GKE Cluster","GKE Clusters"),
    ("container","ClusterManager.UpdateCluster","Update GKE Cluster","GKE Clusters"),
    ("container","ClusterManager.CreateNodePool","Create Node Pool","GKE Node Pools"),
    ("container","ClusterManager.DeleteNodePool","Delete Node Pool","GKE Node Pools"),
    ("container","ClusterManager.UpdateNodePool","Update Node Pool","GKE Node Pools"),
    ("container","ClusterManager.SetMasterAuth","Set GKE Master Auth","GKE Clusters"),
    ("container","ClusterManager.SetNetworkPolicy","Set GKE Network Policy","GKE Clusters"),
    # Cloud SQL
    ("sqladmin","cloudsql.instances.create","Create Cloud SQL Instance","Cloud SQL Instances"),
    ("sqladmin","cloudsql.instances.delete","Delete Cloud SQL Instance","Cloud SQL Instances"),
    ("sqladmin","cloudsql.instances.update","Update Cloud SQL Instance","Cloud SQL Instances"),
    ("sqladmin","cloudsql.users.create","Create Cloud SQL User","Cloud SQL Users"),
    ("sqladmin","cloudsql.users.delete","Delete Cloud SQL User","Cloud SQL Users"),
    ("sqladmin","cloudsql.sslCerts.create","Create Cloud SQL SSL Cert","Cloud SQL SSL Certs"),
    ("sqladmin","cloudsql.sslCerts.delete","Delete Cloud SQL SSL Cert","Cloud SQL SSL Certs"),
    # Cloud KMS
    ("cloudkms","KeyManagementService.CreateKeyRing","Create KMS Key Ring","KMS Key Rings"),
    ("cloudkms","KeyManagementService.CreateCryptoKey","Create KMS Crypto Key","KMS Crypto Keys"),
    ("cloudkms","KeyManagementService.UpdateCryptoKey","Update KMS Crypto Key","KMS Crypto Keys"),
    ("cloudkms","KeyManagementService.DestroyCryptoKeyVersion","Destroy KMS Key Version","KMS Key Versions"),
    ("cloudkms","KeyManagementService.SetIamPolicy","Set KMS IAM Policy","KMS Key Rings"),
    # Pub/Sub
    ("pubsub","Publisher.CreateTopic","Create Pub/Sub Topic","Pub/Sub Topics"),
    ("pubsub","Publisher.DeleteTopic","Delete Pub/Sub Topic","Pub/Sub Topics"),
    ("pubsub","Subscriber.CreateSubscription","Create Pub/Sub Subscription","Pub/Sub Subscriptions"),
    ("pubsub","Subscriber.DeleteSubscription","Delete Pub/Sub Subscription","Pub/Sub Subscriptions"),
    # Cloud Functions
    ("cloudfunctions","CloudFunctionsService.CreateFunction","Create Cloud Function","Cloud Functions"),
    ("cloudfunctions","CloudFunctionsService.DeleteFunction","Delete Cloud Function","Cloud Functions"),
    ("cloudfunctions","CloudFunctionsService.UpdateFunction","Update Cloud Function","Cloud Functions"),
    ("cloudfunctions","CloudFunctionsService.SetIamPolicy","Set Cloud Function IAM Policy","Cloud Functions"),
    # Cloud Run
    ("run","Services.CreateService","Create Cloud Run Service","Cloud Run Services"),
    ("run","Services.DeleteService","Delete Cloud Run Service","Cloud Run Services"),
    ("run","Services.UpdateService","Update Cloud Run Service","Cloud Run Services"),
    ("run","Services.SetIamPolicy","Set Cloud Run IAM Policy","Cloud Run Services"),
    # BigQuery
    ("bigquery","TableService.InsertTable","Create BigQuery Table","BigQuery Tables"),
    ("bigquery","TableService.DeleteTable","Delete BigQuery Table","BigQuery Tables"),
    ("bigquery","DatasetService.InsertDataset","Create BigQuery Dataset","BigQuery Datasets"),
    ("bigquery","DatasetService.DeleteDataset","Delete BigQuery Dataset","BigQuery Datasets"),
    ("bigquery","DatasetService.UpdateDataset","Update BigQuery Dataset","BigQuery Datasets"),
    # Spanner
    ("spanner","InstanceAdmin.CreateInstance","Create Spanner Instance","Spanner Instances"),
    ("spanner","InstanceAdmin.DeleteInstance","Delete Spanner Instance","Spanner Instances"),
    ("spanner","DatabaseAdmin.CreateDatabase","Create Spanner Database","Spanner Databases"),
    ("spanner","DatabaseAdmin.DropDatabase","Drop Spanner Database","Spanner Databases"),
    ("spanner","DatabaseAdmin.SetIamPolicy","Set Spanner IAM Policy","Spanner Databases"),
    # Cloud Logging
    ("logging","LoggingServiceV2.DeleteLog","Delete Log","Cloud Logging"),
    ("logging","ConfigServiceV2.CreateSink","Create Log Sink","Cloud Logging Sinks"),
    ("logging","ConfigServiceV2.DeleteSink","Delete Log Sink","Cloud Logging Sinks"),
    ("logging","ConfigServiceV2.UpdateSink","Update Log Sink","Cloud Logging Sinks"),
    # Cloud DNS
    ("dns","dns.managedZones.create","Create DNS Zone","Cloud DNS Zones"),
    ("dns","dns.managedZones.delete","Delete DNS Zone","Cloud DNS Zones"),
    ("dns","dns.changes.create","Create DNS Change","Cloud DNS Records"),
    # Secret Manager
    ("secretmanager","SecretManagerService.CreateSecret","Create Secret","Secret Manager Secrets"),
    ("secretmanager","SecretManagerService.DeleteSecret","Delete Secret","Secret Manager Secrets"),
    ("secretmanager","SecretManagerService.AddSecretVersion","Add Secret Version","Secret Manager Versions"),
    ("secretmanager","SecretManagerService.DestroySecretVersion","Destroy Secret Version","Secret Manager Versions"),
    ("secretmanager","SecretManagerService.SetIamPolicy","Set Secret IAM Policy","Secret Manager Secrets"),
    # Artifact Registry
    ("artifactregistry","ArtifactRegistry.CreateRepository","Create Artifact Repository","Artifact Registry"),
    ("artifactregistry","ArtifactRegistry.DeleteRepository","Delete Artifact Repository","Artifact Registry"),
    ("artifactregistry","ArtifactRegistry.SetIamPolicy","Set Artifact Registry IAM","Artifact Registry"),
    # Cloud Build
    ("cloudbuild","CloudBuild.CreateBuildTrigger","Create Build Trigger","Cloud Build"),
    ("cloudbuild","CloudBuild.DeleteBuildTrigger","Delete Build Trigger","Cloud Build"),
    ("cloudbuild","CloudBuild.UpdateBuildTrigger","Update Build Trigger","Cloud Build"),
    # Monitoring
    ("monitoring","AlertPolicyService.CreateAlertPolicy","Create Alert Policy","Cloud Monitoring"),
    ("monitoring","AlertPolicyService.DeleteAlertPolicy","Delete Alert Policy","Cloud Monitoring"),
    # Cloud Scheduler
    ("cloudscheduler","CloudScheduler.CreateJob","Create Scheduler Job","Cloud Scheduler"),
    ("cloudscheduler","CloudScheduler.DeleteJob","Delete Scheduler Job","Cloud Scheduler"),
    ("cloudscheduler","CloudScheduler.UpdateJob","Update Scheduler Job","Cloud Scheduler"),
    # Vertex AI
    ("aiplatform","EndpointService.CreateEndpoint","Create AI Platform Endpoint","Vertex AI"),
    ("aiplatform","EndpointService.DeleteEndpoint","Delete AI Platform Endpoint","Vertex AI"),
    ("aiplatform","ModelService.DeleteModel","Delete AI Platform Model","Vertex AI"),
]


# ===========================================================================
# OCI RULES  (service_short, operation_pascal, resource_display)
# ===========================================================================
OCI_RULES: List[Tuple[str, str, str]] = [
    # Identity
    ("identity","CreateUser","IAM Users"),
    ("identity","DeleteUser","IAM Users"),
    ("identity","UpdateUser","IAM Users"),
    ("identity","CreateGroup","IAM Groups"),
    ("identity","DeleteGroup","IAM Groups"),
    ("identity","AddUserToGroup","IAM Group Memberships"),
    ("identity","RemoveUserFromGroup","IAM Group Memberships"),
    ("identity","CreatePolicy","IAM Policies"),
    ("identity","DeletePolicy","IAM Policies"),
    ("identity","UpdatePolicy","IAM Policies"),
    ("identity","CreateDynamicGroup","Dynamic Groups"),
    ("identity","DeleteDynamicGroup","Dynamic Groups"),
    ("identity","CreateCompartment","Compartments"),
    ("identity","DeleteCompartment","Compartments"),
    ("identity","MoveCompartment","Compartments"),
    ("identity","CreateAuthToken","Auth Tokens"),
    ("identity","DeleteAuthToken","Auth Tokens"),
    ("identity","CreateCustomerSecretKey","Customer Secret Keys"),
    ("identity","DeleteCustomerSecretKey","Customer Secret Keys"),
    ("identity","CreateSmtpCredential","SMTP Credentials"),
    ("identity","DeleteSmtpCredential","SMTP Credentials"),
    ("identity","CreateOrResetUIPassword","User Passwords"),
    ("identity","UploadApiKey","API Keys"),
    ("identity","DeleteApiKey","API Keys"),
    # Compute
    ("compute","LaunchInstance","Compute Instances"),
    ("compute","TerminateInstance","Compute Instances"),
    ("compute","UpdateInstance","Compute Instances"),
    ("compute","InstanceAction","Compute Instances"),
    ("compute","CreateImage","Custom Images"),
    ("compute","DeleteImage","Custom Images"),
    ("compute","CreateVnicAttachment","VNIC Attachments"),
    ("compute","DetachVnic","VNIC Attachments"),
    ("compute","AttachVolume","Volume Attachments"),
    ("compute","DetachVolume","Volume Attachments"),
    ("compute","CreateDedicatedVmHost","Dedicated VM Hosts"),
    ("compute","DeleteDedicatedVmHost","Dedicated VM Hosts"),
    # Network
    ("network","CreateVcn","Virtual Cloud Networks"),
    ("network","DeleteVcn","Virtual Cloud Networks"),
    ("network","UpdateVcn","Virtual Cloud Networks"),
    ("network","CreateSubnet","Subnets"),
    ("network","DeleteSubnet","Subnets"),
    ("network","UpdateSubnet","Subnets"),
    ("network","CreateSecurityList","Security Lists"),
    ("network","DeleteSecurityList","Security Lists"),
    ("network","UpdateSecurityList","Security Lists"),
    ("network","CreateNetworkSecurityGroup","Network Security Groups"),
    ("network","DeleteNetworkSecurityGroup","Network Security Groups"),
    ("network","UpdateNetworkSecurityGroupSecurityRules","NSG Security Rules"),
    ("network","CreateInternetGateway","Internet Gateways"),
    ("network","DeleteInternetGateway","Internet Gateways"),
    ("network","CreateNatGateway","NAT Gateways"),
    ("network","DeleteNatGateway","NAT Gateways"),
    ("network","CreateRouteTable","Route Tables"),
    ("network","DeleteRouteTable","Route Tables"),
    ("network","UpdateRouteTable","Route Tables"),
    ("network","CreateDhcpOptions","DHCP Options"),
    ("network","DeleteDhcpOptions","DHCP Options"),
    ("network","CreateLocalPeeringGateway","Local Peering Gateways"),
    ("network","DeleteLocalPeeringGateway","Local Peering Gateways"),
    ("network","CreateIPSecConnection","IPSec Connections"),
    ("network","DeleteIPSecConnection","IPSec Connections"),
    # Storage
    ("storage","CreateBucket","Object Storage Buckets"),
    ("storage","DeleteBucket","Object Storage Buckets"),
    ("storage","UpdateBucket","Object Storage Buckets"),
    ("storage","CreatePreauthenticatedRequest","Pre-Auth Requests"),
    ("storage","DeletePreauthenticatedRequest","Pre-Auth Requests"),
    ("storage","DeleteObject","Objects"),
    # Block Storage
    ("blockstorage","CreateVolume","Block Volumes"),
    ("blockstorage","DeleteVolume","Block Volumes"),
    ("blockstorage","UpdateVolume","Block Volumes"),
    ("blockstorage","CreateVolumeBackup","Volume Backups"),
    ("blockstorage","DeleteVolumeBackup","Volume Backups"),
    ("blockstorage","CreateBootVolume","Boot Volumes"),
    ("blockstorage","DeleteBootVolume","Boot Volumes"),
    # Database
    ("database","CreateDbSystem","DB Systems"),
    ("database","DeleteDbSystem","DB Systems"),
    ("database","UpdateDbSystem","DB Systems"),
    ("database","CreateAutonomousDatabase","Autonomous Databases"),
    ("database","DeleteAutonomousDatabase","Autonomous Databases"),
    ("database","UpdateAutonomousDatabase","Autonomous Databases"),
    ("database","CreateDbHome","DB Homes"),
    ("database","DeleteDbHome","DB Homes"),
    ("database","CreateBackup","DB Backups"),
    ("database","DeleteBackup","DB Backups"),
    # Key Management
    ("keymanagement","CreateKey","KMS Keys"),
    ("keymanagement","DeleteKey","KMS Keys"),
    ("keymanagement","EnableKey","KMS Keys"),
    ("keymanagement","DisableKey","KMS Keys"),
    ("keymanagement","CreateKeyVersion","KMS Key Versions"),
    ("keymanagement","DeleteKeyVersion","KMS Key Versions"),
    ("keymanagement","ScheduleKeyDeletion","KMS Keys"),
    # Vault (Secrets)
    ("vault","CreateSecret","Secrets"),
    ("vault","DeleteSecret","Secrets"),
    ("vault","UpdateSecret","Secrets"),
    ("vault","CreateSecretVersion","Secret Versions"),
    ("vault","ScheduleSecretVersionDeletion","Secret Versions"),
    # Functions
    ("functions","CreateApplication","Function Applications"),
    ("functions","DeleteApplication","Function Applications"),
    ("functions","UpdateApplication","Function Applications"),
    ("functions","CreateFunction","Functions"),
    ("functions","DeleteFunction","Functions"),
    ("functions","UpdateFunction","Functions"),
    # Container Engine (OKE)
    ("containerengine","CreateCluster","OKE Clusters"),
    ("containerengine","DeleteCluster","OKE Clusters"),
    ("containerengine","UpdateCluster","OKE Clusters"),
    ("containerengine","CreateNodePool","OKE Node Pools"),
    ("containerengine","DeleteNodePool","OKE Node Pools"),
    ("containerengine","UpdateNodePool","OKE Node Pools"),
    # Load Balancer
    ("loadbalancer","CreateLoadBalancer","Load Balancers"),
    ("loadbalancer","DeleteLoadBalancer","Load Balancers"),
    ("loadbalancer","UpdateLoadBalancer","Load Balancers"),
    ("loadbalancer","CreateBackendSet","Backend Sets"),
    ("loadbalancer","DeleteBackendSet","Backend Sets"),
    ("loadbalancer","CreateListener","Load Balancer Listeners"),
    ("loadbalancer","DeleteListener","Load Balancer Listeners"),
    # API Gateway
    ("apigateway","CreateGateway","API Gateways"),
    ("apigateway","DeleteGateway","API Gateways"),
    ("apigateway","UpdateGateway","API Gateways"),
    ("apigateway","CreateApi","APIs"),
    ("apigateway","DeleteApi","APIs"),
    ("apigateway","CreateDeployment","API Deployments"),
    ("apigateway","DeleteDeployment","API Deployments"),
    # Streaming
    ("streaming","CreateStream","Streams"),
    ("streaming","DeleteStream","Streams"),
    ("streaming","CreateStreamPool","Stream Pools"),
    ("streaming","DeleteStreamPool","Stream Pools"),
    # Events / Notifications
    ("events","CreateRule","Event Rules"),
    ("events","DeleteRule","Event Rules"),
    ("events","UpdateRule","Event Rules"),
    ("ons","CreateTopic","Notification Topics"),
    ("ons","DeleteTopic","Notification Topics"),
    ("ons","CreateSubscription","Notification Subscriptions"),
    ("ons","DeleteSubscription","Notification Subscriptions"),
    # Monitoring
    ("monitoring","CreateAlarm","Monitoring Alarms"),
    ("monitoring","DeleteAlarm","Monitoring Alarms"),
    ("monitoring","UpdateAlarm","Monitoring Alarms"),
    # Logging
    ("logging","CreateLogGroup","Log Groups"),
    ("logging","DeleteLogGroup","Log Groups"),
    ("logging","CreateLog","Logs"),
    ("logging","DeleteLog","Logs"),
    # Resource Manager
    ("resourcemanager","CreateStack","Resource Manager Stacks"),
    ("resourcemanager","DeleteStack","Resource Manager Stacks"),
    ("resourcemanager","UpdateStack","Resource Manager Stacks"),
    # WAF
    ("waf","CreateWebAppFirewallPolicy","WAF Policies"),
    ("waf","DeleteWebAppFirewallPolicy","WAF Policies"),
    ("waf","UpdateWebAppFirewallPolicy","WAF Policies"),
    # Bastion
    ("bastion","CreateBastion","Bastions"),
    ("bastion","DeleteBastion","Bastions"),
    ("bastion","CreateSession","Bastion Sessions"),
    ("bastion","DeleteSession","Bastion Sessions"),
    # DevOps
    ("devops","CreateProject","DevOps Projects"),
    ("devops","DeleteProject","DevOps Projects"),
    ("devops","CreateRepository","Code Repositories"),
    ("devops","DeleteRepository","Code Repositories"),
    ("devops","CreateDeployPipeline","Deploy Pipelines"),
    ("devops","DeleteDeployPipeline","Deploy Pipelines"),
    # Redis
    ("redis","CreateRedisCluster","Redis Clusters"),
    ("redis","DeleteRedisCluster","Redis Clusters"),
    ("redis","UpdateRedisCluster","Redis Clusters"),
    # Service Connector
    ("sch","CreateServiceConnector","Service Connectors"),
    ("sch","DeleteServiceConnector","Service Connectors"),
    ("sch","UpdateServiceConnector","Service Connectors"),
]


# ===========================================================================
# IBM RULES  (service_underscored, verb, resource_display)
# ===========================================================================
IBM_RULES: List[Tuple[str, str, str]] = [
    # IAM Identity
    ("iam_identity","create","IAM API Keys / Service IDs"),
    ("iam_identity","delete","IAM API Keys / Service IDs"),
    ("iam_identity","update","IAM API Keys / Service IDs"),
    ("iam_identity","lock","IAM Resources"),
    ("iam_identity","unlock","IAM Resources"),
    # IAM Access Management
    ("iam_access_management","create","IAM Policies / Groups"),
    ("iam_access_management","delete","IAM Policies / Groups"),
    ("iam_access_management","update","IAM Policies / Groups"),
    # IAM Groups
    ("iam_groups","create","IAM Access Groups"),
    ("iam_groups","delete","IAM Access Groups"),
    ("iam_groups","update","IAM Access Groups"),
    # Cloud Object Storage
    ("cloud_object_storage","create","COS Buckets / Objects"),
    ("cloud_object_storage","delete","COS Buckets / Objects"),
    ("cloud_object_storage","update","COS Buckets / Objects"),
    # Containers / Kubernetes
    ("containers_kubernetes","create","IKS Clusters / Workers"),
    ("containers_kubernetes","delete","IKS Clusters / Workers"),
    ("containers_kubernetes","update","IKS Clusters / Workers"),
    # VPC Infrastructure
    ("is","create","VPC Infrastructure Resources"),
    ("is","delete","VPC Infrastructure Resources"),
    ("is","update","VPC Infrastructure Resources"),
    ("is","start","VPC Instances"),
    ("is","stop","VPC Instances"),
    # Key Protect
    ("kms","create","Key Protect Keys"),
    ("kms","delete","Key Protect Keys"),
    ("kms","update","Key Protect Keys"),
    ("kms","rotate","Key Protect Keys"),
    ("kms","enable","Key Protect Keys"),
    ("kms","disable","Key Protect Keys"),
    # Secrets Manager
    ("secrets_manager","create","Secrets"),
    ("secrets_manager","delete","Secrets"),
    ("secrets_manager","update","Secrets"),
    ("secrets_manager","rotate","Secrets"),
    # Databases for PostgreSQL
    ("databases_for_postgresql","create","PostgreSQL Deployments"),
    ("databases_for_postgresql","delete","PostgreSQL Deployments"),
    ("databases_for_postgresql","update","PostgreSQL Deployments"),
    # Databases for Redis
    ("databases_for_redis","create","Redis Deployments"),
    ("databases_for_redis","delete","Redis Deployments"),
    ("databases_for_redis","update","Redis Deployments"),
    # Databases for MongoDB
    ("databases_for_mongodb","create","MongoDB Deployments"),
    ("databases_for_mongodb","delete","MongoDB Deployments"),
    ("databases_for_mongodb","update","MongoDB Deployments"),
    # Cloudant
    ("cloudantnosqldb","create","Cloudant Databases"),
    ("cloudantnosqldb","delete","Cloudant Databases"),
    ("cloudantnosqldb","update","Cloudant Databases"),
    # Event Streams
    ("messagehub","create","Event Streams Topics"),
    ("messagehub","delete","Event Streams Topics"),
    ("messagehub","update","Event Streams Topics"),
    # Functions
    ("functions","create","Cloud Functions Actions"),
    ("functions","delete","Cloud Functions Actions"),
    ("functions","update","Cloud Functions Actions"),
    # Code Engine
    ("codeengine","create","Code Engine Projects / Apps"),
    ("codeengine","delete","Code Engine Projects / Apps"),
    ("codeengine","update","Code Engine Projects / Apps"),
    # Container Registry
    ("container_registry","create","Container Registry Namespaces"),
    ("container_registry","delete","Container Registry Namespaces"),
    # Transit Gateway
    ("transit_gateway","create","Transit Gateways"),
    ("transit_gateway","delete","Transit Gateways"),
    ("transit_gateway","update","Transit Gateways"),
    # Resource Controller
    ("resource_controller","create","Service Instances"),
    ("resource_controller","delete","Service Instances"),
    ("resource_controller","update","Service Instances"),
    # Context-Based Restrictions
    ("context_based_restrictions","create","CBR Rules / Zones"),
    ("context_based_restrictions","delete","CBR Rules / Zones"),
    ("context_based_restrictions","update","CBR Rules / Zones"),
    # Continuous Delivery
    ("continuous_delivery","create","Toolchains / Pipelines"),
    ("continuous_delivery","delete","Toolchains / Pipelines"),
    ("continuous_delivery","update","Toolchains / Pipelines"),
    # DNS Services
    ("dns_svcs","create","DNS Zones / Records"),
    ("dns_svcs","delete","DNS Zones / Records"),
    ("dns_svcs","update","DNS Zones / Records"),
    # Hyper Protect Crypto
    ("hs_crypto","create","Hyper Protect Keys"),
    ("hs_crypto","delete","Hyper Protect Keys"),
    ("hs_crypto","rotate","Hyper Protect Keys"),
    # Security Advisor
    ("security_advisor","create","Security Advisor Notes"),
    ("security_advisor","delete","Security Advisor Notes"),
    ("security_advisor","update","Security Advisor Notes"),
    # Toolchain
    ("toolchain","create","Toolchains"),
    ("toolchain","delete","Toolchains"),
    ("toolchain","update","Toolchains"),
]


# ===========================================================================
# Generators
# ===========================================================================

def generate_azure(out: str):
    seen = set()
    with open(out, 'w') as f:
        f.write("-- CIEM Azure Log Rules\nBEGIN;\n\n")
        for (provider, resource, arm_op, action) in AZURE_RULES:
            op_snake = to_snake(arm_op.replace("Microsoft.", "").replace(provider + "/", "", 1))
            rule_id = f"log.azure.{provider}.{op_snake}"
            if rule_id in seen: continue
            seen.add(rule_id)
            cat = infer_action_category(arm_op + " " + action)
            domain = MITRE.get(cat, ('["persistence"]',''))[0].strip('[]"')
            emit(f, rule_id, provider, "azure",
                 f"Azure {provider.title()}: {action}",
                 f"Detected {arm_op} on {resource} via Azure Activity Log.",
                 domain, cat, "azure_activity", arm_op, azure_cfg(arm_op))
        f.write("COMMIT;\n")
    print(f"[Azure] {len(seen)} rules → {out}")


def generate_gcp(out: str):
    seen = set()
    with open(out, 'w') as f:
        f.write("-- CIEM GCP Log Rules\nBEGIN;\n\n")
        for (svc, method, op_display, resource) in GCP_RULES:
            rule_id = f"log.gcp.{svc}.{to_snake(method)}"
            if rule_id in seen: continue
            seen.add(rule_id)
            full_uri = GCP_SVC.get(svc, f"{svc}.googleapis.com")
            cat = infer_action_category(method + " " + op_display)
            domain = MITRE.get(cat, ('["persistence"]',''))[0].strip('[]"')
            emit(f, rule_id, full_uri, "gcp",
                 f"GCP {svc.title()}: {op_display}",
                 f"Detected {op_display} via GCP Cloud Audit Log (methodName contains '{method}').",
                 domain, cat, "gcp_audit", method, gcp_cfg(full_uri, method))
        f.write("COMMIT;\n")
    print(f"[GCP] {len(seen)} rules → {out}")


def generate_oci(out: str):
    seen = set()
    with open(out, 'w') as f:
        f.write("-- CIEM OCI Log Rules\nBEGIN;\n\n")
        for (svc, operation, resource) in OCI_RULES:
            rule_id = f"log.oci.{svc}.{to_snake(operation)}"
            if rule_id in seen: continue
            seen.add(rule_id)
            cadf = OCI_SVC.get(svc, f"com.oraclecloud.{svc}")
            cat = infer_action_category(operation)
            domain = MITRE.get(cat, ('["persistence"]',''))[0].strip('[]"')
            emit(f, rule_id, cadf, "oci",
                 f"OCI {svc.title()}: {operation}",
                 f"Detected {operation} CADF event on {resource} via OCI Audit Log.",
                 domain, cat, "oci_audit", operation, oci_cfg(cadf, operation))
        f.write("COMMIT;\n")
    print(f"[OCI] {len(seen)} rules → {out}")


def generate_ibm(out: str):
    seen = set()
    with open(out, 'w') as f:
        f.write("-- CIEM IBM Log Rules\nBEGIN;\n\n")
        for (svc, verb, resource) in IBM_RULES:
            rule_id = f"log.ibm.{svc}.{verb}"
            if rule_id in seen: continue
            seen.add(rule_id)
            cat = infer_action_category(verb)
            domain = MITRE.get(cat, ('["persistence"]',''))[0].strip('[]"')
            emit(f, rule_id, svc, "ibm",
                 f"IBM {svc.replace('_',' ').title()}: {verb.title()} {resource.split('/')[0].strip()}",
                 f"Detected '{verb}' operation on {resource} via IBM Activity Tracker.",
                 domain, cat, "ibm_activity", verb, ibm_cfg(svc, verb))
        f.write("COMMIT;\n")
    print(f"[IBM] {len(seen)} rules → {out}")


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    generate_azure(os.path.join(base, "ciem_azure_rules.sql"))
    generate_gcp(os.path.join(base,   "ciem_gcp_rules.sql"))
    generate_oci(os.path.join(base,   "ciem_oci_rules.sql"))
    generate_ibm(os.path.join(base,   "ciem_ibm_rules.sql"))
    print("\nDone. Run all 4 SQL files against threat_engine_check DB.")
