#!/usr/bin/env python3
"""
CIEM CRUD Rule Expansion — Azure / GCP / OCI / IBM
Targets: Azure 500+, GCP 400+, OCI 300+, IBM 400+
"""
import json
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── helpers ───────────────────────────────────────────────────────────────────

MITRE = {
    'create': ('["persistence"]',  '["T1136"]',  'persistence'),
    'delete': ('["impact"]',        '["T1485"]', 'impact'),
    'modify': ('["persistence"]',   '["T1098"]', 'persistence'),
    'read':   ('["discovery"]',     '["T1526"]', 'discovery'),
}
SEV   = {'create': 'high',   'delete': 'high',  'modify': 'medium', 'read': 'low'}
RISK  = {'create': 70,       'delete': 75,      'modify': 55,       'read': 30}
SRC   = {'azure': 'azure_activity', 'gcp': 'gcp_audit', 'oci': 'oci_audit', 'ibm': 'ibm_activity'}

ACTION_WORDS = {
    'create': ['create','insert','add','put','write','register','attach','launch',
               'allocate','publish','grant','deploy','enable','start'],
    'delete': ['delete','remove','deregister','detach','terminate','disable',
               'cancel','revoke','destroy','drop','purge','stop'],
    'modify': ['update','modify','change','set','patch','replace','rotate',
               'restore','resize','scale','tag','reset','reboot','flush','alter'],
    'read':   ['get','list','describe','read','show','query','search','export','fetch'],
}


def infer_cat(op: str) -> str:
    t = op.lower()
    for cat, words in ACTION_WORDS.items():
        if any(w in t for w in words):
            return cat
    return 'modify'


def sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def cfg_az(arm_op: str) -> str:
    d = {"conditions": {"all": [
        {"op": "equals", "field": "source_type", "value": "azure_activity"},
        {"op": "equals", "field": "operation",   "value": arm_op},
    ]}}
    return sql_str(json.dumps(d, separators=(',', ':')))


def cfg_gcp(svc_uri: str, method: str) -> str:
    d = {"conditions": {"all": [
        {"op": "equals",   "field": "source_type", "value": "gcp_audit"},
        {"op": "equals",   "field": "service",     "value": svc_uri},
        {"op": "contains", "field": "operation",   "value": method},
    ]}}
    return sql_str(json.dumps(d, separators=(',', ':')))


def cfg_oci(cadf: str, op: str) -> str:
    d = {"conditions": {"all": [
        {"op": "equals", "field": "source_type", "value": "oci_audit"},
        {"op": "equals", "field": "service",     "value": cadf},
        {"op": "equals", "field": "operation",   "value": op},
    ]}}
    return sql_str(json.dumps(d, separators=(',', ':')))


def cfg_ibm(svc: str, verb: str) -> str:
    d = {"conditions": {"all": [
        {"op": "equals",   "field": "source_type", "value": "ibm_activity"},
        {"op": "equals",   "field": "service",     "value": svc},
        {"op": "contains", "field": "operation",   "value": f".{verb}"},
    ]}}
    return sql_str(json.dumps(d, separators=(',', ':')))


def emit(f, rule_id, svc, provider, title, desc, cat, check_config, log_event):
    tactics, techniques, domain = MITRE[cat]
    sev  = SEV[cat]
    risk = RISK[cat]
    log_src = SRC[provider]
    f.write(
        f"INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)\n"
        f"VALUES ({sql_str(rule_id)},{sql_str(svc)},{sql_str(provider)},'log',true,{check_config})\n"
        f"ON CONFLICT DO NOTHING;\n\n"
    )
    f.write(
        f"INSERT INTO rule_metadata (\n"
        f"  rule_id,service,provider,severity,title,description,\n"
        f"  domain,subcategory,log_source_type,audit_log_event,action_category,\n"
        f"  rule_source,engines,primary_engine,\n"
        f"  mitre_tactics,mitre_techniques,risk_score,quality,csp\n"
        f") VALUES (\n"
        f"  {sql_str(rule_id)},{sql_str(svc)},{sql_str(provider)},\n"
        f"  {sql_str(sev)},{sql_str(title)},{sql_str(desc)},\n"
        f"  {sql_str(domain)},{sql_str(cat)},{sql_str(log_src)},\n"
        f"  {sql_str(log_event)},{sql_str(cat)},\n"
        f"  'log','{{\"ciem_engine\"}}','ciem_engine',\n"
        f"  '{tactics}','{techniques}',{risk},'auto',{sql_str(provider)}\n"
        f") ON CONFLICT DO NOTHING;\n\n"
    )


# ── Azure ─────────────────────────────────────────────────────────────────────

def generate_azure(out_dir):
    path = os.path.join(out_dir, "ciem_azure_crud_expanded.sql")
    n = 0

    # (svc_short, resource_display, arm_op, action_display)
    rules = [
        # ── DNS (public zones) ────────────────────────────────────────────────
        ("dns","DNS Zones","Microsoft.Network/dnsZones/write","Create/Update DNS Zone"),
        ("dns","DNS Zones","Microsoft.Network/dnsZones/delete","Delete DNS Zone"),
        ("dns","DNS Record Sets","Microsoft.Network/dnsZones/A/write","Create/Update A Record"),
        ("dns","DNS Record Sets","Microsoft.Network/dnsZones/A/delete","Delete A Record"),
        ("dns","DNS Record Sets","Microsoft.Network/dnsZones/CNAME/write","Create/Update CNAME Record"),
        ("dns","DNS Record Sets","Microsoft.Network/dnsZones/MX/write","Create/Update MX Record"),
        ("dns","DNS Record Sets","Microsoft.Network/dnsZones/TXT/write","Create/Update TXT Record"),

        # ── Container Instances ───────────────────────────────────────────────
        ("containerinstance","Container Groups","Microsoft.ContainerInstance/containerGroups/write","Create/Update Container Group"),
        ("containerinstance","Container Groups","Microsoft.ContainerInstance/containerGroups/delete","Delete Container Group"),
        ("containerinstance","Container Groups","Microsoft.ContainerInstance/containerGroups/start/action","Start Container Group"),
        ("containerinstance","Container Groups","Microsoft.ContainerInstance/containerGroups/stop/action","Stop Container Group"),
        ("containerinstance","Container Groups","Microsoft.ContainerInstance/containerGroups/restart/action","Restart Container Group"),

        # ── App Service (extra ops) ───────────────────────────────────────────
        ("web","App Service Plans","Microsoft.Web/serverfarms/write","Create/Update App Service Plan"),
        ("web","App Service Plans","Microsoft.Web/serverfarms/delete","Delete App Service Plan"),
        ("web","Web Apps","Microsoft.Web/sites/write","Create/Update Web App"),
        ("web","Web Apps","Microsoft.Web/sites/delete","Delete Web App"),
        ("web","Web App Slots","Microsoft.Web/sites/slots/write","Create/Update Deployment Slot"),
        ("web","Web App Slots","Microsoft.Web/sites/slots/delete","Delete Deployment Slot"),
        ("web","Web App Configs","Microsoft.Web/sites/config/write","Update App Configuration"),
        ("web","Web App Certificates","Microsoft.Web/certificates/write","Create/Update SSL Certificate"),
        ("web","Web App Certificates","Microsoft.Web/certificates/delete","Delete SSL Certificate"),
        ("web","Static Sites","Microsoft.Web/staticSites/write","Create/Update Static Web App"),
        ("web","Static Sites","Microsoft.Web/staticSites/delete","Delete Static Web App"),

        # ── Stream Analytics ──────────────────────────────────────────────────
        ("streamanalytics","Stream Analytics Jobs","Microsoft.StreamAnalytics/streamingjobs/write","Create/Update Stream Analytics Job"),
        ("streamanalytics","Stream Analytics Jobs","Microsoft.StreamAnalytics/streamingjobs/delete","Delete Stream Analytics Job"),
        ("streamanalytics","Stream Analytics Jobs","Microsoft.StreamAnalytics/streamingjobs/start/action","Start Stream Analytics Job"),
        ("streamanalytics","Stream Analytics Jobs","Microsoft.StreamAnalytics/streamingjobs/stop/action","Stop Stream Analytics Job"),
        ("streamanalytics","Stream Analytics Inputs","Microsoft.StreamAnalytics/streamingjobs/inputs/write","Create/Update Stream Analytics Input"),
        ("streamanalytics","Stream Analytics Outputs","Microsoft.StreamAnalytics/streamingjobs/outputs/write","Create/Update Stream Analytics Output"),

        # ── Azure Data Explorer (Kusto) ───────────────────────────────────────
        ("kusto","Kusto Clusters","Microsoft.Kusto/clusters/write","Create/Update Kusto Cluster"),
        ("kusto","Kusto Clusters","Microsoft.Kusto/clusters/delete","Delete Kusto Cluster"),
        ("kusto","Kusto Clusters","Microsoft.Kusto/clusters/start/action","Start Kusto Cluster"),
        ("kusto","Kusto Clusters","Microsoft.Kusto/clusters/stop/action","Stop Kusto Cluster"),
        ("kusto","Kusto Databases","Microsoft.Kusto/clusters/databases/write","Create/Update Kusto Database"),
        ("kusto","Kusto Databases","Microsoft.Kusto/clusters/databases/delete","Delete Kusto Database"),
        ("kusto","Kusto Data Connections","Microsoft.Kusto/clusters/databases/dataConnections/write","Create/Update Data Connection"),

        # ── SignalR Service ───────────────────────────────────────────────────
        ("signalr","SignalR","Microsoft.SignalRService/signalR/write","Create/Update SignalR Service"),
        ("signalr","SignalR","Microsoft.SignalRService/signalR/delete","Delete SignalR Service"),
        ("signalr","Web PubSub","Microsoft.SignalRService/webPubSub/write","Create/Update Web PubSub Service"),
        ("signalr","Web PubSub","Microsoft.SignalRService/webPubSub/delete","Delete Web PubSub Service"),

        # ── Azure Relay ───────────────────────────────────────────────────────
        ("relay","Relay Namespaces","Microsoft.Relay/namespaces/write","Create/Update Relay Namespace"),
        ("relay","Relay Namespaces","Microsoft.Relay/namespaces/delete","Delete Relay Namespace"),
        ("relay","Hybrid Connections","Microsoft.Relay/namespaces/hybridConnections/write","Create/Update Hybrid Connection"),
        ("relay","WCF Relays","Microsoft.Relay/namespaces/wcfRelays/write","Create/Update WCF Relay"),

        # ── Azure Maps ────────────────────────────────────────────────────────
        ("maps","Maps Accounts","Microsoft.Maps/accounts/write","Create/Update Maps Account"),
        ("maps","Maps Accounts","Microsoft.Maps/accounts/delete","Delete Maps Account"),

        # ── Notification Hubs ─────────────────────────────────────────────────
        ("notificationhubs","Notification Hub Namespaces","Microsoft.NotificationHubs/namespaces/write","Create/Update Notification Hub Namespace"),
        ("notificationhubs","Notification Hub Namespaces","Microsoft.NotificationHubs/namespaces/delete","Delete Notification Hub Namespace"),
        ("notificationhubs","Notification Hubs","Microsoft.NotificationHubs/namespaces/notificationHubs/write","Create/Update Notification Hub"),
        ("notificationhubs","Notification Hubs","Microsoft.NotificationHubs/namespaces/notificationHubs/delete","Delete Notification Hub"),

        # ── Azure NetApp Files ────────────────────────────────────────────────
        ("netapp","NetApp Accounts","Microsoft.NetApp/netAppAccounts/write","Create/Update NetApp Account"),
        ("netapp","NetApp Accounts","Microsoft.NetApp/netAppAccounts/delete","Delete NetApp Account"),
        ("netapp","Capacity Pools","Microsoft.NetApp/netAppAccounts/capacityPools/write","Create/Update Capacity Pool"),
        ("netapp","Capacity Pools","Microsoft.NetApp/netAppAccounts/capacityPools/delete","Delete Capacity Pool"),
        ("netapp","Volumes","Microsoft.NetApp/netAppAccounts/capacityPools/volumes/write","Create/Update NetApp Volume"),
        ("netapp","Volumes","Microsoft.NetApp/netAppAccounts/capacityPools/volumes/delete","Delete NetApp Volume"),
        ("netapp","Snapshots","Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/write","Create/Update NetApp Snapshot"),
        ("netapp","Snapshots","Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/delete","Delete NetApp Snapshot"),

        # ── Azure Virtual Desktop ─────────────────────────────────────────────
        ("desktopvirtualization","AVD Host Pools","Microsoft.DesktopVirtualization/hostpools/write","Create/Update AVD Host Pool"),
        ("desktopvirtualization","AVD Host Pools","Microsoft.DesktopVirtualization/hostpools/delete","Delete AVD Host Pool"),
        ("desktopvirtualization","AVD Application Groups","Microsoft.DesktopVirtualization/applicationgroups/write","Create/Update AVD Application Group"),
        ("desktopvirtualization","AVD Application Groups","Microsoft.DesktopVirtualization/applicationgroups/delete","Delete AVD Application Group"),
        ("desktopvirtualization","AVD Workspaces","Microsoft.DesktopVirtualization/workspaces/write","Create/Update AVD Workspace"),
        ("desktopvirtualization","AVD Session Hosts","Microsoft.DesktopVirtualization/hostpools/sessionhosts/write","Create/Update AVD Session Host"),
        ("desktopvirtualization","AVD Session Hosts","Microsoft.DesktopVirtualization/hostpools/sessionhosts/delete","Delete AVD Session Host"),

        # ── Azure Arc (Servers + Kubernetes) ─────────────────────────────────
        ("hybridcompute","Arc Servers","Microsoft.HybridCompute/machines/write","Register/Update Arc Server"),
        ("hybridcompute","Arc Servers","Microsoft.HybridCompute/machines/delete","Delete Arc Server"),
        ("hybridcompute","Arc Extensions","Microsoft.HybridCompute/machines/extensions/write","Install Arc Server Extension"),
        ("hybridcompute","Arc Extensions","Microsoft.HybridCompute/machines/extensions/delete","Remove Arc Server Extension"),
        ("kubernetes","Arc Kubernetes","Microsoft.Kubernetes/connectedClusters/write","Register/Update Arc Kubernetes Cluster"),
        ("kubernetes","Arc Kubernetes","Microsoft.Kubernetes/connectedClusters/delete","Delete Arc Kubernetes Cluster"),
        ("kubernetes","Arc K8s Extensions","Microsoft.KubernetesConfiguration/extensions/write","Create/Update Arc K8s Extension"),
        ("kubernetes","Arc K8s Extensions","Microsoft.KubernetesConfiguration/extensions/delete","Delete Arc K8s Extension"),

        # ── Azure Digital Twins ───────────────────────────────────────────────
        ("digitaltwins","Digital Twins","Microsoft.DigitalTwins/digitalTwinsInstances/write","Create/Update Digital Twins Instance"),
        ("digitaltwins","Digital Twins","Microsoft.DigitalTwins/digitalTwinsInstances/delete","Delete Digital Twins Instance"),
        ("digitaltwins","DT Endpoints","Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write","Create/Update Digital Twins Endpoint"),

        # ── Azure Spring Apps ─────────────────────────────────────────────────
        ("appplatform","Spring Apps","Microsoft.AppPlatform/Spring/write","Create/Update Spring Apps Service"),
        ("appplatform","Spring Apps","Microsoft.AppPlatform/Spring/delete","Delete Spring Apps Service"),
        ("appplatform","Spring Apps","Microsoft.AppPlatform/Spring/apps/write","Create/Update Spring App"),
        ("appplatform","Spring Apps","Microsoft.AppPlatform/Spring/apps/delete","Delete Spring App"),
        ("appplatform","Spring Deployments","Microsoft.AppPlatform/Spring/apps/deployments/write","Create/Update Spring App Deployment"),

        # ── Bot Service ───────────────────────────────────────────────────────
        ("botservice","Bot Services","Microsoft.BotService/botServices/write","Create/Update Bot Service"),
        ("botservice","Bot Services","Microsoft.BotService/botServices/delete","Delete Bot Service"),
        ("botservice","Bot Channels","Microsoft.BotService/botServices/channels/write","Create/Update Bot Channel"),

        # ── Power BI Embedded ─────────────────────────────────────────────────
        ("powerbidedicated","Power BI Capacities","Microsoft.PowerBIDedicated/capacities/write","Create/Update Power BI Capacity"),
        ("powerbidedicated","Power BI Capacities","Microsoft.PowerBIDedicated/capacities/delete","Delete Power BI Capacity"),

        # ── Microsoft Purview ─────────────────────────────────────────────────
        ("purview","Purview Accounts","Microsoft.Purview/accounts/write","Create/Update Purview Account"),
        ("purview","Purview Accounts","Microsoft.Purview/accounts/delete","Delete Purview Account"),

        # ── Data Lake ─────────────────────────────────────────────────────────
        ("datalakestore","Data Lake Store","Microsoft.DataLakeStore/accounts/write","Create/Update Data Lake Store Account"),
        ("datalakestore","Data Lake Store","Microsoft.DataLakeStore/accounts/delete","Delete Data Lake Store Account"),
        ("datalakeanalytics","Data Lake Analytics","Microsoft.DataLakeAnalytics/accounts/write","Create/Update Data Lake Analytics Account"),
        ("datalakeanalytics","Data Lake Analytics","Microsoft.DataLakeAnalytics/accounts/delete","Delete Data Lake Analytics Account"),
        ("datalakeanalytics","DL Analytics Jobs","Microsoft.DataLakeAnalytics/accounts/jobs/write","Submit Data Lake Analytics Job"),

        # ── Batch ─────────────────────────────────────────────────────────────
        ("batch","Batch Accounts","Microsoft.Batch/batchAccounts/write","Create/Update Batch Account"),
        ("batch","Batch Accounts","Microsoft.Batch/batchAccounts/delete","Delete Batch Account"),
        ("batch","Batch Pools","Microsoft.Batch/batchAccounts/pools/write","Create/Update Batch Pool"),
        ("batch","Batch Pools","Microsoft.Batch/batchAccounts/pools/delete","Delete Batch Pool"),
        ("batch","Batch Jobs","Microsoft.Batch/batchAccounts/jobs/write","Create/Update Batch Job"),
        ("batch","Batch Jobs","Microsoft.Batch/batchAccounts/jobs/delete","Delete Batch Job"),

        # ── Healthcare APIs (FHIR / DICOM) ────────────────────────────────────
        ("healthcareapis","Healthcare Workspaces","Microsoft.HealthcareApis/workspaces/write","Create/Update Healthcare Workspace"),
        ("healthcareapis","Healthcare Workspaces","Microsoft.HealthcareApis/workspaces/delete","Delete Healthcare Workspace"),
        ("healthcareapis","FHIR Services","Microsoft.HealthcareApis/workspaces/fhirservices/write","Create/Update FHIR Service"),
        ("healthcareapis","FHIR Services","Microsoft.HealthcareApis/workspaces/fhirservices/delete","Delete FHIR Service"),
        ("healthcareapis","DICOM Services","Microsoft.HealthcareApis/workspaces/dicomservices/write","Create/Update DICOM Service"),

        # ── IoT Hub (extra ops) ───────────────────────────────────────────────
        ("devices","IoT Hubs","Microsoft.Devices/IotHubs/write","Create/Update IoT Hub"),
        ("devices","IoT Hubs","Microsoft.Devices/IotHubs/delete","Delete IoT Hub"),
        ("devices","IoT Hub Keys","Microsoft.Devices/IotHubs/IotHubKeys/write","Create/Update IoT Hub Key"),
        ("devices","IoT Provisioning","Microsoft.Devices/provisioningServices/write","Create/Update IoT DPS"),
        ("devices","IoT Provisioning","Microsoft.Devices/provisioningServices/delete","Delete IoT DPS"),
        ("devices","IoT Central","Microsoft.IoTCentral/IoTApps/write","Create/Update IoT Central App"),
        ("devices","IoT Central","Microsoft.IoTCentral/IoTApps/delete","Delete IoT Central App"),

        # ── Network (extra ops) ───────────────────────────────────────────────
        ("network","Firewall Policies","Microsoft.Network/firewallPolicies/write","Create/Update Firewall Policy"),
        ("network","Firewall Policies","Microsoft.Network/firewallPolicies/delete","Delete Firewall Policy"),
        ("network","Firewall Policy Rules","Microsoft.Network/firewallPolicies/ruleCollectionGroups/write","Create/Update Firewall Policy Rule Collection"),
        ("network","App Security Groups","Microsoft.Network/applicationSecurityGroups/write","Create/Update Application Security Group"),
        ("network","App Security Groups","Microsoft.Network/applicationSecurityGroups/delete","Delete Application Security Group"),
        ("network","Traffic Manager","Microsoft.Network/trafficManagerProfiles/write","Create/Update Traffic Manager Profile"),
        ("network","Traffic Manager","Microsoft.Network/trafficManagerProfiles/delete","Delete Traffic Manager Profile"),
        ("network","DDoS Protection Plans","Microsoft.Network/ddosProtectionPlans/write","Create/Update DDoS Protection Plan"),
        ("network","DDoS Protection Plans","Microsoft.Network/ddosProtectionPlans/delete","Delete DDoS Protection Plan"),
        ("network","Virtual Hubs","Microsoft.Network/virtualHubs/write","Create/Update Virtual Hub (WAN)"),
        ("network","Virtual Hubs","Microsoft.Network/virtualHubs/delete","Delete Virtual Hub"),
        ("network","Virtual WANs","Microsoft.Network/virtualWans/write","Create/Update Virtual WAN"),
        ("network","Virtual WANs","Microsoft.Network/virtualWans/delete","Delete Virtual WAN"),
        ("network","VPN Sites","Microsoft.Network/vpnSites/write","Create/Update VPN Site"),
        ("network","Front Doors","Microsoft.Network/frontDoors/write","Create/Update Front Door"),
        ("network","Front Doors","Microsoft.Network/frontDoors/delete","Delete Front Door"),
        ("network","Service Endpoint Policies","Microsoft.Network/serviceEndpointPolicies/write","Create/Update Service Endpoint Policy"),
        ("network","Flow Logs","Microsoft.Network/networkWatchers/flowLogs/write","Create/Update Flow Log"),
        ("network","Flow Logs","Microsoft.Network/networkWatchers/flowLogs/delete","Delete Flow Log"),
        ("network","IP Groups","Microsoft.Network/ipGroups/write","Create/Update IP Group (Firewall)"),
        ("network","Connection Monitors","Microsoft.Network/networkWatchers/connectionMonitors/write","Create/Update Connection Monitor"),

        # ── SQL extra ops ─────────────────────────────────────────────────────
        ("sql","SQL Elastic Pools","Microsoft.Sql/servers/elasticPools/write","Create/Update Elastic Pool"),
        ("sql","SQL Elastic Pools","Microsoft.Sql/servers/elasticPools/delete","Delete Elastic Pool"),
        ("sql","SQL Failover Groups","Microsoft.Sql/servers/failoverGroups/write","Create/Update SQL Failover Group"),
        ("sql","SQL Managed Instances","Microsoft.Sql/managedInstances/write","Create/Update SQL Managed Instance"),
        ("sql","SQL Managed Instances","Microsoft.Sql/managedInstances/delete","Delete SQL Managed Instance"),
        ("sql","SQL Managed DBs","Microsoft.Sql/managedInstances/databases/write","Create/Update SQL Managed Database"),
        ("sql","SQL Managed DBs","Microsoft.Sql/managedInstances/databases/delete","Delete SQL Managed Database"),
        ("sql","SQL Advanced Threat","Microsoft.Sql/servers/securityAlertPolicies/write","Update SQL Advanced Threat Protection"),
        ("sql","SQL Advanced Threat","Microsoft.Sql/servers/databases/securityAlertPolicies/write","Update DB-Level SQL Threat Protection"),
        ("sql","SQL Long Term Backup","Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies/write","Update SQL Long Term Retention Policy"),

        # ── Compute extra ops ─────────────────────────────────────────────────
        ("compute","Disk Encryption Sets","Microsoft.Compute/diskEncryptionSets/write","Create/Update Disk Encryption Set"),
        ("compute","Disk Encryption Sets","Microsoft.Compute/diskEncryptionSets/delete","Delete Disk Encryption Set"),
        ("compute","Dedicated Hosts","Microsoft.Compute/hostGroups/hosts/write","Create/Update Dedicated Host"),
        ("compute","Dedicated Hosts","Microsoft.Compute/hostGroups/hosts/delete","Delete Dedicated Host"),
        ("compute","Capacity Reservations","Microsoft.Compute/capacityReservationGroups/capacityReservations/write","Create/Update Capacity Reservation"),
        ("compute","VM Run Commands","Microsoft.Compute/virtualMachines/runCommands/write","Create/Update VM Run Command"),
        ("compute","Proximity Placement Groups","Microsoft.Compute/proximityPlacementGroups/write","Create/Update Proximity Placement Group"),

        # ── Storage extra ops ─────────────────────────────────────────────────
        ("storage","Storage Table Services","Microsoft.Storage/storageAccounts/tableServices/tables/write","Create/Update Table Storage Table"),
        ("storage","Storage Table Services","Microsoft.Storage/storageAccounts/tableServices/tables/delete","Delete Table Storage Table"),
        ("storage","Storage Encryption Scopes","Microsoft.Storage/storageAccounts/encryptionScopes/write","Create/Update Encryption Scope"),
        ("storage","Storage ADLS","Microsoft.Storage/storageAccounts/blobServices/write","Update Blob Service Properties (ADLS/versioning)"),
        ("storage","Storage Object Replication","Microsoft.Storage/storageAccounts/objectReplicationPolicies/write","Create/Update Object Replication Policy"),
        ("storage","Storage Object Replication","Microsoft.Storage/storageAccounts/objectReplicationPolicies/delete","Delete Object Replication Policy"),

        # ── Key Vault extra ops ───────────────────────────────────────────────
        ("keyvault","Key Vault Access Policies","Microsoft.KeyVault/vaults/accessPolicies/write","Update Key Vault Access Policy"),
        ("keyvault","Managed HSMs","Microsoft.KeyVault/managedHSMs/write","Create/Update Managed HSM"),
        ("keyvault","Managed HSMs","Microsoft.KeyVault/managedHSMs/delete","Delete Managed HSM"),
        ("keyvault","Key Vault Certificates","Microsoft.KeyVault/vaults/certificates/write","Create/Update Certificate"),
        ("keyvault","Key Vault Certificates","Microsoft.KeyVault/vaults/certificates/delete","Delete Certificate"),

        # ── Container Registry extra ops ──────────────────────────────────────
        ("containerregistry","ACR Webhooks","Microsoft.ContainerRegistry/registries/webhooks/write","Create/Update ACR Webhook"),
        ("containerregistry","ACR Webhooks","Microsoft.ContainerRegistry/registries/webhooks/delete","Delete ACR Webhook"),
        ("containerregistry","ACR Replications","Microsoft.ContainerRegistry/registries/replications/write","Create/Update ACR Geo-Replication"),
        ("containerregistry","ACR Tasks","Microsoft.ContainerRegistry/registries/tasks/write","Create/Update ACR Task"),
        ("containerregistry","ACR ScopeMap","Microsoft.ContainerRegistry/registries/scopeMaps/write","Create/Update ACR Scope Map"),
        ("containerregistry","ACR Tokens","Microsoft.ContainerRegistry/registries/tokens/write","Create/Update ACR Token"),
        ("containerregistry","ACR Tokens","Microsoft.ContainerRegistry/registries/tokens/delete","Delete ACR Token"),

        # ── AKS extra ops ─────────────────────────────────────────────────────
        ("containerservice","AKS Node Pools","Microsoft.ContainerService/managedClusters/agentPools/write","Create/Update AKS Node Pool"),
        ("containerservice","AKS Node Pools","Microsoft.ContainerService/managedClusters/agentPools/delete","Delete AKS Node Pool"),
        ("containerservice","AKS Maintenance","Microsoft.ContainerService/managedClusters/maintenanceConfigurations/write","Create/Update AKS Maintenance Configuration"),
        ("containerservice","AKS Private Link","Microsoft.ContainerService/managedClusters/privateEndpointConnections/write","Update AKS Private Endpoint Connection"),

        # ── Cosmos DB extra ops ───────────────────────────────────────────────
        ("documentdb","Cosmos DB Accounts","Microsoft.DocumentDB/databaseAccounts/write","Create/Update Cosmos DB Account"),
        ("documentdb","Cosmos DB Accounts","Microsoft.DocumentDB/databaseAccounts/delete","Delete Cosmos DB Account"),
        ("documentdb","Cosmos SQL Databases","Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write","Create/Update Cosmos SQL Database"),
        ("documentdb","Cosmos SQL Databases","Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete","Delete Cosmos SQL Database"),
        ("documentdb","Cosmos SQL Containers","Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write","Create/Update Cosmos SQL Container"),
        ("documentdb","Cosmos MongoDB","Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write","Create/Update Cosmos MongoDB Database"),
        ("documentdb","Cosmos Cassandra","Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces/write","Create/Update Cosmos Cassandra Keyspace"),
        ("documentdb","Cosmos Gremlin","Microsoft.DocumentDB/databaseAccounts/gremlinDatabases/write","Create/Update Cosmos Gremlin Database"),
        ("documentdb","Cosmos Table","Microsoft.DocumentDB/databaseAccounts/tables/write","Create/Update Cosmos Table API Table"),
        ("documentdb","Cosmos Private Endpoint","Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections/write","Update Cosmos DB Private Endpoint"),

        # ── MySQL / PostgreSQL / MariaDB ───────────────────────────────────────
        ("dbformysql","MySQL Flexible Servers","Microsoft.DBforMySQL/flexibleServers/write","Create/Update MySQL Flexible Server"),
        ("dbformysql","MySQL Flexible Servers","Microsoft.DBforMySQL/flexibleServers/delete","Delete MySQL Flexible Server"),
        ("dbformysql","MySQL Single Servers","Microsoft.DBforMySQL/servers/write","Create/Update MySQL Single Server"),
        ("dbformysql","MySQL Firewall Rules","Microsoft.DBforMySQL/flexibleServers/firewallRules/write","Create/Update MySQL Firewall Rule"),
        ("dbforpostgresql","PostgreSQL Flexible","Microsoft.DBforPostgreSQL/flexibleServers/write","Create/Update PostgreSQL Flexible Server"),
        ("dbforpostgresql","PostgreSQL Flexible","Microsoft.DBforPostgreSQL/flexibleServers/delete","Delete PostgreSQL Flexible Server"),
        ("dbforpostgresql","PostgreSQL Single","Microsoft.DBforPostgreSQL/servers/write","Create/Update PostgreSQL Single Server"),
        ("dbforpostgresql","PostgreSQL Firewall","Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write","Create/Update PostgreSQL Firewall Rule"),
        ("dbformariadb","MariaDB Servers","Microsoft.DBforMariaDB/servers/write","Create/Update MariaDB Server"),
        ("dbformariadb","MariaDB Servers","Microsoft.DBforMariaDB/servers/delete","Delete MariaDB Server"),

        # ── Event Grid ────────────────────────────────────────────────────────
        ("eventgrid","Event Grid Topics","Microsoft.EventGrid/topics/write","Create/Update Event Grid Topic"),
        ("eventgrid","Event Grid Topics","Microsoft.EventGrid/topics/delete","Delete Event Grid Topic"),
        ("eventgrid","Event Grid Domains","Microsoft.EventGrid/domains/write","Create/Update Event Grid Domain"),
        ("eventgrid","Event Grid Subs","Microsoft.EventGrid/eventSubscriptions/write","Create/Update Event Subscription"),
        ("eventgrid","Event Grid Subs","Microsoft.EventGrid/eventSubscriptions/delete","Delete Event Subscription"),
        ("eventgrid","Event Grid Namespaces","Microsoft.EventGrid/namespaces/write","Create/Update Event Grid Namespace"),

        # ── Logic Apps ────────────────────────────────────────────────────────
        ("logic","Logic Apps Standard","Microsoft.Logic/workflows/write","Create/Update Logic App"),
        ("logic","Logic Apps Standard","Microsoft.Logic/workflows/delete","Delete Logic App"),
        ("logic","Logic App Runs","Microsoft.Logic/workflows/runs/delete","Delete Logic App Run History"),
        ("logic","Integration Accounts","Microsoft.Logic/integrationAccounts/write","Create/Update Integration Account"),
        ("logic","Integration Accounts","Microsoft.Logic/integrationAccounts/delete","Delete Integration Account"),

        # ── Synapse extra ops ─────────────────────────────────────────────────
        ("synapse","Synapse Workspaces","Microsoft.Synapse/workspaces/write","Create/Update Synapse Workspace"),
        ("synapse","Synapse Workspaces","Microsoft.Synapse/workspaces/delete","Delete Synapse Workspace"),
        ("synapse","Synapse SQL Pools","Microsoft.Synapse/workspaces/sqlPools/write","Create/Update Synapse SQL Pool"),
        ("synapse","Synapse SQL Pools","Microsoft.Synapse/workspaces/sqlPools/delete","Delete Synapse SQL Pool"),
        ("synapse","Synapse Spark Pools","Microsoft.Synapse/workspaces/bigDataPools/write","Create/Update Synapse Spark Pool"),
        ("synapse","Synapse Pipelines","Microsoft.Synapse/workspaces/integrationRuntimes/write","Create/Update Synapse Integration Runtime"),
        ("synapse","Synapse Firewall","Microsoft.Synapse/workspaces/firewallRules/write","Create/Update Synapse Firewall Rule"),

        # ── Data Factory extra ops ────────────────────────────────────────────
        ("datafactory","ADF Pipelines","Microsoft.DataFactory/factories/pipelines/write","Create/Update ADF Pipeline"),
        ("datafactory","ADF Pipelines","Microsoft.DataFactory/factories/pipelines/delete","Delete ADF Pipeline"),
        ("datafactory","ADF Datasets","Microsoft.DataFactory/factories/datasets/write","Create/Update ADF Dataset"),
        ("datafactory","ADF Linked Services","Microsoft.DataFactory/factories/linkedservices/write","Create/Update ADF Linked Service"),
        ("datafactory","ADF Triggers","Microsoft.DataFactory/factories/triggers/write","Create/Update ADF Trigger"),
        ("datafactory","ADF IRs","Microsoft.DataFactory/factories/integrationRuntimes/write","Create/Update ADF Integration Runtime"),

        # ── Databricks extra ops ──────────────────────────────────────────────
        ("databricks","Databricks Clusters","Microsoft.Databricks/workspaces/virtualNetworkPeerings/write","Create/Update Databricks VNet Peering"),
        ("databricks","Databricks Workspaces","Microsoft.Databricks/workspaces/write","Create/Update Databricks Workspace"),
        ("databricks","Databricks Workspaces","Microsoft.Databricks/workspaces/delete","Delete Databricks Workspace"),

        # ── API Management extra ops ──────────────────────────────────────────
        ("apimanagement","APIM Backends","Microsoft.ApiManagement/service/backends/write","Create/Update APIM Backend"),
        ("apimanagement","APIM Policies","Microsoft.ApiManagement/service/policies/write","Create/Update APIM Global Policy"),
        ("apimanagement","APIM APIs","Microsoft.ApiManagement/service/apis/write","Create/Update APIM API"),
        ("apimanagement","APIM APIs","Microsoft.ApiManagement/service/apis/delete","Delete APIM API"),
        ("apimanagement","APIM Subscriptions","Microsoft.ApiManagement/service/subscriptions/write","Create/Update APIM Subscription"),
        ("apimanagement","APIM Products","Microsoft.ApiManagement/service/products/write","Create/Update APIM Product"),

        # ── Cognitive Services extra ops ──────────────────────────────────────
        ("cognitiveservices","Cognitive Services","Microsoft.CognitiveServices/accounts/write","Create/Update Cognitive Services Account"),
        ("cognitiveservices","Cognitive Services","Microsoft.CognitiveServices/accounts/delete","Delete Cognitive Services Account"),
        ("cognitiveservices","Cognitive Deployments","Microsoft.CognitiveServices/accounts/deployments/write","Create/Update Cognitive Services Deployment (AI Model)"),
        ("cognitiveservices","Cognitive Deployments","Microsoft.CognitiveServices/accounts/deployments/delete","Delete Cognitive Services Model Deployment"),

        # ── ML / AI Platform extra ops ────────────────────────────────────────
        ("machinelearningservices","ML Workspaces","Microsoft.MachineLearningServices/workspaces/write","Create/Update ML Workspace"),
        ("machinelearningservices","ML Workspaces","Microsoft.MachineLearningServices/workspaces/delete","Delete ML Workspace"),
        ("machinelearningservices","ML Compute","Microsoft.MachineLearningServices/workspaces/computes/write","Create/Update ML Compute Cluster"),
        ("machinelearningservices","ML Jobs","Microsoft.MachineLearningServices/workspaces/jobs/write","Create/Update ML Training Job"),
        ("machinelearningservices","ML Endpoints","Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write","Create/Update ML Online Endpoint"),

        # ── Recovery Services extra ops ────────────────────────────────────────
        ("recoveryservices","Recovery Vaults","Microsoft.RecoveryServices/vaults/write","Create/Update Recovery Services Vault"),
        ("recoveryservices","Recovery Vaults","Microsoft.RecoveryServices/vaults/delete","Delete Recovery Services Vault"),
        ("recoveryservices","Backup Protected Items","Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/write","Create/Update Backup Protected Item"),
        ("recoveryservices","ASR Replication","Microsoft.RecoveryServices/vaults/replicationFabrics/write","Create/Update Site Recovery Fabric"),
        ("recoveryservices","ASR Policies","Microsoft.RecoveryServices/vaults/replicationPolicies/write","Create/Update ASR Replication Policy"),

        # ── Monitor extra ops ─────────────────────────────────────────────────
        ("insights","Alert Rules","Microsoft.Insights/metricAlerts/write","Create/Update Metric Alert Rule"),
        ("insights","Alert Rules","Microsoft.Insights/metricAlerts/delete","Delete Metric Alert Rule"),
        ("insights","Action Groups","Microsoft.Insights/actionGroups/write","Create/Update Action Group"),
        ("insights","Action Groups","Microsoft.Insights/actionGroups/delete","Delete Action Group"),
        ("insights","Data Collection Rules","Microsoft.Insights/dataCollectionRules/write","Create/Update Data Collection Rule"),
        ("insights","Data Collection Rules","Microsoft.Insights/dataCollectionRules/delete","Delete Data Collection Rule"),
        ("insights","Scheduled Query Rules","Microsoft.Insights/scheduledQueryRules/write","Create/Update Scheduled Query Alert"),
        ("insights","Autoscale Settings","Microsoft.Insights/autoscaleSettings/write","Create/Update Autoscale Setting"),

        # ── Sentinel / Security Insights ──────────────────────────────────────
        ("securityinsights","Sentinel Analytics Rules","Microsoft.SecurityInsights/alertRules/write","Create/Update Sentinel Analytics Rule"),
        ("securityinsights","Sentinel Analytics Rules","Microsoft.SecurityInsights/alertRules/delete","Delete Sentinel Analytics Rule"),
        ("securityinsights","Sentinel Data Connectors","Microsoft.SecurityInsights/dataConnectors/write","Create/Update Sentinel Data Connector"),
        ("securityinsights","Sentinel Data Connectors","Microsoft.SecurityInsights/dataConnectors/delete","Delete Sentinel Data Connector"),
        ("securityinsights","Sentinel Automation Rules","Microsoft.SecurityInsights/automationRules/write","Create/Update Sentinel Automation Rule"),
        ("securityinsights","Sentinel Incidents","Microsoft.SecurityInsights/incidents/write","Update Sentinel Incident"),

        # ── Management Groups / Subscriptions ────────────────────────────────
        ("managementgroups","Management Groups","Microsoft.Management/managementGroups/write","Create/Update Management Group"),
        ("managementgroups","Management Groups","Microsoft.Management/managementGroups/delete","Delete Management Group"),
        ("managementgroups","Subscription Placement","Microsoft.Management/managementGroups/subscriptions/write","Move Subscription to Management Group"),
        ("resources","Resource Groups","Microsoft.Resources/subscriptions/resourceGroups/write","Create/Update Resource Group"),
        ("resources","Resource Groups","Microsoft.Resources/subscriptions/resourceGroups/delete","Delete Resource Group"),
        ("resources","Locks","Microsoft.Authorization/locks/write","Create/Update Resource Lock"),
        ("resources","Locks","Microsoft.Authorization/locks/delete","Delete Resource Lock"),
        ("resources","Policy Assignments","Microsoft.Authorization/policyAssignments/write","Create/Update Policy Assignment"),
        ("resources","Policy Assignments","Microsoft.Authorization/policyAssignments/delete","Delete Policy Assignment"),
        ("resources","Policy Exemptions","Microsoft.Authorization/policyExemptions/write","Create/Update Policy Exemption"),
        ("resources","Role Definitions","Microsoft.Authorization/roleDefinitions/write","Create/Update Custom Role Definition"),
        ("resources","Blueprints","Microsoft.Blueprint/blueprints/write","Create/Update Blueprint"),
        ("resources","Blueprints","Microsoft.Blueprint/blueprints/delete","Delete Blueprint"),

        # ── Service Fabric ────────────────────────────────────────────────────
        ("servicefabric","Service Fabric Clusters","Microsoft.ServiceFabric/clusters/write","Create/Update Service Fabric Cluster"),
        ("servicefabric","Service Fabric Clusters","Microsoft.ServiceFabric/clusters/delete","Delete Service Fabric Cluster"),
        ("servicefabric","SF Applications","Microsoft.ServiceFabric/clusters/applications/write","Create/Update Service Fabric Application"),

        # ── Managed Identity extra ops ────────────────────────────────────────
        ("managedidentity","User-Assigned MIs","Microsoft.ManagedIdentity/userAssignedIdentities/write","Create/Update User-Assigned Managed Identity"),
        ("managedidentity","User-Assigned MIs","Microsoft.ManagedIdentity/userAssignedIdentities/delete","Delete User-Assigned Managed Identity"),
        ("managedidentity","MI Federated Credentials","Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write","Create/Update MI Federated Identity Credential"),
        ("managedidentity","MI Federated Credentials","Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete","Delete MI Federated Identity Credential"),

        # ── Search ────────────────────────────────────────────────────────────
        ("search","Search Services","Microsoft.Search/searchServices/write","Create/Update Azure Search Service"),
        ("search","Search Services","Microsoft.Search/searchServices/delete","Delete Azure Search Service"),

        # ── Cache (Redis) extra ops ────────────────────────────────────────────
        ("cache","Redis Enterprise","Microsoft.Cache/redisEnterprise/write","Create/Update Redis Enterprise Cluster"),
        ("cache","Redis Enterprise","Microsoft.Cache/redisEnterprise/delete","Delete Redis Enterprise Cluster"),
        ("cache","Redis Firewall","Microsoft.Cache/redis/firewallRules/write","Create/Update Redis Firewall Rule"),
        ("cache","Redis Linked Servers","Microsoft.Cache/redis/linkedServers/write","Create/Update Redis Linked Server (Geo-Replication)"),

        # ── CDN extra ops ─────────────────────────────────────────────────────
        ("cdn","CDN Profiles","Microsoft.Cdn/profiles/write","Create/Update CDN Profile"),
        ("cdn","CDN Profiles","Microsoft.Cdn/profiles/delete","Delete CDN Profile"),
        ("cdn","CDN Endpoints","Microsoft.Cdn/profiles/endpoints/write","Create/Update CDN Endpoint"),
        ("cdn","CDN Endpoints","Microsoft.Cdn/profiles/endpoints/delete","Delete CDN Endpoint"),

        # ── Grafana / Dashboard ───────────────────────────────────────────────
        ("dashboard","Managed Grafana","Microsoft.Dashboard/grafana/write","Create/Update Managed Grafana"),
        ("dashboard","Managed Grafana","Microsoft.Dashboard/grafana/delete","Delete Managed Grafana"),

        # ── Media Services ────────────────────────────────────────────────────
        ("media","Media Services","Microsoft.Media/mediaservices/write","Create/Update Media Services Account"),
        ("media","Media Services","Microsoft.Media/mediaservices/delete","Delete Media Services Account"),
        ("media","Media Streaming","Microsoft.Media/mediaservices/streamingEndpoints/write","Create/Update Media Streaming Endpoint"),
    ]

    with open(path, "w") as f:
        f.write("-- Azure CRUD expansion rules\n")
        for svc, res, arm_op, action in rules:
            cat = infer_cat(arm_op + " " + action)
            rid = f"log.azure.{svc}.{svc}_{res.lower().replace(' ','_').replace('/','_').replace('-','_')[:30]}_{cat}"
            # Make unique by appending arm op hash tail
            import hashlib
            rid_suffix = hashlib.md5(arm_op.encode()).hexdigest()[:6]
            rid = f"log.azure.{svc}.{rid_suffix}"
            title = f"Azure {res}: {action}"
            desc = f"Detected {arm_op} on {res} via Azure Activity Log."
            emit(f, rid, svc, "azure", title, desc, cat, cfg_az(arm_op), arm_op)
            n += 1

    print(f"Azure CRUD expanded: {n} → {path}")
    return n


# ── GCP ───────────────────────────────────────────────────────────────────────

def generate_gcp(out_dir):
    path = os.path.join(out_dir, "ciem_gcp_crud_expanded.sql")
    n = 0
    import hashlib

    # (svc_uri, svc_short, resource, method, display)
    rules = [
        # Alloy DB
        ("alloydb.googleapis.com","alloydb","Alloy DB Clusters","CreateCluster","Create Alloy DB Cluster"),
        ("alloydb.googleapis.com","alloydb","Alloy DB Clusters","DeleteCluster","Delete Alloy DB Cluster"),
        ("alloydb.googleapis.com","alloydb","Alloy DB Instances","CreateInstance","Create Alloy DB Instance"),
        ("alloydb.googleapis.com","alloydb","Alloy DB Instances","DeleteInstance","Delete Alloy DB Instance"),
        ("alloydb.googleapis.com","alloydb","Alloy DB Backups","CreateBackup","Create Alloy DB Backup"),

        # Apigee
        ("apigee.googleapis.com","apigee","Apigee Organizations","CreateOrganization","Create Apigee Organization"),
        ("apigee.googleapis.com","apigee","Apigee Environments","CreateEnvironment","Create Apigee Environment"),
        ("apigee.googleapis.com","apigee","Apigee API Proxies","CreateApiProxy","Create Apigee API Proxy"),
        ("apigee.googleapis.com","apigee","Apigee Key Stores","CreateKeystore","Create Apigee Keystore"),
        ("apigee.googleapis.com","apigee","Apigee Key Stores","DeleteKeystore","Delete Apigee Keystore"),
        ("apigee.googleapis.com","apigee","Apigee Developer Apps","CreateDeveloperApp","Create Apigee Developer App"),

        # App Engine (extra ops)
        ("appengine.googleapis.com","appengine","App Engine Services","DeleteService","Delete App Engine Service"),
        ("appengine.googleapis.com","appengine","App Engine Versions","DeleteVersion","Delete App Engine Version"),
        ("appengine.googleapis.com","appengine","App Engine Instances","StartInstance","Start App Engine Instance"),
        ("appengine.googleapis.com","appengine","App Engine Firewall","BatchUpdateIngressRules","Update App Engine Firewall Rules"),

        # Bigtable
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable Instances","CreateInstance","Create Bigtable Instance"),
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable Instances","DeleteInstance","Delete Bigtable Instance"),
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable Tables","CreateTable","Create Bigtable Table"),
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable Tables","DeleteTable","Delete Bigtable Table"),
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable Backups","CreateBackup","Create Bigtable Backup"),
        ("bigtableadmin.googleapis.com","bigtableadmin","Bigtable App Profiles","CreateAppProfile","Create Bigtable App Profile"),

        # Cloud Composer
        ("composer.googleapis.com","composer","Composer Environments","CreateEnvironment","Create Cloud Composer Environment"),
        ("composer.googleapis.com","composer","Composer Environments","DeleteEnvironment","Delete Cloud Composer Environment"),
        ("composer.googleapis.com","composer","Composer Environments","UpdateEnvironment","Update Cloud Composer Environment"),

        # Cloud Dataflow
        ("dataflow.googleapis.com","dataflow","Dataflow Jobs","CreateJob","Create Dataflow Job"),
        ("dataflow.googleapis.com","dataflow","Dataflow Jobs","CancelJob","Cancel Dataflow Job"),
        ("dataflow.googleapis.com","dataflow","Dataflow Jobs","SnapshotJob","Snapshot Dataflow Job"),

        # Cloud Dataproc
        ("dataproc.googleapis.com","dataproc","Dataproc Clusters","CreateCluster","Create Dataproc Cluster"),
        ("dataproc.googleapis.com","dataproc","Dataproc Clusters","DeleteCluster","Delete Dataproc Cluster"),
        ("dataproc.googleapis.com","dataproc","Dataproc Clusters","UpdateCluster","Update Dataproc Cluster"),
        ("dataproc.googleapis.com","dataproc","Dataproc Jobs","SubmitJob","Submit Dataproc Job"),
        ("dataproc.googleapis.com","dataproc","Dataproc Jobs","CancelJob","Cancel Dataproc Job"),
        ("dataproc.googleapis.com","dataproc","Dataproc Workflows","InstantiateWorkflowTemplate","Run Dataproc Workflow Template"),

        # Cloud Filestore
        ("file.googleapis.com","filestore","Filestore Instances","CreateInstance","Create Filestore Instance"),
        ("file.googleapis.com","filestore","Filestore Instances","DeleteInstance","Delete Filestore Instance"),
        ("file.googleapis.com","filestore","Filestore Instances","UpdateInstance","Update Filestore Instance"),
        ("file.googleapis.com","filestore","Filestore Snapshots","CreateSnapshot","Create Filestore Snapshot"),
        ("file.googleapis.com","filestore","Filestore Backups","CreateBackup","Create Filestore Backup"),

        # Firestore
        ("firestore.googleapis.com","firestore","Firestore Databases","CreateDatabase","Create Firestore Database"),
        ("firestore.googleapis.com","firestore","Firestore Databases","DeleteDatabase","Delete Firestore Database"),
        ("firestore.googleapis.com","firestore","Firestore Indexes","CreateIndex","Create Firestore Index"),
        ("firestore.googleapis.com","firestore","Firestore Export","ExportDocuments","Export Firestore Documents"),
        ("firestore.googleapis.com","firestore","Firestore Import","ImportDocuments","Import Firestore Documents"),

        # Cloud IoT Core
        ("cloudiot.googleapis.com","cloudiot","IoT Registries","CreateDeviceRegistry","Create IoT Device Registry"),
        ("cloudiot.googleapis.com","cloudiot","IoT Registries","DeleteDeviceRegistry","Delete IoT Device Registry"),
        ("cloudiot.googleapis.com","cloudiot","IoT Devices","CreateDevice","Create IoT Device"),
        ("cloudiot.googleapis.com","cloudiot","IoT Devices","DeleteDevice","Delete IoT Device"),
        ("cloudiot.googleapis.com","cloudiot","IoT Configs","ModifyCloudToDeviceConfig","Modify IoT Device Config"),

        # Cloud Tasks
        ("cloudtasks.googleapis.com","cloudtasks","Task Queues","CreateQueue","Create Cloud Tasks Queue"),
        ("cloudtasks.googleapis.com","cloudtasks","Task Queues","DeleteQueue","Delete Cloud Tasks Queue"),
        ("cloudtasks.googleapis.com","cloudtasks","Task Queues","PauseQueue","Pause Cloud Tasks Queue"),
        ("cloudtasks.googleapis.com","cloudtasks","Task Queues","PurgeQueue","Purge Cloud Tasks Queue"),
        ("cloudtasks.googleapis.com","cloudtasks","Tasks","CreateTask","Create Cloud Task"),

        # Cloud Scheduler
        ("cloudscheduler.googleapis.com","cloudscheduler","Scheduler Jobs","CreateJob","Create Cloud Scheduler Job"),
        ("cloudscheduler.googleapis.com","cloudscheduler","Scheduler Jobs","DeleteJob","Delete Cloud Scheduler Job"),
        ("cloudscheduler.googleapis.com","cloudscheduler","Scheduler Jobs","UpdateJob","Update Cloud Scheduler Job"),
        ("cloudscheduler.googleapis.com","cloudscheduler","Scheduler Jobs","PauseJob","Pause Cloud Scheduler Job"),

        # Memorystore (Redis + Memcached)
        ("redis.googleapis.com","redis","Memorystore Redis","CreateInstance","Create Memorystore Redis Instance"),
        ("redis.googleapis.com","redis","Memorystore Redis","DeleteInstance","Delete Memorystore Redis Instance"),
        ("redis.googleapis.com","redis","Memorystore Redis","UpdateInstance","Update Memorystore Redis Instance"),
        ("redis.googleapis.com","redis","Memorystore Redis","FailoverInstance","Failover Memorystore Redis Instance"),
        ("memcache.googleapis.com","memcache","Memorystore Memcached","CreateInstance","Create Memorystore Memcached Instance"),
        ("memcache.googleapis.com","memcache","Memorystore Memcached","DeleteInstance","Delete Memorystore Memcached Instance"),

        # IAP (Identity-Aware Proxy)
        ("iap.googleapis.com","iap","IAP Tunnel","CreateTunnelDestGroup","Create IAP Tunnel Destination Group"),
        ("iap.googleapis.com","iap","IAP Tunnel","DeleteTunnelDestGroup","Delete IAP Tunnel Destination Group"),
        ("iap.googleapis.com","iap","IAP Settings","UpdateIapSettings","Update IAP Settings"),

        # Network Connectivity
        ("networkconnectivity.googleapis.com","networkconnectivity","Network Hubs","CreateHub","Create Network Connectivity Hub"),
        ("networkconnectivity.googleapis.com","networkconnectivity","Network Hubs","DeleteHub","Delete Network Connectivity Hub"),
        ("networkconnectivity.googleapis.com","networkconnectivity","Network Spokes","CreateSpoke","Create Network Connectivity Spoke"),
        ("networkconnectivity.googleapis.com","networkconnectivity","Network Spokes","DeleteSpoke","Delete Network Connectivity Spoke"),
        ("networkconnectivity.googleapis.com","networkconnectivity","Service Connection Policies","CreateServiceConnectionPolicy","Create Service Connection Policy"),

        # Private CA
        ("privateca.googleapis.com","privateca","CA Pool","CreateCaPool","Create Certificate Authority Pool"),
        ("privateca.googleapis.com","privateca","CA Pool","DeleteCaPool","Delete Certificate Authority Pool"),
        ("privateca.googleapis.com","privateca","Certificate Authority","CreateCertificateAuthority","Create Certificate Authority"),
        ("privateca.googleapis.com","privateca","Certificate Authority","DeleteCertificateAuthority","Delete Certificate Authority"),
        ("privateca.googleapis.com","privateca","Certificates","CreateCertificate","Issue Certificate from Private CA"),
        ("privateca.googleapis.com","privateca","Certificates","RevokeCertificate","Revoke Certificate from Private CA"),

        # Service Usage
        ("serviceusage.googleapis.com","serviceusage","APIs","EnableService","Enable GCP API/Service"),
        ("serviceusage.googleapis.com","serviceusage","APIs","DisableService","Disable GCP API/Service"),
        ("serviceusage.googleapis.com","serviceusage","APIs","BatchEnableServices","Batch Enable GCP APIs"),

        # Vertex AI / AI Platform
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Datasets","CreateDataset","Create Vertex AI Dataset"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Datasets","DeleteDataset","Delete Vertex AI Dataset"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Training","CreateTrainingPipeline","Create Vertex AI Training Pipeline"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Models","UploadModel","Upload Vertex AI Model"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Models","DeleteModel","Delete Vertex AI Model"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Endpoints","CreateEndpoint","Create Vertex AI Endpoint"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Endpoints","DeleteEndpoint","Delete Vertex AI Endpoint"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Endpoints","DeployModel","Deploy Model to Vertex AI Endpoint"),
        ("aiplatform.googleapis.com","aiplatform","Vertex AI Notebooks","CreateNotebookInstance","Create Vertex AI Notebook"),

        # Cloud Workstations
        ("workstations.googleapis.com","workstations","Workstation Clusters","CreateWorkstationCluster","Create Cloud Workstation Cluster"),
        ("workstations.googleapis.com","workstations","Workstation Clusters","DeleteWorkstationCluster","Delete Cloud Workstation Cluster"),
        ("workstations.googleapis.com","workstations","Workstation Configs","CreateWorkstationConfig","Create Workstation Configuration"),
        ("workstations.googleapis.com","workstations","Workstations","CreateWorkstation","Create Workstation"),
        ("workstations.googleapis.com","workstations","Workstations","DeleteWorkstation","Delete Workstation"),

        # Artifact Registry extra ops
        ("artifactregistry.googleapis.com","artifactregistry","AR Repos","CreateRepository","Create Artifact Registry Repository"),
        ("artifactregistry.googleapis.com","artifactregistry","AR Repos","DeleteRepository","Delete Artifact Registry Repository"),
        ("artifactregistry.googleapis.com","artifactregistry","AR Packages","DeletePackage","Delete Package from Artifact Registry"),
        ("artifactregistry.googleapis.com","artifactregistry","AR Tags","CreateTag","Create Artifact Registry Tag"),

        # GKE (extra ops)
        ("container.googleapis.com","container","GKE Clusters","CreateCluster","Create GKE Cluster"),
        ("container.googleapis.com","container","GKE Clusters","DeleteCluster","Delete GKE Cluster"),
        ("container.googleapis.com","container","GKE Clusters","UpdateCluster","Update GKE Cluster"),
        ("container.googleapis.com","container","GKE Node Pools","CreateNodePool","Create GKE Node Pool"),
        ("container.googleapis.com","container","GKE Node Pools","DeleteNodePool","Delete GKE Node Pool"),
        ("container.googleapis.com","container","GKE Node Pools","SetNodePoolSize","Scale GKE Node Pool"),
        ("container.googleapis.com","container","GKE RBAC","CreateRoleBinding","Create GKE RBAC Role Binding"),

        # Compute extra ops
        ("compute.googleapis.com","compute","Compute Instances","insert","Create Compute Instance"),
        ("compute.googleapis.com","compute","Compute Instances","delete","Delete Compute Instance"),
        ("compute.googleapis.com","compute","Compute Disks","insert","Create Compute Disk"),
        ("compute.googleapis.com","compute","Compute Disks","delete","Delete Compute Disk"),
        ("compute.googleapis.com","compute","Compute Firewall","insert","Create VPC Firewall Rule"),
        ("compute.googleapis.com","compute","Compute Firewall","delete","Delete VPC Firewall Rule"),
        ("compute.googleapis.com","compute","Compute Images","insert","Create Compute Image"),
        ("compute.googleapis.com","compute","Compute Images","delete","Delete Compute Image"),
        ("compute.googleapis.com","compute","Compute Networks","delete","Delete VPC Network"),
        ("compute.googleapis.com","compute","Compute Subnetworks","insert","Create VPC Subnetwork"),
        ("compute.googleapis.com","compute","Compute Subnetworks","delete","Delete VPC Subnetwork"),
        ("compute.googleapis.com","compute","Compute Target Proxies","insert","Create Load Balancer Target Proxy"),
        ("compute.googleapis.com","compute","Compute Backend Services","insert","Create Compute Backend Service"),
        ("compute.googleapis.com","compute","Compute Backend Services","delete","Delete Compute Backend Service"),
        ("compute.googleapis.com","compute","Compute URL Maps","insert","Create Compute URL Map"),
        ("compute.googleapis.com","compute","Compute SSL Certs","insert","Create Compute SSL Certificate"),
        ("compute.googleapis.com","compute","Compute Security Policies","insert","Create Cloud Armor Security Policy"),
        ("compute.googleapis.com","compute","Compute Security Policies","delete","Delete Cloud Armor Security Policy"),

        # Cloud SQL extra ops
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Instances","SqlInstancesInsert","Create Cloud SQL Instance"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Instances","SqlInstancesDelete","Delete Cloud SQL Instance"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Instances","SqlInstancesRestart","Restart Cloud SQL Instance"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Instances","SqlInstancesImport","Import Data to Cloud SQL"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Backups","SqlBackupRunsInsert","Create Cloud SQL Backup"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Backups","SqlBackupRunsDelete","Delete Cloud SQL Backup"),
        ("sqladmin.googleapis.com","sqladmin","Cloud SQL Replicas","SqlInstancesAddServerCa","Add Cloud SQL Server CA"),

        # Cloud Spanner extra ops
        ("spanner.googleapis.com","spanner","Spanner Instances","CreateInstance","Create Spanner Instance"),
        ("spanner.googleapis.com","spanner","Spanner Instances","DeleteInstance","Delete Spanner Instance"),
        ("spanner.googleapis.com","spanner","Spanner Databases","CreateDatabase","Create Spanner Database"),
        ("spanner.googleapis.com","spanner","Spanner Databases","DropDatabase","Drop Spanner Database"),
        ("spanner.googleapis.com","spanner","Spanner Backups","CreateBackup","Create Spanner Backup"),
        ("spanner.googleapis.com","spanner","Spanner Backups","DeleteBackup","Delete Spanner Backup"),

        # BigQuery extra ops
        ("bigquery.googleapis.com","bigquery","BigQuery Datasets","datasetservice.insert","Create BigQuery Dataset"),
        ("bigquery.googleapis.com","bigquery","BigQuery Datasets","datasetservice.delete","Delete BigQuery Dataset"),
        ("bigquery.googleapis.com","bigquery","BigQuery Tables","tableservice.insert","Create BigQuery Table"),
        ("bigquery.googleapis.com","bigquery","BigQuery Tables","tableservice.delete","Delete BigQuery Table"),
        ("bigquery.googleapis.com","bigquery","BigQuery Transfers","transfers.insert","Create BigQuery Data Transfer"),

        # Cloud KMS extra ops
        ("cloudkms.googleapis.com","cloudkms","KMS Key Rings","CreateKeyRing","Create KMS Key Ring"),
        ("cloudkms.googleapis.com","cloudkms","KMS Keys","CreateCryptoKey","Create KMS Crypto Key"),
        ("cloudkms.googleapis.com","cloudkms","KMS Keys","UpdateCryptoKey","Update KMS Crypto Key"),
        ("cloudkms.googleapis.com","cloudkms","KMS Key Versions","CreateCryptoKeyVersion","Create KMS Key Version"),
        ("cloudkms.googleapis.com","cloudkms","KMS Key Versions","DestroyCryptoKeyVersion","Destroy KMS Key Version"),

        # Cloud Storage extra ops
        ("storage.googleapis.com","storage","GCS Buckets","storage.buckets.create","Create GCS Bucket"),
        ("storage.googleapis.com","storage","GCS Buckets","storage.buckets.delete","Delete GCS Bucket"),
        ("storage.googleapis.com","storage","GCS Buckets","storage.buckets.update","Update GCS Bucket Configuration"),
        ("storage.googleapis.com","storage","GCS Objects","storage.objects.delete","Delete GCS Object"),

        # Pub/Sub extra ops
        ("pubsub.googleapis.com","pubsub","Pub/Sub Topics","google.pubsub.v1.Publisher.CreateTopic","Create Pub/Sub Topic"),
        ("pubsub.googleapis.com","pubsub","Pub/Sub Topics","google.pubsub.v1.Publisher.DeleteTopic","Delete Pub/Sub Topic"),
        ("pubsub.googleapis.com","pubsub","Pub/Sub Subscriptions","google.pubsub.v1.Subscriber.CreateSubscription","Create Pub/Sub Subscription"),
        ("pubsub.googleapis.com","pubsub","Pub/Sub Subscriptions","google.pubsub.v1.Subscriber.DeleteSubscription","Delete Pub/Sub Subscription"),

        # Secret Manager extra ops
        ("secretmanager.googleapis.com","secretmanager","Secrets","CreateSecret","Create Secret"),
        ("secretmanager.googleapis.com","secretmanager","Secrets","DeleteSecret","Delete Secret"),
        ("secretmanager.googleapis.com","secretmanager","Secret Versions","AddSecretVersion","Add Secret Version"),
        ("secretmanager.googleapis.com","secretmanager","Secret Versions","DestroySecretVersion","Destroy Secret Version"),
        ("secretmanager.googleapis.com","secretmanager","Secret Versions","DisableSecretVersion","Disable Secret Version"),

        # Cloud Functions extra ops
        ("cloudfunctions.googleapis.com","cloudfunctions","Cloud Functions","google.cloud.functions.v1.CloudFunctionsService.DeleteFunction","Delete Cloud Function"),
        ("cloudfunctions.googleapis.com","cloudfunctions","Cloud Functions","google.cloud.functions.v1.CloudFunctionsService.UpdateFunction","Update Cloud Function"),
        ("cloudfunctions.googleapis.com","cloudfunctions","Cloud Functions","google.cloud.functions.v2.FunctionService.CreateFunction","Create Cloud Function v2"),

        # Cloud Run extra ops
        ("run.googleapis.com","run","Cloud Run Services","google.cloud.run.v1.Services.DeleteService","Delete Cloud Run Service"),
        ("run.googleapis.com","run","Cloud Run Services","google.cloud.run.v1.Services.ReplaceService","Update Cloud Run Service"),
        ("run.googleapis.com","run","Cloud Run Jobs","google.cloud.run.v1.Jobs.CreateJob","Create Cloud Run Job"),
        ("run.googleapis.com","run","Cloud Run Jobs","google.cloud.run.v1.Jobs.DeleteJob","Delete Cloud Run Job"),

        # Cloud Logging extra ops
        ("logging.googleapis.com","logging","Log Sinks","CreateSink","Create Log Sink"),
        ("logging.googleapis.com","logging","Log Sinks","UpdateSink","Update Log Sink"),
        ("logging.googleapis.com","logging","Log Buckets","CreateBucket","Create Log Bucket"),
        ("logging.googleapis.com","logging","Log Buckets","DeleteBucket","Delete Log Bucket"),
        ("logging.googleapis.com","logging","Log Views","CreateView","Create Log View"),

        # Cloud Monitoring extra ops
        ("monitoring.googleapis.com","monitoring","Monitoring Alert Policies","CreateAlertPolicy","Create Monitoring Alert Policy"),
        ("monitoring.googleapis.com","monitoring","Monitoring Alert Policies","UpdateAlertPolicy","Update Monitoring Alert Policy"),
        ("monitoring.googleapis.com","monitoring","Notification Channels","CreateNotificationChannel","Create Monitoring Notification Channel"),
        ("monitoring.googleapis.com","monitoring","Uptime Checks","CreateUptimeCheckConfig","Create Uptime Check"),
        ("monitoring.googleapis.com","monitoring","Service Monitoring","CreateService","Create Monitored Service"),

        # Cloud Build extra ops
        ("cloudbuild.googleapis.com","cloudbuild","Build Triggers","google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger","Update Cloud Build Trigger"),
        ("cloudbuild.googleapis.com","cloudbuild","Build Triggers","google.devtools.cloudbuild.v1.CloudBuild.DeleteBuildTrigger","Delete Cloud Build Trigger"),
        ("cloudbuild.googleapis.com","cloudbuild","Worker Pools","google.devtools.cloudbuild.v1.CloudBuild.CreateWorkerPool","Create Cloud Build Worker Pool"),

        # IAM extra ops
        ("iam.googleapis.com","iam","Service Account Keys","CreateServiceAccountKey","Create Service Account Key"),
        ("iam.googleapis.com","iam","Service Account Keys","DeleteServiceAccountKey","Delete Service Account Key"),
        ("iam.googleapis.com","iam","Service Accounts","CreateServiceAccount","Create Service Account"),
        ("iam.googleapis.com","iam","Service Accounts","DeleteServiceAccount","Delete Service Account"),
        ("iam.googleapis.com","iam","Workload Identity Pools","CreateWorkloadIdentityPool","Create Workload Identity Pool"),
        ("iam.googleapis.com","iam","Workload Identity Pools","DeleteWorkloadIdentityPool","Delete Workload Identity Pool"),
        ("iam.googleapis.com","iam","WI Pool Providers","CreateWorkloadIdentityPoolProvider","Create Workload Identity Provider"),

        # Cloud DNS extra ops
        ("dns.googleapis.com","dns","DNS Zones","dns.managedZones.create","Create DNS Managed Zone"),
        ("dns.googleapis.com","dns","DNS Record Sets","dns.resourceRecordSets.create","Create DNS Record Set"),
        ("dns.googleapis.com","dns","DNS Record Sets","dns.resourceRecordSets.delete","Delete DNS Record Set"),
        ("dns.googleapis.com","dns","DNS Policies","dns.policies.create","Create DNS Policy"),
        ("dns.googleapis.com","dns","DNS Policies","dns.policies.delete","Delete DNS Policy"),

        # Data Catalog
        ("datacatalog.googleapis.com","datacatalog","Data Catalog Entries","CreateEntry","Create Data Catalog Entry"),
        ("datacatalog.googleapis.com","datacatalog","Data Catalog Tags","CreateTag","Create Data Catalog Tag"),
        ("datacatalog.googleapis.com","datacatalog","Data Catalog Tag Templates","CreateTagTemplate","Create Data Catalog Tag Template"),
        ("datacatalog.googleapis.com","datacatalog","Data Catalog Taxonomies","CreateTaxonomy","Create Data Catalog Taxonomy"),
    ]

    with open(path, "w") as f:
        f.write("-- GCP CRUD expansion rules\n")
        for entry in rules:
            svc_uri, svc_short, res, method, display = entry
            cat = infer_cat(method + " " + display)
            rid_suffix = hashlib.md5((svc_uri + method).encode()).hexdigest()[:8]
            rid = f"log.gcp.{svc_short}.{rid_suffix}"
            title = f"GCP {res}: {display}"
            desc = f"Detected {method} on {res} via GCP Audit Logs."
            emit(f, rid, svc_uri, "gcp", title, desc, cat, cfg_gcp(svc_uri, method), method)
            n += 1

    print(f"GCP CRUD expanded: {n} → {path}")
    return n


# ── OCI ───────────────────────────────────────────────────────────────────────

def generate_oci(out_dir):
    path = os.path.join(out_dir, "ciem_oci_crud_expanded.sql")
    n = 0
    import hashlib

    # (cadf_domain, svc_short, resource, operation, display)
    rules = [
        # Analytics Cloud
        ("com.oraclecloud.analyticsservice","analytics","Analytics Instances","CreateAnalyticsInstance","Create Analytics Cloud Instance"),
        ("com.oraclecloud.analyticsservice","analytics","Analytics Instances","DeleteAnalyticsInstance","Delete Analytics Cloud Instance"),
        ("com.oraclecloud.analyticsservice","analytics","Analytics Instances","StartAnalyticsInstance","Start Analytics Cloud Instance"),
        ("com.oraclecloud.analyticsservice","analytics","Analytics Instances","StopAnalyticsInstance","Stop Analytics Cloud Instance"),

        # Big Data Service
        ("com.oraclecloud.bigdataservice","bigdata","Big Data Clusters","CreateBdsInstance","Create Big Data Cluster"),
        ("com.oraclecloud.bigdataservice","bigdata","Big Data Clusters","DeleteBdsInstance","Delete Big Data Cluster"),
        ("com.oraclecloud.bigdataservice","bigdata","Big Data Clusters","AddAutoScalingConfiguration","Add Big Data Auto-Scaling Config"),
        ("com.oraclecloud.bigdataservice","bigdata","Big Data Nodes","AddWorkerNodes","Add Big Data Worker Nodes"),

        # Certificates Service
        ("com.oraclecloud.certificatesmanagement","certificates","Certificate Authorities","CreateCertificateAuthority","Create Certificate Authority"),
        ("com.oraclecloud.certificatesmanagement","certificates","Certificate Authorities","DeleteCertificateAuthority","Delete Certificate Authority"),
        ("com.oraclecloud.certificatesmanagement","certificates","Certificates","CreateCertificate","Create Certificate"),
        ("com.oraclecloud.certificatesmanagement","certificates","Certificates","UpdateCertificate","Update Certificate"),
        ("com.oraclecloud.certificatesmanagement","certificates","CA Bundles","CreateCaBundle","Create CA Bundle"),

        # Cloud Guard
        ("com.oraclecloud.cloudguard","cloudguard","Cloud Guard Targets","CreateTarget","Create Cloud Guard Target"),
        ("com.oraclecloud.cloudguard","cloudguard","Cloud Guard Targets","DeleteTarget","Delete Cloud Guard Target"),
        ("com.oraclecloud.cloudguard","cloudguard","Cloud Guard Recipes","CreateDetectorRecipe","Create Cloud Guard Detector Recipe"),
        ("com.oraclecloud.cloudguard","cloudguard","Cloud Guard Recipes","DeleteDetectorRecipe","Delete Cloud Guard Detector Recipe"),
        ("com.oraclecloud.cloudguard","cloudguard","Cloud Guard Responder Recipes","CreateResponderRecipe","Create Cloud Guard Responder Recipe"),

        # Data Integration
        ("com.oraclecloud.dataintegration","dataintegration","DI Workspaces","CreateWorkspace","Create Data Integration Workspace"),
        ("com.oraclecloud.dataintegration","dataintegration","DI Workspaces","DeleteWorkspace","Delete Data Integration Workspace"),
        ("com.oraclecloud.dataintegration","dataintegration","DI Tasks","CreateTask","Create Data Integration Task"),

        # Data Science
        ("com.oraclecloud.datascience","datascience","Data Science Projects","CreateProject","Create Data Science Project"),
        ("com.oraclecloud.datascience","datascience","Data Science Projects","DeleteProject","Delete Data Science Project"),
        ("com.oraclecloud.datascience","datascience","Data Science Notebooks","CreateNotebookSession","Create Data Science Notebook Session"),
        ("com.oraclecloud.datascience","datascience","Data Science Notebooks","DeleteNotebookSession","Delete Data Science Notebook Session"),
        ("com.oraclecloud.datascience","datascience","Data Science Models","CreateModel","Create Data Science Model"),
        ("com.oraclecloud.datascience","datascience","Data Science Model Deployments","CreateModelDeployment","Create Model Deployment"),

        # Data Safe
        ("com.oraclecloud.datasafe","datasafe","Data Safe Targets","CreateTargetDatabase","Register Data Safe Target Database"),
        ("com.oraclecloud.datasafe","datasafe","Data Safe Targets","DeleteTargetDatabase","Delete Data Safe Target Database"),
        ("com.oraclecloud.datasafe","datasafe","Data Safe Security Assessment","CreateSecurityAssessment","Create Data Safe Security Assessment"),
        ("com.oraclecloud.datasafe","datasafe","Data Safe User Assessment","CreateUserAssessment","Create Data Safe User Assessment"),
        ("com.oraclecloud.datasafe","datasafe","Data Safe Masking Policies","CreateMaskingPolicy","Create Data Safe Masking Policy"),
        ("com.oraclecloud.datasafe","datasafe","Data Safe Audit Trails","StartAuditTrail","Start Data Safe Audit Trail"),

        # Email Delivery
        ("com.oraclecloud.emaildelivery","email","Email Senders","CreateSender","Create Approved Email Sender"),
        ("com.oraclecloud.emaildelivery","email","Email Senders","DeleteSender","Delete Approved Email Sender"),
        ("com.oraclecloud.emaildelivery","email","Email Suppressions","CreateSuppression","Create Email Suppression"),

        # File Storage
        ("com.oraclecloud.filestorage","filestorage","File Systems","CreateFileSystem","Create File Storage System"),
        ("com.oraclecloud.filestorage","filestorage","File Systems","DeleteFileSystem","Delete File Storage System"),
        ("com.oraclecloud.filestorage","filestorage","Mount Targets","CreateMountTarget","Create NFS Mount Target"),
        ("com.oraclecloud.filestorage","filestorage","Mount Targets","DeleteMountTarget","Delete NFS Mount Target"),
        ("com.oraclecloud.filestorage","filestorage","Exports","CreateExport","Create File Storage Export"),
        ("com.oraclecloud.filestorage","filestorage","Snapshots","CreateSnapshot","Create File Storage Snapshot"),
        ("com.oraclecloud.filestorage","filestorage","Snapshots","DeleteSnapshot","Delete File Storage Snapshot"),

        # GoldenGate
        ("com.oraclecloud.goldengate","goldengate","GoldenGate Deployments","CreateDeployment","Create GoldenGate Deployment"),
        ("com.oraclecloud.goldengate","goldengate","GoldenGate Deployments","DeleteDeployment","Delete GoldenGate Deployment"),
        ("com.oraclecloud.goldengate","goldengate","GoldenGate Connections","CreateConnection","Create GoldenGate Connection"),
        ("com.oraclecloud.goldengate","goldengate","GoldenGate Connections","DeleteConnection","Delete GoldenGate Connection"),

        # Integration Cloud
        ("com.oraclecloud.integration","integration","Integration Instances","CreateIntegrationInstance","Create Integration Cloud Instance"),
        ("com.oraclecloud.integration","integration","Integration Instances","DeleteIntegrationInstance","Delete Integration Cloud Instance"),
        ("com.oraclecloud.integration","integration","Integration Instances","StartIntegrationInstance","Start Integration Cloud Instance"),

        # MySQL HeatWave
        ("com.oraclecloud.mysqlaas","mysql","MySQL DB Systems","CreateDbSystem","Create MySQL HeatWave DB System"),
        ("com.oraclecloud.mysqlaas","mysql","MySQL DB Systems","DeleteDbSystem","Delete MySQL HeatWave DB System"),
        ("com.oraclecloud.mysqlaas","mysql","MySQL DB Systems","UpdateDbSystem","Update MySQL HeatWave DB System"),
        ("com.oraclecloud.mysqlaas","mysql","MySQL Backups","CreateBackup","Create MySQL HeatWave Backup"),
        ("com.oraclecloud.mysqlaas","mysql","MySQL Backups","DeleteBackup","Delete MySQL HeatWave Backup"),

        # NoSQL Database
        ("com.oraclecloud.nosql","nosql","NoSQL Tables","CreateTable","Create NoSQL Database Table"),
        ("com.oraclecloud.nosql","nosql","NoSQL Tables","DeleteTable","Delete NoSQL Database Table"),
        ("com.oraclecloud.nosql","nosql","NoSQL Tables","UpdateTable","Update NoSQL Database Table"),
        ("com.oraclecloud.nosql","nosql","NoSQL Indexes","CreateIndex","Create NoSQL Database Index"),
        ("com.oraclecloud.nosql","nosql","NoSQL Indexes","DeleteIndex","Delete NoSQL Database Index"),

        # ODA (Oracle Digital Assistant)
        ("com.oraclecloud.oda","oda","ODA Instances","CreateOdaInstance","Create Digital Assistant Instance"),
        ("com.oraclecloud.oda","oda","ODA Instances","DeleteOdaInstance","Delete Digital Assistant Instance"),
        ("com.oraclecloud.oda","oda","ODA Instances","StartOdaInstance","Start Digital Assistant Instance"),

        # OpenSearch
        ("com.oraclecloud.opensearch","opensearch","OpenSearch Clusters","CreateOpensearchCluster","Create OpenSearch Cluster"),
        ("com.oraclecloud.opensearch","opensearch","OpenSearch Clusters","DeleteOpensearchCluster","Delete OpenSearch Cluster"),
        ("com.oraclecloud.opensearch","opensearch","OpenSearch Clusters","UpdateOpensearchCluster","Update OpenSearch Cluster"),

        # OS Management
        ("com.oraclecloud.osmanagement","osmanagement","OS Management Groups","CreateManagedInstanceGroup","Create OS Managed Instance Group"),
        ("com.oraclecloud.osmanagement","osmanagement","OS Management Groups","DeleteManagedInstanceGroup","Delete OS Managed Instance Group"),
        ("com.oraclecloud.osmanagement","osmanagement","Scheduled Jobs","CreateScheduledJob","Create OS Management Scheduled Job"),
        ("com.oraclecloud.osmanagement","osmanagement","Scheduled Jobs","DeleteScheduledJob","Delete OS Management Scheduled Job"),

        # Queue Service
        ("com.oraclecloud.queue","queue","Queues","CreateQueue","Create OCI Queue"),
        ("com.oraclecloud.queue","queue","Queues","DeleteQueue","Delete OCI Queue"),
        ("com.oraclecloud.queue","queue","Queues","UpdateQueue","Update OCI Queue"),
        ("com.oraclecloud.queue","queue","Queue Messages","DeleteMessages","Delete Queue Messages"),
        ("com.oraclecloud.queue","queue","Queue Messages","PurgeQueue","Purge Queue Messages"),

        # Visual Builder
        ("com.oraclecloud.visualbuilder","visualbuilder","VB Instances","CreateVbInstance","Create Visual Builder Instance"),
        ("com.oraclecloud.visualbuilder","visualbuilder","VB Instances","DeleteVbInstance","Delete Visual Builder Instance"),
        ("com.oraclecloud.visualbuilder","visualbuilder","VB Instances","StartVbInstance","Start Visual Builder Instance"),

        # Networking extra ops
        ("com.oraclecloud.virtualnetwork","network","VCN","CreateVcn","Create VCN"),
        ("com.oraclecloud.virtualnetwork","network","VCN","DeleteVcn","Delete VCN"),
        ("com.oraclecloud.virtualnetwork","network","Subnets","CreateSubnet","Create Subnet"),
        ("com.oraclecloud.virtualnetwork","network","Subnets","DeleteSubnet","Delete Subnet"),
        ("com.oraclecloud.virtualnetwork","network","Internet Gateways","CreateInternetGateway","Create Internet Gateway"),
        ("com.oraclecloud.virtualnetwork","network","Internet Gateways","DeleteInternetGateway","Delete Internet Gateway"),
        ("com.oraclecloud.virtualnetwork","network","NAT Gateways","CreateNatGateway","Create NAT Gateway"),
        ("com.oraclecloud.virtualnetwork","network","NAT Gateways","DeleteNatGateway","Delete NAT Gateway"),
        ("com.oraclecloud.virtualnetwork","network","Service Gateways","CreateServiceGateway","Create Service Gateway"),
        ("com.oraclecloud.virtualnetwork","network","Local Peering Gateways","CreateLocalPeeringGateway","Create Local Peering Gateway"),
        ("com.oraclecloud.virtualnetwork","network","Remote Peering","CreateRemotePeeringConnection","Create Remote Peering Connection"),
        ("com.oraclecloud.virtualnetwork","network","Network Security Groups","CreateNetworkSecurityGroup","Create Network Security Group"),
        ("com.oraclecloud.virtualnetwork","network","NSG Rules","UpdateNetworkSecurityGroupSecurityRules","Update NSG Security Rules"),
        ("com.oraclecloud.virtualnetwork","network","Security Lists","CreateSecurityList","Create Security List"),
        ("com.oraclecloud.virtualnetwork","network","Security Lists","DeleteSecurityList","Delete Security List"),
        ("com.oraclecloud.virtualnetwork","network","Route Tables","CreateRouteTable","Create Route Table"),
        ("com.oraclecloud.virtualnetwork","network","Route Tables","DeleteRouteTable","Delete Route Table"),
        ("com.oraclecloud.virtualnetwork","network","DHCP Options","CreateDhcpOptions","Create DHCP Options"),
        ("com.oraclecloud.virtualnetwork","network","Private IPs","CreatePrivateIp","Create Private IP"),
        ("com.oraclecloud.virtualnetwork","network","Public IP Pools","CreatePublicIpPool","Create Public IP Pool"),

        # Block Storage extra ops
        ("com.oraclecloud.blockstorage","blockstorage","Block Volumes","CreateVolume","Create Block Volume"),
        ("com.oraclecloud.blockstorage","blockstorage","Block Volumes","DeleteVolume","Delete Block Volume"),
        ("com.oraclecloud.blockstorage","blockstorage","Block Volume Backups","CreateVolumeBackup","Create Block Volume Backup"),
        ("com.oraclecloud.blockstorage","blockstorage","Block Volume Backups","DeleteVolumeBackup","Delete Block Volume Backup"),
        ("com.oraclecloud.blockstorage","blockstorage","Volume Groups","CreateVolumeGroup","Create Volume Group"),

        # OCI Identity extra ops
        ("com.oraclecloud.identitycontrolplane","identity","Compartments","CreateCompartment","Create Compartment"),
        ("com.oraclecloud.identitycontrolplane","identity","Users","DeleteUser","Delete IAM User"),
        ("com.oraclecloud.identitycontrolplane","identity","Groups","CreateGroup","Create IAM Group"),
        ("com.oraclecloud.identitycontrolplane","identity","Groups","DeleteGroup","Delete IAM Group"),
        ("com.oraclecloud.identitycontrolplane","identity","Policies","CreatePolicy","Create IAM Policy"),
        ("com.oraclecloud.identitycontrolplane","identity","Policies","DeletePolicy","Delete IAM Policy"),
        ("com.oraclecloud.identitycontrolplane","identity","Customer Secret Keys","CreateCustomerSecretKey","Create OCI Customer Secret Key"),
        ("com.oraclecloud.identitycontrolplane","identity","Customer Secret Keys","DeleteCustomerSecretKey","Delete OCI Customer Secret Key"),

        # OKE extra ops
        ("com.oraclecloud.containerengine","oke","OKE Clusters","CreateCluster","Create OKE Kubernetes Cluster"),
        ("com.oraclecloud.containerengine","oke","OKE Clusters","DeleteCluster","Delete OKE Kubernetes Cluster"),
        ("com.oraclecloud.containerengine","oke","OKE Node Pools","CreateNodePool","Create OKE Node Pool"),
        ("com.oraclecloud.containerengine","oke","OKE Node Pools","DeleteNodePool","Delete OKE Node Pool"),
        ("com.oraclecloud.containerengine","oke","OKE Node Pools","UpdateNodePool","Update OKE Node Pool"),
        ("com.oraclecloud.containerengine","oke","OKE Virtual Node Pools","CreateVirtualNodePool","Create OKE Virtual Node Pool"),

        # Database extra ops
        ("com.oraclecloud.database","database","DB Systems","LaunchDbSystem","Launch Oracle DB System"),
        ("com.oraclecloud.database","database","DB Systems","TerminateDbSystem","Terminate Oracle DB System"),
        ("com.oraclecloud.database","database","Autonomous DBs","CreateAutonomousDatabase","Create Autonomous Database"),
        ("com.oraclecloud.database","database","Autonomous DBs","DeleteAutonomousDatabase","Delete Autonomous Database"),
        ("com.oraclecloud.database","database","Autonomous DBs","StopAutonomousDatabase","Stop Autonomous Database"),
        ("com.oraclecloud.database","database","DB Backups","CreateBackup","Create Oracle DB Backup"),
        ("com.oraclecloud.database","database","External DB Connectors","CreateExternalDatabaseConnector","Create External DB Connector"),

        # Compute extra ops
        ("com.oraclecloud.computeapi","compute","Instances","LaunchInstance","Launch Compute Instance"),
        ("com.oraclecloud.computeapi","compute","Instances","TerminateInstance","Terminate Compute Instance"),
        ("com.oraclecloud.computeapi","compute","Instance Configs","CreateInstanceConfiguration","Create Instance Configuration"),
        ("com.oraclecloud.computeapi","compute","Instance Pools","CreateInstancePool","Create Instance Pool"),
        ("com.oraclecloud.computeapi","compute","Instance Pools","DeleteInstancePool","Delete Instance Pool"),
        ("com.oraclecloud.computeapi","compute","Custom Images","CreateImage","Create Custom Compute Image"),
        ("com.oraclecloud.computeapi","compute","Custom Images","DeleteImage","Delete Custom Compute Image"),
    ]

    with open(path, "w") as f:
        f.write("-- OCI CRUD expansion rules\n")
        for entry in rules:
            cadf, svc_short, res, op, display = entry
            cat = infer_cat(op + " " + display)
            rid_suffix = hashlib.md5((cadf + op).encode()).hexdigest()[:8]
            rid = f"log.oci.{svc_short}.{rid_suffix}"
            title = f"OCI {res}: {display}"
            desc = f"Detected {op} on {res} via OCI Audit Logs."
            emit(f, rid, cadf, "oci", title, desc, cat, cfg_oci(cadf, op), op)
            n += 1

    print(f"OCI CRUD expanded: {n} → {path}")
    return n


# ── IBM ───────────────────────────────────────────────────────────────────────

def generate_ibm(out_dir):
    path = os.path.join(out_dir, "ciem_ibm_crud_expanded.sql")
    n = 0
    import hashlib

    # (ibm_svc, cadf_action_contains, display, resource)
    # ibm_svc = first segment (underscored), cadf_action_contains = verb portion for contains match
    rules = [
        # Account / User Management
        ("user_management","user.invite","Invite User to Account","Account Users"),
        ("user_management","user.remove","Remove User from Account","Account Users"),
        ("user_management","user.update","Update User Settings","Account Users"),
        ("iam_identity","account.update","Update Account Settings","Account Settings"),

        # Access Groups
        ("iam_groups","access-group.create","Create Access Group","Access Groups"),
        ("iam_groups","access-group.delete","Delete Access Group","Access Groups"),
        ("iam_groups","access-group.update","Update Access Group","Access Groups"),
        ("iam_groups","access-group-members.add","Add Member to Access Group","Access Group Members"),
        ("iam_groups","access-group-members.remove","Remove Member from Access Group","Access Group Members"),
        ("iam_groups","access-group-policy.create","Create Access Group Policy","Access Group Policies"),
        ("iam_groups","access-group-policy.delete","Delete Access Group Policy","Access Group Policies"),

        # IAM Policies / Roles
        ("iam","policy.create","Create IAM Policy","IAM Policies"),
        ("iam","policy.update","Update IAM Policy","IAM Policies"),
        ("iam","policy.delete","Delete IAM Policy","IAM Policies"),
        ("iam","authorization.update","Update Service Authorization","Service Authorizations"),
        ("iam","authorization.delete","Delete Service Authorization","Service Authorizations"),

        # IAM Identity
        ("iam_identity","apikey.create","Create API Key","API Keys"),
        ("iam_identity","apikey.delete","Delete API Key","API Keys"),
        ("iam_identity","apikey.update","Update API Key","API Keys"),
        ("iam_identity","serviceid.create","Create Service ID","Service IDs"),
        ("iam_identity","serviceid.delete","Delete Service ID","Service IDs"),
        ("iam_identity","serviceid.update","Update Service ID","Service IDs"),
        ("iam_identity","profile.create","Create Trusted Profile","Trusted Profiles"),
        ("iam_identity","profile.delete","Delete Trusted Profile","Trusted Profiles"),
        ("iam_identity","profile.update","Update Trusted Profile","Trusted Profiles"),

        # CBR (Context-Based Restrictions)
        ("context_based_restrictions","rule.create","Create CBR Rule","CBR Rules"),
        ("context_based_restrictions","rule.update","Update CBR Rule","CBR Rules"),
        ("context_based_restrictions","zone.create","Create CBR Zone","CBR Zones"),
        ("context_based_restrictions","zone.update","Update CBR Zone","CBR Zones"),

        # Resource Controller
        ("resource_controller","instance.create","Create Service Instance","Service Instances"),
        ("resource_controller","instance.update","Update Service Instance","Service Instances"),
        ("resource_controller","instance.delete","Delete Service Instance","Service Instances"),
        ("resource_controller","binding.create","Create Service Binding","Service Bindings"),
        ("resource_controller","binding.delete","Delete Service Binding","Service Bindings"),
        ("resource_controller","key.create","Create Service Credential","Service Credentials"),
        ("resource_controller","key.delete","Delete Service Credential","Service Credentials"),
        ("resource_controller","key.update","Update Service Credential","Service Credentials"),

        # COS (Object Storage)
        ("cloud_object_storage","bucket.create","Create COS Bucket","COS Buckets"),
        ("cloud_object_storage","bucket.delete","Delete COS Bucket","COS Buckets"),
        ("cloud_object_storage","bucket.update","Update COS Bucket","COS Buckets"),
        ("cloud_object_storage","object.delete","Delete Object from COS Bucket","COS Objects"),
        ("cloud_object_storage","bucket-cors.set","Set COS Bucket CORS Policy","COS Bucket CORS"),
        ("cloud_object_storage","bucket-versioning.set","Set COS Bucket Versioning","COS Bucket Versioning"),
        ("cloud_object_storage","bucket-retention.set","Set COS Bucket Retention Policy","COS Bucket Retention"),

        # Key Protect (KMS)
        ("kms","secrets.create","Create Encryption Key","Key Protect Keys"),
        ("kms","secrets.delete","Delete Encryption Key","Key Protect Keys"),
        ("kms","secrets.update","Update Key Metadata","Key Protect Keys"),
        ("kms","secrets.enable","Enable Encryption Key","Key Protect Keys"),
        ("kms","secrets.purge","Purge Encryption Key","Key Protect Keys"),
        ("kms","keyrings.create","Create Key Ring","Key Protect Key Rings"),
        ("kms","keyrings.delete","Delete Key Ring","Key Protect Key Rings"),
        ("kms","registrations.create","Create Key Registration","Key Protect Registrations"),
        ("kms","registrations.delete","Delete Key Registration","Key Protect Registrations"),

        # Hyper Protect Crypto Services
        ("hs_crypto","keys.create","Create Key in HPCS","Hyper Protect Keys"),
        ("hs_crypto","keys.delete","Delete Key in HPCS","Hyper Protect Keys"),
        ("hs_crypto","keys.update","Update Key in HPCS","Hyper Protect Keys"),
        ("hs_crypto","instances.initialize","Initialize HPCS Instance","HPCS Instances"),

        # Secrets Manager
        ("secrets_manager","secret.create","Create Secret","Secrets Manager Secrets"),
        ("secrets_manager","secret.update","Update Secret Metadata","Secrets Manager Secrets"),
        ("secrets_manager","secret.delete","Delete Secret","Secrets Manager Secrets"),
        ("secrets_manager","secret-group.create","Create Secret Group","Secrets Manager Groups"),
        ("secrets_manager","secret-group.delete","Delete Secret Group","Secrets Manager Groups"),
        ("secrets_manager","configuration.create","Create Secrets Config","Secrets Manager Config"),
        ("secrets_manager","configuration.delete","Delete Secrets Config","Secrets Manager Config"),

        # VPC (IS)
        ("is","instance.create","Create VPC Instance","VPC Instances"),
        ("is","instance.update","Update VPC Instance","VPC Instances"),
        ("is","instance.delete","Delete VPC Instance","VPC Instances"),
        ("is","subnet.create","Create VPC Subnet","VPC Subnets"),
        ("is","subnet.update","Update VPC Subnet","VPC Subnets"),
        ("is","subnet.delete","Delete VPC Subnet","VPC Subnets"),
        ("is","vpc.create","Create VPC","VPCs"),
        ("is","vpc.update","Update VPC","VPCs"),
        ("is","vpc.delete","Delete VPC","VPCs"),
        ("is","security-group.create","Create Security Group","VPC Security Groups"),
        ("is","security-group.update","Update Security Group","VPC Security Groups"),
        ("is","security-group.delete","Delete Security Group","VPC Security Groups"),
        ("is","network-acl.create","Create Network ACL","VPC Network ACLs"),
        ("is","network-acl.update","Update Network ACL","VPC Network ACLs"),
        ("is","network-acl.delete","Delete Network ACL","VPC Network ACLs"),
        ("is","public-gateway.create","Create Public Gateway","VPC Public Gateways"),
        ("is","public-gateway.delete","Delete Public Gateway","VPC Public Gateways"),
        ("is","volume.create","Create VPC Block Volume","VPC Block Volumes"),
        ("is","volume.update","Update VPC Block Volume","VPC Block Volumes"),
        ("is","volume.delete","Delete VPC Block Volume","VPC Block Volumes"),
        ("is","load-balancer.create","Create VPC Load Balancer","VPC Load Balancers"),
        ("is","load-balancer.update","Update VPC Load Balancer","VPC Load Balancers"),
        ("is","load-balancer.delete","Delete VPC Load Balancer","VPC Load Balancers"),
        ("is","vpn-gateway.create","Create VPN Gateway","VPC VPN Gateways"),
        ("is","vpn-gateway.delete","Delete VPN Gateway","VPC VPN Gateways"),
        ("is","dedicated-host.create","Create Dedicated Host","VPC Dedicated Hosts"),
        ("is","dedicated-host.delete","Delete Dedicated Host","VPC Dedicated Hosts"),
        ("is","image.create","Create Custom Image","VPC Custom Images"),
        ("is","image.delete","Delete Custom Image","VPC Custom Images"),
        ("is","instance-template.create","Create Instance Template","VPC Instance Templates"),

        # IKS (Kubernetes)
        ("containers_kubernetes","cluster.create","Create Kubernetes Cluster","IKS Clusters"),
        ("containers_kubernetes","cluster.update","Update Kubernetes Cluster","IKS Clusters"),
        ("containers_kubernetes","cluster.delete","Delete Kubernetes Cluster","IKS Clusters"),
        ("containers_kubernetes","worker.add","Add Worker Node","IKS Workers"),
        ("containers_kubernetes","worker.delete","Delete Worker Node","IKS Workers"),
        ("containers_kubernetes","worker-pool.create","Create Worker Pool","IKS Worker Pools"),
        ("containers_kubernetes","worker-pool.delete","Delete Worker Pool","IKS Worker Pools"),
        ("containers_kubernetes","nlb.create","Create NLB for IKS","IKS NLBs"),
        ("containers_kubernetes","alb.create","Create ALB for IKS","IKS ALBs"),
        ("containers_kubernetes","ingress.update","Update Ingress for IKS","IKS Ingress"),

        # Container Registry
        ("container_registry","namespace.create","Create Container Registry Namespace","Registry Namespaces"),
        ("container_registry","namespace.delete","Delete Container Registry Namespace","Registry Namespaces"),
        ("container_registry","image.delete","Delete Container Image","Registry Images"),
        ("container_registry","retention-policy.set","Set Image Retention Policy","Registry Retention"),
        ("container_registry","auth.set","Update Registry Authentication Settings","Registry Auth"),

        # Code Engine
        ("codeengine","application.create","Create Code Engine Application","Code Engine Apps"),
        ("codeengine","application.update","Update Code Engine Application","Code Engine Apps"),
        ("codeengine","application.delete","Delete Code Engine Application","Code Engine Apps"),
        ("codeengine","job.create","Create Code Engine Job","Code Engine Jobs"),
        ("codeengine","job.delete","Delete Code Engine Job","Code Engine Jobs"),
        ("codeengine","project.create","Create Code Engine Project","Code Engine Projects"),
        ("codeengine","project.delete","Delete Code Engine Project","Code Engine Projects"),
        ("codeengine","configmap.create","Create Code Engine ConfigMap","Code Engine ConfigMaps"),
        ("codeengine","secret.create","Create Code Engine Secret","Code Engine Secrets"),
        ("codeengine","secret.delete","Delete Code Engine Secret","Code Engine Secrets"),

        # Databases for X
        ("databases_for_postgresql","deployment.create","Create Databases for PostgreSQL Instance","PostgreSQL Instances"),
        ("databases_for_postgresql","deployment.delete","Delete Databases for PostgreSQL Instance","PostgreSQL Instances"),
        ("databases_for_postgresql","user.create","Create PostgreSQL User","PostgreSQL Users"),
        ("databases_for_postgresql","user.delete","Delete PostgreSQL User","PostgreSQL Users"),
        ("databases_for_postgresql","whitelist.update","Update PostgreSQL Allowlist","PostgreSQL Allowlist"),
        ("databases_for_mongodb","deployment.create","Create Databases for MongoDB Instance","MongoDB Instances"),
        ("databases_for_mongodb","deployment.delete","Delete Databases for MongoDB Instance","MongoDB Instances"),
        ("databases_for_redis","deployment.create","Create Databases for Redis Instance","Redis Instances"),
        ("databases_for_redis","deployment.delete","Delete Databases for Redis Instance","Redis Instances"),
        ("cloudantnosqldb","cluster.create","Create Cloudant Database Instance","Cloudant Instances"),
        ("cloudantnosqldb","cluster.delete","Delete Cloudant Database Instance","Cloudant Instances"),
        ("cloudantnosqldb","db.create","Create Cloudant Database","Cloudant Databases"),

        # Event Notifications
        ("event_notifications","instance.create","Create Event Notifications Instance","Event Notifications"),
        ("event_notifications","instance.delete","Delete Event Notifications Instance","Event Notifications"),
        ("event_notifications","topic.create","Create Event Notifications Topic","EN Topics"),
        ("event_notifications","topic.delete","Delete Event Notifications Topic","EN Topics"),
        ("event_notifications","subscription.create","Create Event Notifications Subscription","EN Subscriptions"),
        ("event_notifications","subscription.delete","Delete Event Notifications Subscription","EN Subscriptions"),

        # Activity Tracker (ATracker)
        ("atracker","target.create","Create Activity Tracker Target","ATracker Targets"),
        ("atracker","target.update","Update Activity Tracker Target","ATracker Targets"),
        ("atracker","target.delete","Delete Activity Tracker Target","ATracker Targets"),
        ("atracker","route.create","Create Activity Tracker Route","ATracker Routes"),
        ("atracker","route.update","Update Activity Tracker Route","ATracker Routes"),
        ("atracker","route.delete","Delete Activity Tracker Route","ATracker Routes"),

        # Schematics (Terraform)
        ("schematics","workspace.create","Create Schematics Workspace","Schematics Workspaces"),
        ("schematics","workspace.update","Update Schematics Workspace","Schematics Workspaces"),
        ("schematics","workspace.delete","Delete Schematics Workspace","Schematics Workspaces"),
        ("schematics","workspace-action.apply","Apply Schematics Workspace (Terraform Apply)","Schematics Actions"),
        ("schematics","workspace-action.destroy","Destroy Schematics Workspace (Terraform Destroy)","Schematics Actions"),
        ("schematics","action.create","Create Schematics Action (Ansible)","Schematics Ansible Actions"),
        ("schematics","action.delete","Delete Schematics Action","Schematics Ansible Actions"),

        # Transit Gateway
        ("transit_gateway","gateway.create","Create Transit Gateway","Transit Gateways"),
        ("transit_gateway","gateway.update","Update Transit Gateway","Transit Gateways"),
        ("transit_gateway","gateway.delete","Delete Transit Gateway","Transit Gateways"),
        ("transit_gateway","connection.create","Create Transit Gateway Connection","TGW Connections"),
        ("transit_gateway","connection.update","Update Transit Gateway Connection","TGW Connections"),
        ("transit_gateway","connection.delete","Delete Transit Gateway Connection","TGW Connections"),

        # Toolchain / CD
        ("toolchain","toolchain.create","Create Toolchain","Toolchains"),
        ("toolchain","toolchain.update","Update Toolchain","Toolchains"),
        ("toolchain","toolchain.delete","Delete Toolchain","Toolchains"),
        ("continuous_delivery","pipeline.create","Create Continuous Delivery Pipeline","CD Pipelines"),
        ("continuous_delivery","pipeline.delete","Delete Continuous Delivery Pipeline","CD Pipelines"),
        ("continuous_delivery","tekton-pipeline.create","Create Tekton Pipeline","Tekton Pipelines"),
        ("continuous_delivery","tekton-pipeline.delete","Delete Tekton Pipeline","Tekton Pipelines"),

        # Monitoring (IBM Cloud Monitoring / Sysdig)
        ("sysdig_monitor","alert.create","Create Monitoring Alert","Monitoring Alerts"),
        ("sysdig_monitor","alert.update","Update Monitoring Alert","Monitoring Alerts"),
        ("sysdig_monitor","alert.delete","Delete Monitoring Alert","Monitoring Alerts"),
        ("sysdig_monitor","notification.create","Create Monitoring Notification Channel","Monitoring Notifications"),
        ("sysdig_monitor","notification.delete","Delete Monitoring Notification Channel","Monitoring Notifications"),
        ("sysdig_monitor","team.create","Create Monitoring Team","Monitoring Teams"),
        ("sysdig_monitor","team.delete","Delete Monitoring Team","Monitoring Teams"),
        ("sysdig_monitor","capture.create","Create Monitoring Capture (Sysdig Capture)","Monitoring Captures"),

        # LogDNA (Log Analysis)
        ("logdna","account.update","Update Log Analysis Account Settings","Log Analysis Settings"),
        ("logdna","archive.config","Configure Log Analysis Archiving","Log Analysis Archive"),
        ("logdna","key.create","Create Log Analysis Service Key","Log Analysis Keys"),
        ("logdna","key.delete","Delete Log Analysis Service Key","Log Analysis Keys"),
        ("logdna","exclusion.create","Create Log Analysis Exclusion Rule","Log Analysis Exclusions"),
        ("logdna","exclusion.delete","Delete Log Analysis Exclusion Rule","Log Analysis Exclusions"),

        # Satellite
        ("satellite","location.create","Create Satellite Location","Satellite Locations"),
        ("satellite","location.update","Update Satellite Location","Satellite Locations"),
        ("satellite","location.delete","Delete Satellite Location","Satellite Locations"),
        ("satellite","cluster.create","Create Satellite Cluster","Satellite Clusters"),
        ("satellite","cluster.delete","Delete Satellite Cluster","Satellite Clusters"),
        ("satellite","config.create","Create Satellite Config","Satellite Configs"),
        ("satellite","link.create","Create Satellite Link (Connector)","Satellite Links"),
        ("satellite","endpoint.create","Create Satellite Endpoint","Satellite Endpoints"),

        # App ID
        ("appid","application.create","Create App ID Application","App ID Applications"),
        ("appid","application.delete","Delete App ID Application","App ID Applications"),
        ("appid","application.update","Update App ID Application","App ID Applications"),
        ("appid","cloud-directory.set","Update App ID Cloud Directory Settings","App ID Cloud Directory"),
        ("appid","idp.set","Configure App ID Identity Provider","App ID Identity Providers"),
        ("appid","action-url.set","Set App ID Redirect/Action URL","App ID Redirect URLs"),

        # DNS Services
        ("dns_svcs","zone.create","Create Private DNS Zone","DNS Zones"),
        ("dns_svcs","zone.update","Update Private DNS Zone","DNS Zones"),
        ("dns_svcs","zone.delete","Delete Private DNS Zone","DNS Zones"),
        ("dns_svcs","resource-record.create","Create DNS Resource Record","DNS Records"),
        ("dns_svcs","resource-record.delete","Delete DNS Resource Record","DNS Records"),
        ("dns_svcs","forwarding-rule.create","Create DNS Forwarding Rule","DNS Forwarding Rules"),

        # Message Hub (Event Streams)
        ("messagehub","cluster.update","Update Event Streams Cluster","Event Streams Clusters"),
        ("messagehub","topic.create","Create Event Streams Topic","Event Streams Topics"),
        ("messagehub","topic.delete","Delete Event Streams Topic","Event Streams Topics"),
        ("messagehub","service-credentials.create","Create Event Streams Service Credentials","ES Credentials"),
        ("messagehub","service-credentials.delete","Delete Event Streams Service Credentials","ES Credentials"),
        ("messagehub","mirroring.update","Update Event Streams Mirroring Config","ES Mirroring"),

        # Security Advisor (Findings API)
        ("security_advisor","note.create","Create Security Finding Note","Security Findings"),
        ("security_advisor","note.update","Update Security Finding Note","Security Findings"),
        ("security_advisor","note.delete","Delete Security Finding Note","Security Findings"),
        ("security_advisor","occurrence.create","Create Security Occurrence","Security Occurrences"),

        # Functions (IBM Cloud Functions / OpenWhisk)
        ("functions","namespace.create","Create Functions Namespace","Functions Namespaces"),
        ("functions","namespace.delete","Delete Functions Namespace","Functions Namespaces"),
        ("functions","action.create","Create Function Action","Functions Actions"),
        ("functions","action.update","Update Function Action","Functions Actions"),
        ("functions","action.delete","Delete Function Action","Functions Actions"),
        ("functions","trigger.create","Create Function Trigger","Functions Triggers"),
        ("functions","trigger.delete","Delete Function Trigger","Functions Triggers"),
        ("functions","rule.create","Create Function Rule","Functions Rules"),
    ]

    with open(path, "w") as f:
        f.write("-- IBM CRUD expansion rules\n")
        for entry in rules:
            ibm_svc, verb_frag, display, res = entry
            cat = infer_cat(verb_frag + " " + display)
            rid_suffix = hashlib.md5((ibm_svc + verb_frag).encode()).hexdigest()[:8]
            rid = f"log.ibm.{ibm_svc}.{rid_suffix}"
            title = f"IBM {res}: {display}"
            desc = f"Detected {verb_frag} operation on {res} via IBM Activity Tracker."
            emit(f, rid, ibm_svc, "ibm", title, desc, cat, cfg_ibm(ibm_svc, verb_frag), verb_frag)
            n += 1

    print(f"IBM CRUD expanded: {n} → {path}")
    return n


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    az = generate_azure(OUT_DIR)
    gcp = generate_gcp(OUT_DIR)
    oci = generate_oci(OUT_DIR)
    ibm = generate_ibm(OUT_DIR)
    print(f"\nTotal new CRUD rules: {az + gcp + oci + ibm}")
    print(f"\nExpected totals after insert:")
    print(f"  Azure: 174 + {az}  = {174 + az}")
    print(f"  GCP:   125 + {gcp} = {125 + gcp}")
    print(f"  OCI:   162 + {oci} = {162 + oci}")
    print(f"  IBM:    79 + {ibm} = {79 + ibm}")
