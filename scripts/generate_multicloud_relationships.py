#!/usr/bin/env python3
"""
Multi-Cloud Relationship Rules Generator

Generates relationship rules for Azure, GCP, OCI, IBM, Alicloud, and K8s
by applying common cloud patterns to resource types from the pythonsdk DB.

Rules are written directly to the relationship_rules table in threat_engine_pythonsdk.
"""

import json
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Tuple, Any

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

# --- DB Connection ---
DB_HOST = os.getenv("PYTHONSDK_DB_HOST", "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com")
DB_PORT = os.getenv("PYTHONSDK_DB_PORT", "5432")
DB_NAME = os.getenv("PYTHONSDK_DB_NAME", "threat_engine_pythonsdk")
DB_USER = os.getenv("PYTHONSDK_DB_USER", "postgres")
DB_PASS = os.getenv("PYTHONSDK_DB_PASSWORD", "jtv2BkJF8qoFtAKP")


def get_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS
    )


# ============================================================================
# AZURE RELATIONSHIP RULES
# ============================================================================

def generate_azure_rules() -> List[Dict]:
    """Generate relationship rules for Azure."""
    rules = []
    csp = "azure"

    # --- Compute ---
    # VM → Network Interface
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "attached_to",
                    "network.networkinterfaces", "networkProfile.networkInterfaces[].id",
                    "{networkProfile.networkInterfaces[].id}"))
    # VM → Disk (OS)
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "uses",
                    "compute.disks", "storageProfile.osDisk.managedDisk.id",
                    "{storageProfile.osDisk.managedDisk.id}"))
    # VM → Disk (Data)
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "uses",
                    "compute.disks", "storageProfile.dataDisks[].managedDisk.id",
                    "{storageProfile.dataDisks[].managedDisk.id}"))
    # VM → Availability Set
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "member_of",
                    "compute.availabilitysets", "availabilitySet.id",
                    "{availabilitySet.id}"))
    # VM → VM Scale Set
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "member_of",
                    "compute.virtualmachinescalesets", "virtualMachineScaleSet.id",
                    "{virtualMachineScaleSet.id}"))
    # VM → Image
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "uses",
                    "compute.images", "storageProfile.imageReference.id",
                    "{storageProfile.imageReference.id}"))
    # VM → Proximity Placement Group
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "member_of",
                    "compute.proximityplacementgroups", "proximityPlacementGroup.id",
                    "{proximityPlacementGroup.id}"))
    # VM → Dedicated Host
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "runs_on",
                    "compute.dedicatedhosts", "host.id",
                    "{host.id}"))
    # VM → Disk Encryption Set
    rules.append(r(csp, "azure.compute", "compute.virtualmachines", "encrypted_by",
                    "compute.diskencryptionsets", "storageProfile.osDisk.managedDisk.diskEncryptionSet.id",
                    "{storageProfile.osDisk.managedDisk.diskEncryptionSet.id}"))
    # VMSS → Subnet
    rules.append(r(csp, "azure.compute", "compute.virtualmachinescalesets", "contained_by",
                    "network.subnets", "virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].ipConfigurations[].subnet.id",
                    "{subnet.id}"))
    # Disk → Disk Encryption Set
    rules.append(r(csp, "azure.compute", "compute.disks", "encrypted_by",
                    "compute.diskencryptionsets", "encryption.diskEncryptionSetId",
                    "{encryption.diskEncryptionSetId}"))
    # Disk Encryption Set → Key Vault Key
    rules.append(r(csp, "azure.compute", "compute.diskencryptionsets", "uses",
                    "keyvault.keys", "activeKey.keyUrl",
                    "{activeKey.keyUrl}"))
    # Snapshot → Disk
    rules.append(r(csp, "azure.compute", "compute.snapshots", "backs_up_to",
                    "compute.disks", "creationData.sourceResourceId",
                    "{creationData.sourceResourceId}"))

    # --- Network ---
    # NIC → Subnet
    rules.append(r(csp, "azure.network", "network.networkinterfaces", "contained_by",
                    "network.subnets", "ipConfigurations[].subnet.id",
                    "{ipConfigurations[].subnet.id}"))
    # NIC → NSG
    rules.append(r(csp, "azure.network", "network.networkinterfaces", "attached_to",
                    "network.networksecuritygroups", "networkSecurityGroup.id",
                    "{networkSecurityGroup.id}"))
    # NIC → Public IP
    rules.append(r(csp, "azure.network", "network.networkinterfaces", "attached_to",
                    "network.publicipaddresses", "ipConfigurations[].publicIPAddress.id",
                    "{ipConfigurations[].publicIPAddress.id}"))
    # Subnet → VNet
    rules.append(r(csp, "azure.network", "network.subnets", "contained_by",
                    "network.virtualnetworks", "vnet_id",
                    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}"))
    # Subnet → NSG
    rules.append(r(csp, "azure.network", "network.subnets", "attached_to",
                    "network.networksecuritygroups", "networkSecurityGroup.id",
                    "{networkSecurityGroup.id}"))
    # Subnet → Route Table
    rules.append(r(csp, "azure.network", "network.subnets", "routes_to",
                    "network.routetables", "routeTable.id",
                    "{routeTable.id}"))
    # VNet Peering
    rules.append(r(csp, "azure.network", "network.virtualnetworkpeerings", "connected_to",
                    "network.virtualnetworks", "remoteVirtualNetwork.id",
                    "{remoteVirtualNetwork.id}"))
    # LB → Backend Pool (NIC)
    rules.append(r(csp, "azure.network", "network.loadbalancers", "serves_traffic_for",
                    "network.networkinterfaces", "backendAddressPools[].backendIPConfigurations[].id",
                    "{backendIPConfigurations[].id}"))
    # App Gateway → Subnet
    rules.append(r(csp, "azure.network", "network.applicationgateways", "contained_by",
                    "network.subnets", "gatewayIPConfigurations[].subnet.id",
                    "{gatewayIPConfigurations[].subnet.id}"))
    # App Gateway → Key Vault Certificate
    rules.append(r(csp, "azure.network", "network.applicationgateways", "uses",
                    "keyvault.secrets", "sslCertificates[].keyVaultSecretId",
                    "{sslCertificates[].keyVaultSecretId}"))
    # Firewall → Subnet
    rules.append(r(csp, "azure.network", "network.azurefirewalls", "contained_by",
                    "network.subnets", "ipConfigurations[].subnet.id",
                    "{ipConfigurations[].subnet.id}"))
    # Firewall → Public IP
    rules.append(r(csp, "azure.network", "network.azurefirewalls", "attached_to",
                    "network.publicipaddresses", "ipConfigurations[].publicIPAddress.id",
                    "{ipConfigurations[].publicIPAddress.id}"))
    # Private Endpoint → Subnet
    rules.append(r(csp, "azure.network", "network.privateendpoints", "contained_by",
                    "network.subnets", "subnet.id",
                    "{subnet.id}"))
    # VPN Gateway → Subnet
    rules.append(r(csp, "azure.network", "network.virtualnetworkgateways", "contained_by",
                    "network.subnets", "ipConfigurations[].subnet.id",
                    "{ipConfigurations[].subnet.id}"))
    # VPN Gateway → Public IP
    rules.append(r(csp, "azure.network", "network.virtualnetworkgateways", "attached_to",
                    "network.publicipaddresses", "ipConfigurations[].publicIPAddress.id",
                    "{ipConfigurations[].publicIPAddress.id}"))
    # NAT Gateway → Public IP
    rules.append(r(csp, "azure.network", "network.natgateways", "attached_to",
                    "network.publicipaddresses", "publicIpAddresses[].id",
                    "{publicIpAddresses[].id}"))
    # NAT Gateway → Subnet
    rules.append(r(csp, "azure.network", "network.natgateways", "attached_to",
                    "network.subnets", "subnets[].id",
                    "{subnets[].id}"))
    # Bastion → Subnet
    rules.append(r(csp, "azure.network", "network.bastionhosts", "contained_by",
                    "network.subnets", "ipConfigurations[].subnet.id",
                    "{ipConfigurations[].subnet.id}"))

    # --- Storage ---
    # Storage Account → Private Endpoint
    rules.append(r(csp, "azure.storage", "storage.storageaccounts", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    # Storage Account → Key Vault Key (CMK)
    rules.append(r(csp, "azure.storage", "storage.storageaccounts", "encrypted_by",
                    "keyvault.keys", "encryption.keyVaultProperties.keyVaultUri",
                    "{encryption.keyVaultProperties.keyVaultUri}"))
    # Storage Account → VNet Rule
    rules.append(r(csp, "azure.storage", "storage.storageaccounts", "allows_traffic_from",
                    "network.virtualnetworks", "networkRuleSet.virtualNetworkRules[].virtualNetworkResourceId",
                    "{networkRuleSet.virtualNetworkRules[].virtualNetworkResourceId}"))

    # --- Key Vault ---
    # Key Vault → Private Endpoint
    rules.append(r(csp, "azure.keyvault", "keyvault.vaults", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    # Key Vault → VNet Rule
    rules.append(r(csp, "azure.keyvault", "keyvault.vaults", "allows_traffic_from",
                    "network.virtualnetworks", "networkAcls.virtualNetworkRules[].id",
                    "{networkAcls.virtualNetworkRules[].id}"))

    # --- SQL ---
    # SQL Server → Private Endpoint
    rules.append(r(csp, "azure.sql", "sql.servers", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    # SQL Server → VNet Rule
    rules.append(r(csp, "azure.sql", "sql.servers", "allows_traffic_from",
                    "network.virtualnetworks", "virtualNetworkSubnetId",
                    "{virtualNetworkSubnetId}"))
    # SQL Database → Server
    rules.append(r(csp, "azure.sql", "sql.databases", "contained_by",
                    "sql.servers", "server_id",
                    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}"))
    # SQL Database → Elastic Pool
    rules.append(r(csp, "azure.sql", "sql.databases", "member_of",
                    "sql.elasticpools", "elasticPoolId",
                    "{elasticPoolId}"))
    # SQL Database → Key Vault Key (TDE)
    rules.append(r(csp, "azure.sql", "sql.databases", "encrypted_by",
                    "keyvault.keys", "encryptionProtector.serverKeyName",
                    "{encryptionProtector.serverKeyName}"))

    # --- Container Service (AKS) ---
    # AKS → Subnet
    rules.append(r(csp, "azure.containerservice", "containerservice.managedclusters", "contained_by",
                    "network.subnets", "agentPoolProfiles[].vnetSubnetID",
                    "{agentPoolProfiles[].vnetSubnetID}"))
    # AKS → Log Analytics Workspace
    rules.append(r(csp, "azure.containerservice", "containerservice.managedclusters", "logging_enabled_to",
                    "monitor.azuremonitorworkspaces", "addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID",
                    "{addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID}"))
    # AKS → Managed Identity
    rules.append(r(csp, "azure.containerservice", "containerservice.managedclusters", "assumes",
                    "authorization.roleassignments", "identity.principalId",
                    "{identity.principalId}"))
    # Agent Pool → VMSS
    rules.append(r(csp, "azure.containerservice", "containerservice.agentpools", "runs_on",
                    "compute.virtualmachinescalesets", "nodeImageVersion",
                    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}"))
    # AKS → ACR
    rules.append(r(csp, "azure.containerservice", "containerservice.managedclusters", "uses",
                    "containerregistry.registries", "acrResourceId",
                    "{acrResourceId}"))

    # --- Container Registry ---
    rules.append(r(csp, "azure.containerregistry", "containerregistry.registries", "encrypted_by",
                    "keyvault.keys", "encryption.keyVaultProperties.keyIdentifier",
                    "{encryption.keyVaultProperties.keyIdentifier}"))
    rules.append(r(csp, "azure.containerregistry", "containerregistry.registries", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))

    # --- Web (App Service) ---
    rules.append(r(csp, "azure.web", "web.sites", "contained_by",
                    "web.serverfarms", "serverFarmId",
                    "{serverFarmId}"))
    rules.append(r(csp, "azure.web", "web.sites", "contained_by",
                    "network.subnets", "virtualNetworkSubnetId",
                    "{virtualNetworkSubnetId}"))
    rules.append(r(csp, "azure.web", "web.sites", "assumes",
                    "authorization.roleassignments", "identity.principalId",
                    "{identity.principalId}"))
    rules.append(r(csp, "azure.web", "web.sites", "uses",
                    "keyvault.secrets", "siteConfig.appSettings.keyVaultReference",
                    "{siteConfig.appSettings.keyVaultReference}"))

    # --- CosmosDB ---
    rules.append(r(csp, "azure.cosmosdb", "cosmosdb.databaseaccounts", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    rules.append(r(csp, "azure.cosmosdb", "cosmosdb.databaseaccounts", "allows_traffic_from",
                    "network.virtualnetworks", "virtualNetworkRules[].id",
                    "{virtualNetworkRules[].id}"))
    rules.append(r(csp, "azure.cosmosdb", "cosmosdb.databaseaccounts", "encrypted_by",
                    "keyvault.keys", "keyVaultKeyUri",
                    "{keyVaultKeyUri}"))

    # --- Authorization (RBAC) ---
    rules.append(r(csp, "azure.authorization", "authorization.roleassignments", "grants_access_to",
                    "authorization.roledefinitions", "roleDefinitionId",
                    "{roleDefinitionId}"))

    # --- Monitor ---
    rules.append(r(csp, "azure.monitor", "monitor.metricalerts", "monitored_by",
                    "monitor.actiongroups", "actions[].actionGroupId",
                    "{actions[].actionGroupId}"))
    rules.append(r(csp, "azure.monitor", "monitor.datacollectionrules", "routes_to",
                    "monitor.azuremonitorworkspaces", "destinations.logAnalytics[].workspaceResourceId",
                    "{destinations.logAnalytics[].workspaceResourceId}"))
    rules.append(r(csp, "azure.monitor", "monitor.autoscalesettings", "attached_to",
                    "compute.virtualmachinescalesets", "targetResourceUri",
                    "{targetResourceUri}"))

    # --- Redis ---
    rules.append(r(csp, "azure.cache", "cache.redis", "contained_by",
                    "network.subnets", "subnetId",
                    "{subnetId}"))
    rules.append(r(csp, "azure.cache", "cache.redis", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))

    # --- PostgreSQL / MySQL ---
    rules.append(r(csp, "azure.rdbms_postgresql", "rdbms_postgresql.servers", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    rules.append(r(csp, "azure.rdbms_postgresql", "rdbms_postgresql.servers", "allows_traffic_from",
                    "network.virtualnetworks", "virtualNetworkRules[].virtualNetworkSubnetId",
                    "{virtualNetworkRules[].virtualNetworkSubnetId}"))
    rules.append(r(csp, "azure.rdbms_mysql", "rdbms_mysql.servers", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))

    # --- Event Hub / Service Bus ---
    rules.append(r(csp, "azure.eventhub", "eventhub.namespaces", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))
    rules.append(r(csp, "azure.eventhub", "eventhub.namespaces", "encrypted_by",
                    "keyvault.keys", "encryption.keyVaultProperties[].keyName",
                    "{encryption.keyVaultProperties[].keyName}"))
    rules.append(r(csp, "azure.servicebus", "servicebus.namespaces", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))

    # --- Data Factory ---
    rules.append(r(csp, "azure.datafactory", "datafactory.factories", "assumes",
                    "authorization.roleassignments", "identity.principalId",
                    "{identity.principalId}"))
    rules.append(r(csp, "azure.datafactory", "datafactory.factories", "connected_to",
                    "network.privateendpoints", "privateEndpointConnections[].privateEndpoint.id",
                    "{privateEndpointConnections[].privateEndpoint.id}"))

    # --- DNS ---
    rules.append(r(csp, "azure.dns", "dns.recordsets", "resolves_to",
                    "network.publicipaddresses", "ARecords[].ipv4Address",
                    "{ARecords[].ipv4Address}"))
    rules.append(r(csp, "azure.privatedns", "privatedns.recordsets", "resolves_to",
                    "network.privateendpoints", "ARecords[].ipv4Address",
                    "{ARecords[].ipv4Address}"))

    # --- CDN ---
    rules.append(r(csp, "azure.cdn", "cdn.endpoints", "serves_traffic_for",
                    "storage.storageaccounts", "origins[].hostName",
                    "{origins[].hostName}"))
    rules.append(r(csp, "azure.cdn", "cdn.endpoints", "serves_traffic_for",
                    "web.sites", "origins[].hostName",
                    "{origins[].hostName}"))

    # --- Front Door ---
    rules.append(r(csp, "azure.frontdoor", "frontdoor.frontdoors", "serves_traffic_for",
                    "web.sites", "backendPools[].backends[].address",
                    "{backendPools[].backends[].address}"))

    # --- Backup ---
    rules.append(r(csp, "azure.recoveryservicesbackup", "recoveryservicesbackup.vaults", "backs_up_to",
                    "compute.virtualmachines", "protectedItems[].sourceResourceId",
                    "{protectedItems[].sourceResourceId}"))

    # --- Logic Apps ---
    rules.append(r(csp, "azure.logic", "logic.workflows", "assumes",
                    "authorization.roleassignments", "identity.principalId",
                    "{identity.principalId}"))

    return rules


# ============================================================================
# GCP RELATIONSHIP RULES
# ============================================================================

def generate_gcp_rules() -> List[Dict]:
    """Generate relationship rules for GCP."""
    rules = []
    csp = "gcp"

    # --- Compute Engine ---
    # Instance → Network
    rules.append(r(csp, "gcp.compute", "compute.instances", "contained_by",
                    "compute.networks", "networkInterfaces[].network",
                    "{networkInterfaces[].network}"))
    # Instance → Subnetwork
    rules.append(r(csp, "gcp.compute", "compute.instances", "contained_by",
                    "compute.subnetworks", "networkInterfaces[].subnetwork",
                    "{networkInterfaces[].subnetwork}"))
    # Instance → Disk
    rules.append(r(csp, "gcp.compute", "compute.instances", "uses",
                    "compute.disks", "disks[].source",
                    "{disks[].source}"))
    # Instance → Service Account
    rules.append(r(csp, "gcp.compute", "compute.instances", "assumes",
                    "iam.serviceaccounts", "serviceAccounts[].email",
                    "{serviceAccounts[].email}"))
    # Instance → Machine Image
    rules.append(r(csp, "gcp.compute", "compute.instances", "uses",
                    "compute.images", "disks[].initializeParams.sourceImage",
                    "{disks[].initializeParams.sourceImage}"))
    # Instance → Instance Template
    rules.append(r(csp, "gcp.compute", "compute.instances", "uses",
                    "compute.instancetemplates", "sourceInstanceTemplate",
                    "{sourceInstanceTemplate}"))
    # Instance → Firewall (via network tags)
    rules.append(r(csp, "gcp.compute", "compute.firewalls", "allows_traffic_from",
                    "compute.instances", "targetTags[]",
                    "{targetTags[]}"))
    # Instance Group → Instance
    rules.append(r(csp, "gcp.compute", "compute.instancegroupmanagers", "manages",
                    "compute.instancetemplates", "instanceTemplate",
                    "{instanceTemplate}"))
    # Disk → Snapshot
    rules.append(r(csp, "gcp.compute", "compute.snapshots", "backs_up_to",
                    "compute.disks", "sourceDisk",
                    "{sourceDisk}"))
    # Disk → KMS Key
    rules.append(r(csp, "gcp.compute", "compute.disks", "encrypted_by",
                    "cloudkms.cryptokeys", "diskEncryptionKey.kmsKeyName",
                    "{diskEncryptionKey.kmsKeyName}"))
    # Forwarding Rule → Target Pool / Backend Service
    rules.append(r(csp, "gcp.compute", "compute.forwardingrules", "routes_to",
                    "compute.targetpools", "target",
                    "{target}"))
    rules.append(r(csp, "gcp.compute", "compute.forwardingrules", "routes_to",
                    "compute.backendservices", "backendService",
                    "{backendService}"))
    # Backend Service → Instance Group
    rules.append(r(csp, "gcp.compute", "compute.backendservices", "serves_traffic_for",
                    "compute.instancegroups", "backends[].group",
                    "{backends[].group}"))
    # Backend Service → Health Check
    rules.append(r(csp, "gcp.compute", "compute.backendservices", "monitored_by",
                    "compute.healthchecks", "healthChecks[]",
                    "{healthChecks[]}"))
    # URL Map → Backend Service
    rules.append(r(csp, "gcp.compute", "compute.urlmaps", "routes_to",
                    "compute.backendservices", "defaultService",
                    "{defaultService}"))
    # Target HTTPS Proxy → SSL Certificate
    rules.append(r(csp, "gcp.compute", "compute.targethttpsproxies", "uses",
                    "compute.sslcertificates", "sslCertificates[]",
                    "{sslCertificates[]}"))
    # Target HTTPS Proxy → URL Map
    rules.append(r(csp, "gcp.compute", "compute.targethttpsproxies", "routes_to",
                    "compute.urlmaps", "urlMap",
                    "{urlMap}"))
    # VPN Tunnel → VPN Gateway
    rules.append(r(csp, "gcp.compute", "compute.vpntunnels", "connected_to",
                    "compute.vpngateways", "vpnGateway",
                    "{vpnGateway}"))
    # Router → Network
    rules.append(r(csp, "gcp.compute", "compute.routers", "contained_by",
                    "compute.networks", "network",
                    "{network}"))
    # Network → Firewall
    rules.append(r(csp, "gcp.compute", "compute.firewalls", "attached_to",
                    "compute.networks", "network",
                    "{network}"))

    # --- Cloud Storage ---
    # Bucket → KMS Key
    rules.append(r(csp, "gcp.storage", "storage.buckets", "encrypted_by",
                    "cloudkms.cryptokeys", "encryption.defaultKmsKeyName",
                    "{encryption.defaultKmsKeyName}"))
    # Bucket → Logging Bucket
    rules.append(r(csp, "gcp.storage", "storage.buckets", "logging_enabled_to",
                    "storage.buckets", "logging.logBucket",
                    "{logging.logBucket}"))

    # --- GKE ---
    # Cluster → Network
    rules.append(r(csp, "gcp.container", "container.clusters", "contained_by",
                    "compute.networks", "network",
                    "{network}"))
    # Cluster → Subnetwork
    rules.append(r(csp, "gcp.container", "container.clusters", "contained_by",
                    "compute.subnetworks", "subnetwork",
                    "{subnetwork}"))
    # Cluster → Service Account
    rules.append(r(csp, "gcp.container", "container.clusters", "assumes",
                    "iam.serviceaccounts", "nodeConfig.serviceAccount",
                    "{nodeConfig.serviceAccount}"))
    # Cluster → KMS Key (envelope encryption)
    rules.append(r(csp, "gcp.container", "container.clusters", "encrypted_by",
                    "cloudkms.cryptokeys", "databaseEncryption.keyName",
                    "{databaseEncryption.keyName}"))

    # --- Cloud SQL ---
    # SQL Instance → Network
    rules.append(r(csp, "gcp.sqladmin", "sqladmin.instances", "contained_by",
                    "compute.networks", "settings.ipConfiguration.privateNetwork",
                    "{settings.ipConfiguration.privateNetwork}"))
    # SQL Instance → KMS Key
    rules.append(r(csp, "gcp.sqladmin", "sqladmin.instances", "encrypted_by",
                    "cloudkms.cryptokeys", "diskEncryptionConfiguration.kmsKeyName",
                    "{diskEncryptionConfiguration.kmsKeyName}"))
    # SQL Instance → Replica
    rules.append(r(csp, "gcp.sqladmin", "sqladmin.instances", "replicates_to",
                    "sqladmin.instances", "replicaNames[]",
                    "{replicaNames[]}"))

    # --- IAM ---
    # Service Account → Role
    rules.append(r(csp, "gcp.iam", "iam.serviceaccounts", "has_policy",
                    "iam.roles", "bindings[].role",
                    "{bindings[].role}"))
    # Service Account Key → Service Account
    rules.append(r(csp, "gcp.iam", "iam.serviceaccountkeys", "attached_to",
                    "iam.serviceaccounts", "serviceAccountEmail",
                    "{serviceAccountEmail}"))

    # --- Cloud Functions ---
    # Function → VPC Connector
    rules.append(r(csp, "gcp.cloudfunctions", "cloudfunctions.functions", "contained_by",
                    "compute.networks", "vpcConnector",
                    "{vpcConnector}"))
    # Function → Service Account
    rules.append(r(csp, "gcp.cloudfunctions", "cloudfunctions.functions", "assumes",
                    "iam.serviceaccounts", "serviceAccountEmail",
                    "{serviceAccountEmail}"))
    # Function → Pub/Sub Trigger
    rules.append(r(csp, "gcp.cloudfunctions", "cloudfunctions.functions", "subscribes_to",
                    "pubsub.topics", "eventTrigger.resource",
                    "{eventTrigger.resource}"))
    # Function → Secret
    rules.append(r(csp, "gcp.cloudfunctions", "cloudfunctions.functions", "uses",
                    "secretmanager.secrets", "secretEnvironmentVariables[].secret",
                    "{secretEnvironmentVariables[].secret}"))

    # --- Cloud Run ---
    rules.append(r(csp, "gcp.run", "run.services", "assumes",
                    "iam.serviceaccounts", "spec.template.spec.serviceAccountName",
                    "{spec.template.spec.serviceAccountName}"))
    rules.append(r(csp, "gcp.run", "run.services", "contained_by",
                    "compute.networks", "spec.template.metadata.annotations.run.googleapis.com/vpc-access-connector",
                    "{spec.template.metadata.annotations.run.googleapis.com/vpc-access-connector}"))

    # --- Pub/Sub ---
    rules.append(r(csp, "gcp.pubsub", "pubsub.subscriptions", "subscribes_to",
                    "pubsub.topics", "topic",
                    "{topic}"))
    rules.append(r(csp, "gcp.pubsub", "pubsub.subscriptions", "routes_to",
                    "cloudfunctions.functions", "pushConfig.pushEndpoint",
                    "{pushConfig.pushEndpoint}"))

    # --- BigQuery ---
    rules.append(r(csp, "gcp.bigquery", "bigquery.datasets", "encrypted_by",
                    "cloudkms.cryptokeys", "defaultEncryptionConfiguration.kmsKeyName",
                    "{defaultEncryptionConfiguration.kmsKeyName}"))

    # --- Cloud KMS ---
    rules.append(r(csp, "gcp.cloudkms", "cloudkms.keyrings", "contained_by",
                    "cloudkms.locations", "location",
                    "projects/{project}/locations/{location}"))

    # --- Logging ---
    rules.append(r(csp, "gcp.logging", "logging.sinks", "routes_to",
                    "storage.buckets", "destination",
                    "{destination}"))
    rules.append(r(csp, "gcp.logging", "logging.sinks", "routes_to",
                    "bigquery.datasets", "destination",
                    "{destination}"))
    rules.append(r(csp, "gcp.logging", "logging.sinks", "routes_to",
                    "pubsub.topics", "destination",
                    "{destination}"))

    # --- Cloud DNS ---
    rules.append(r(csp, "gcp.dns", "dns.managedzones", "contained_by",
                    "compute.networks", "privateVisibilityConfig.networks[].networkUrl",
                    "{privateVisibilityConfig.networks[].networkUrl}"))

    # --- Memorystore (Redis) ---
    rules.append(r(csp, "gcp.redis", "redis.instances", "contained_by",
                    "compute.networks", "authorizedNetwork",
                    "{authorizedNetwork}"))

    # --- Spanner ---
    rules.append(r(csp, "gcp.spanner", "spanner.databases", "contained_by",
                    "spanner.instances", "instance",
                    "{instance}"))
    rules.append(r(csp, "gcp.spanner", "spanner.databases", "encrypted_by",
                    "cloudkms.cryptokeys", "encryptionConfig.kmsKeyName",
                    "{encryptionConfig.kmsKeyName}"))

    # --- Cloud Armor ---
    rules.append(r(csp, "gcp.compute", "compute.securitypolicies", "attached_to",
                    "compute.backendservices", "targetResource",
                    "{targetResource}"))

    return rules


# ============================================================================
# OCI RELATIONSHIP RULES
# ============================================================================

def generate_oci_rules() -> List[Dict]:
    """Generate relationship rules for Oracle Cloud Infrastructure."""
    rules = []
    csp = "oci"

    # --- Compute ---
    # Instance → VCN Subnet
    rules.append(r(csp, "oci.core", "core.instances", "contained_by",
                    "core.subnets", "launchDetails.createVnicDetails.subnetId",
                    "{launchDetails.createVnicDetails.subnetId}"))
    # Instance → Image
    rules.append(r(csp, "oci.core", "core.instances", "uses",
                    "core.images", "sourceDetails.imageId",
                    "{sourceDetails.imageId}"))
    # Instance → Shape (Availability Domain)
    rules.append(r(csp, "oci.core", "core.instances", "runs_on",
                    "core.shapes", "shape",
                    "{shape}"))
    # Instance → Boot Volume
    rules.append(r(csp, "oci.core", "core.instances", "uses",
                    "core.bootvolumes", "bootVolumeId",
                    "{bootVolumeId}"))
    # Instance → VNIC
    rules.append(r(csp, "oci.core", "core.vnicattachments", "attached_to",
                    "core.instances", "instanceId",
                    "{instanceId}"))
    rules.append(r(csp, "oci.core", "core.vnicattachments", "attached_to",
                    "core.vnics", "vnicId",
                    "{vnicId}"))

    # --- Network ---
    # Subnet → VCN
    rules.append(r(csp, "oci.core", "core.subnets", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # Subnet → Route Table
    rules.append(r(csp, "oci.core", "core.subnets", "routes_to",
                    "core.routetables", "routeTableId",
                    "{routeTableId}"))
    # Subnet → Security List
    rules.append(r(csp, "oci.core", "core.subnets", "attached_to",
                    "core.securitylists", "securityListIds[]",
                    "{securityListIds[]}"))
    # Subnet → DHCP Options
    rules.append(r(csp, "oci.core", "core.subnets", "uses",
                    "core.dhcpoptions", "dhcpOptionsId",
                    "{dhcpOptionsId}"))
    # NSG → VCN
    rules.append(r(csp, "oci.core", "core.networksecuritygroups", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # Internet Gateway → VCN
    rules.append(r(csp, "oci.core", "core.internetgateways", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # NAT Gateway → VCN
    rules.append(r(csp, "oci.core", "core.natgateways", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # Service Gateway → VCN
    rules.append(r(csp, "oci.core", "core.servicegateways", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # DRG Attachment → VCN
    rules.append(r(csp, "oci.core", "core.drgattachments", "connected_to",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    rules.append(r(csp, "oci.core", "core.drgattachments", "connected_to",
                    "core.drgs", "drgId",
                    "{drgId}"))
    # Route Table → VCN
    rules.append(r(csp, "oci.core", "core.routetables", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # Security List → VCN
    rules.append(r(csp, "oci.core", "core.securitylists", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    # LPG → VCN
    rules.append(r(csp, "oci.core", "core.localpeerings", "connected_to",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    rules.append(r(csp, "oci.core", "core.localpeerings", "connected_to",
                    "core.localpeerings", "peerId",
                    "{peerId}"))

    # --- Storage ---
    # Volume → Backup Policy
    rules.append(r(csp, "oci.core", "core.volumes", "backs_up_to",
                    "core.volumebackuppolicies", "volumeBackupPolicyId",
                    "{volumeBackupPolicyId}"))
    # Volume → KMS Key
    rules.append(r(csp, "oci.core", "core.volumes", "encrypted_by",
                    "kms.keys", "kmsKeyId",
                    "{kmsKeyId}"))
    # Volume Attachment → Instance
    rules.append(r(csp, "oci.core", "core.volumeattachments", "attached_to",
                    "core.instances", "instanceId",
                    "{instanceId}"))
    rules.append(r(csp, "oci.core", "core.volumeattachments", "attached_to",
                    "core.volumes", "volumeId",
                    "{volumeId}"))
    # Boot Volume → KMS Key
    rules.append(r(csp, "oci.core", "core.bootvolumes", "encrypted_by",
                    "kms.keys", "kmsKeyId",
                    "{kmsKeyId}"))
    # Object Storage → KMS Key
    rules.append(r(csp, "oci.objectstorage", "objectstorage.buckets", "encrypted_by",
                    "kms.keys", "kmsKeyId",
                    "{kmsKeyId}"))

    # --- Load Balancer ---
    rules.append(r(csp, "oci.loadbalancer", "loadbalancer.loadbalancers", "contained_by",
                    "core.subnets", "subnetIds[]",
                    "{subnetIds[]}"))
    rules.append(r(csp, "oci.loadbalancer", "loadbalancer.loadbalancers", "attached_to",
                    "core.networksecuritygroups", "networkSecurityGroupIds[]",
                    "{networkSecurityGroupIds[]}"))

    # --- Database ---
    rules.append(r(csp, "oci.database", "database.dbsystems", "contained_by",
                    "core.subnets", "subnetId",
                    "{subnetId}"))
    rules.append(r(csp, "oci.database", "database.dbsystems", "attached_to",
                    "core.networksecuritygroups", "nsgIds[]",
                    "{nsgIds[]}"))
    rules.append(r(csp, "oci.database", "database.autonomousdatabases", "contained_by",
                    "core.subnets", "subnetId",
                    "{subnetId}"))
    rules.append(r(csp, "oci.database", "database.autonomousdatabases", "attached_to",
                    "core.networksecuritygroups", "nsgIds[]",
                    "{nsgIds[]}"))
    rules.append(r(csp, "oci.database", "database.autonomousdatabases", "encrypted_by",
                    "kms.keys", "kmsKeyId",
                    "{kmsKeyId}"))

    # --- Container Engine (OKE) ---
    rules.append(r(csp, "oci.containerengine", "containerengine.clusters", "contained_by",
                    "core.vcns", "vcnId",
                    "{vcnId}"))
    rules.append(r(csp, "oci.containerengine", "containerengine.nodepools", "contained_by",
                    "core.subnets", "nodeConfigDetails.placementConfigs[].subnetId",
                    "{nodeConfigDetails.placementConfigs[].subnetId}"))
    rules.append(r(csp, "oci.containerengine", "containerengine.nodepools", "member_of",
                    "containerengine.clusters", "clusterId",
                    "{clusterId}"))

    # --- Functions ---
    rules.append(r(csp, "oci.functions", "functions.applications", "contained_by",
                    "core.subnets", "subnetIds[]",
                    "{subnetIds[]}"))

    # --- Notifications ---
    rules.append(r(csp, "oci.ons", "ons.subscriptions", "subscribes_to",
                    "ons.topics", "topicId",
                    "{topicId}"))

    # --- Events ---
    rules.append(r(csp, "oci.events", "events.rules", "triggers",
                    "functions.functions", "actions.actions[].functionId",
                    "{actions.actions[].functionId}"))
    rules.append(r(csp, "oci.events", "events.rules", "publishes_to",
                    "ons.topics", "actions.actions[].topicId",
                    "{actions.actions[].topicId}"))

    # --- Vault / KMS ---
    rules.append(r(csp, "oci.kms", "kms.keys", "contained_by",
                    "kms.vaults", "vaultId",
                    "{vaultId}"))

    # --- IAM ---
    rules.append(r(csp, "oci.identity", "identity.policies", "has_policy",
                    "identity.compartments", "compartmentId",
                    "{compartmentId}"))
    rules.append(r(csp, "oci.identity", "identity.groups", "member_of",
                    "identity.compartments", "compartmentId",
                    "{compartmentId}"))

    # --- Logging ---
    rules.append(r(csp, "oci.logging", "logging.logs", "logging_enabled_to",
                    "logging.loggroups", "logGroupId",
                    "{logGroupId}"))

    # --- DNS ---
    rules.append(r(csp, "oci.dns", "dns.zones", "resolves_to",
                    "core.vcns", "viewId",
                    "{viewId}"))

    # --- WAF ---
    rules.append(r(csp, "oci.waas", "waas.waaspolicies", "attached_to",
                    "loadbalancer.loadbalancers", "loadBalancerId",
                    "{loadBalancerId}"))

    return rules


# ============================================================================
# IBM CLOUD RELATIONSHIP RULES
# ============================================================================

def generate_ibm_rules() -> List[Dict]:
    """Generate relationship rules for IBM Cloud."""
    rules = []
    csp = "ibm"

    # --- VPC ---
    # Instance → Subnet
    rules.append(r(csp, "ibm.is", "is.instances", "contained_by",
                    "is.subnets", "primary_network_interface.subnet.id",
                    "{primary_network_interface.subnet.id}"))
    # Instance → VPC
    rules.append(r(csp, "ibm.is", "is.instances", "contained_by",
                    "is.vpcs", "vpc.id",
                    "{vpc.id}"))
    # Instance → Security Group
    rules.append(r(csp, "ibm.is", "is.instances", "attached_to",
                    "is.securitygroups", "primary_network_interface.security_groups[].id",
                    "{primary_network_interface.security_groups[].id}"))
    # Instance → Image
    rules.append(r(csp, "ibm.is", "is.instances", "uses",
                    "is.images", "image.id",
                    "{image.id}"))
    # Instance → Volume
    rules.append(r(csp, "ibm.is", "is.instances", "uses",
                    "is.volumes", "volume_attachments[].volume.id",
                    "{volume_attachments[].volume.id}"))
    # Instance → SSH Key
    rules.append(r(csp, "ibm.is", "is.instances", "uses",
                    "is.keys", "keys[].id",
                    "{keys[].id}"))
    # Instance → Placement Group
    rules.append(r(csp, "ibm.is", "is.instances", "member_of",
                    "is.placementgroups", "placement_target.id",
                    "{placement_target.id}"))

    # Subnet → VPC
    rules.append(r(csp, "ibm.is", "is.subnets", "contained_by",
                    "is.vpcs", "vpc.id",
                    "{vpc.id}"))
    # Subnet → Network ACL
    rules.append(r(csp, "ibm.is", "is.subnets", "attached_to",
                    "is.networkacls", "network_acl.id",
                    "{network_acl.id}"))
    # Subnet → Public Gateway
    rules.append(r(csp, "ibm.is", "is.subnets", "attached_to",
                    "is.publicgateways", "public_gateway.id",
                    "{public_gateway.id}"))
    # Subnet → Routing Table
    rules.append(r(csp, "ibm.is", "is.subnets", "routes_to",
                    "is.vpcroutes", "routing_table.id",
                    "{routing_table.id}"))

    # Security Group → VPC
    rules.append(r(csp, "ibm.is", "is.securitygroups", "contained_by",
                    "is.vpcs", "vpc.id",
                    "{vpc.id}"))
    # Network ACL → VPC
    rules.append(r(csp, "ibm.is", "is.networkacls", "contained_by",
                    "is.vpcs", "vpc.id",
                    "{vpc.id}"))
    # Public Gateway → VPC
    rules.append(r(csp, "ibm.is", "is.publicgateways", "contained_by",
                    "is.vpcs", "vpc.id",
                    "{vpc.id}"))
    # Public Gateway → Floating IP
    rules.append(r(csp, "ibm.is", "is.publicgateways", "attached_to",
                    "is.floatingips", "floating_ip.id",
                    "{floating_ip.id}"))

    # Floating IP → Instance
    rules.append(r(csp, "ibm.is", "is.floatingips", "attached_to",
                    "is.instances", "target.id",
                    "{target.id}"))

    # Volume → Encryption Key
    rules.append(r(csp, "ibm.is", "is.volumes", "encrypted_by",
                    "kms.keys", "encryption_key.crn",
                    "{encryption_key.crn}"))

    # --- Load Balancer ---
    rules.append(r(csp, "ibm.is", "is.loadbalancers", "contained_by",
                    "is.subnets", "subnets[].id",
                    "{subnets[].id}"))
    rules.append(r(csp, "ibm.is", "is.loadbalancers", "attached_to",
                    "is.securitygroups", "security_groups[].id",
                    "{security_groups[].id}"))

    # --- VPN ---
    rules.append(r(csp, "ibm.is", "is.vpngateways", "contained_by",
                    "is.subnets", "subnet.id",
                    "{subnet.id}"))

    # --- Container / Kubernetes ---
    rules.append(r(csp, "ibm.containers", "containers.clusters", "contained_by",
                    "is.vpcs", "vpcs[]",
                    "{vpcs[]}"))

    # --- Cloud Object Storage ---
    rules.append(r(csp, "ibm.cos", "cos.buckets", "encrypted_by",
                    "kms.keys", "crn_key",
                    "{crn_key}"))

    # --- KMS (Key Protect) ---
    rules.append(r(csp, "ibm.kms", "kms.keys", "contained_by",
                    "kms.instances", "instance_id",
                    "{instance_id}"))

    # --- IAM ---
    rules.append(r(csp, "ibm.iam", "iam.accessgroups", "has_policy",
                    "iam.policies", "policies[].id",
                    "{policies[].id}"))
    rules.append(r(csp, "ibm.iam", "iam.serviceids", "assumes",
                    "iam.policies", "policies[].id",
                    "{policies[].id}"))

    # --- Transit Gateway ---
    rules.append(r(csp, "ibm.transitgateway", "transitgateway.gateways", "connected_to",
                    "is.vpcs", "connections[].network_id",
                    "{connections[].network_id}"))

    # --- Activity Tracker ---
    rules.append(r(csp, "ibm.atracker", "atracker.routes", "logging_enabled_to",
                    "cos.buckets", "rules[].targets[].cos_endpoint.bucket",
                    "{rules[].targets[].cos_endpoint.bucket}"))

    # --- Databases ---
    rules.append(r(csp, "ibm.databases", "databases.deployments", "encrypted_by",
                    "kms.keys", "key_protect_key.id",
                    "{key_protect_key.id}"))

    return rules


# ============================================================================
# ALICLOUD RELATIONSHIP RULES
# ============================================================================

def generate_alicloud_rules() -> List[Dict]:
    """Generate relationship rules for Alibaba Cloud."""
    rules = []
    csp = "alicloud"

    # --- ECS (Compute) ---
    rules.append(r(csp, "alicloud.ecs", "ecs.instances", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.instances", "contained_by",
                    "vpc.vswitches", "VSwitchId",
                    "{VSwitchId}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.instances", "attached_to",
                    "ecs.securitygroups", "SecurityGroupIds[]",
                    "{SecurityGroupIds[]}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.instances", "uses",
                    "ecs.images", "ImageId",
                    "{ImageId}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.instances", "uses",
                    "ecs.keypairs", "KeyPairName",
                    "{KeyPairName}"))
    # ECS → Disk
    rules.append(r(csp, "alicloud.ecs", "ecs.disks", "attached_to",
                    "ecs.instances", "InstanceId",
                    "{InstanceId}"))
    # ECS → KMS Key
    rules.append(r(csp, "alicloud.ecs", "ecs.disks", "encrypted_by",
                    "kms.keys", "KMSKeyId",
                    "{KMSKeyId}"))
    # ECS → ENI
    rules.append(r(csp, "alicloud.ecs", "ecs.networkinterfaces", "attached_to",
                    "ecs.instances", "InstanceId",
                    "{InstanceId}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.networkinterfaces", "contained_by",
                    "vpc.vswitches", "VSwitchId",
                    "{VSwitchId}"))
    rules.append(r(csp, "alicloud.ecs", "ecs.networkinterfaces", "attached_to",
                    "ecs.securitygroups", "SecurityGroupId",
                    "{SecurityGroupId}"))
    # Snapshot → Disk
    rules.append(r(csp, "alicloud.ecs", "ecs.snapshots", "backs_up_to",
                    "ecs.disks", "SourceDiskId",
                    "{SourceDiskId}"))

    # --- VPC ---
    rules.append(r(csp, "alicloud.vpc", "vpc.vswitches", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.vpc", "vpc.routetables", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    # NAT Gateway → VPC
    rules.append(r(csp, "alicloud.vpc", "vpc.natgateways", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    # EIP → Instance
    rules.append(r(csp, "alicloud.vpc", "vpc.eips", "attached_to",
                    "ecs.instances", "InstanceId",
                    "{InstanceId}"))

    # --- SLB (Load Balancer) ---
    rules.append(r(csp, "alicloud.slb", "slb.loadbalancers", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.slb", "slb.loadbalancers", "contained_by",
                    "vpc.vswitches", "VSwitchId",
                    "{VSwitchId}"))
    rules.append(r(csp, "alicloud.slb", "slb.loadbalancers", "serves_traffic_for",
                    "ecs.instances", "BackendServers[].ServerId",
                    "{BackendServers[].ServerId}"))

    # --- ALB ---
    rules.append(r(csp, "alicloud.alb", "alb.loadbalancers", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))

    # --- ACK (Container Service) ---
    rules.append(r(csp, "alicloud.ack", "ack.clusters", "contained_by",
                    "vpc.vpcs", "vpc_id",
                    "{vpc_id}"))
    rules.append(r(csp, "alicloud.ack", "ack.clusters", "contained_by",
                    "vpc.vswitches", "vswitch_id",
                    "{vswitch_id}"))

    # --- OSS (Object Storage) ---
    rules.append(r(csp, "alicloud.oss", "oss.buckets", "encrypted_by",
                    "kms.keys", "ServerSideEncryptionRule.KMSMasterKeyID",
                    "{ServerSideEncryptionRule.KMSMasterKeyID}"))
    rules.append(r(csp, "alicloud.oss", "oss.buckets", "logging_enabled_to",
                    "oss.buckets", "BucketLoggingStatus.TargetBucket",
                    "{BucketLoggingStatus.TargetBucket}"))

    # --- RDS ---
    rules.append(r(csp, "alicloud.rds", "rds.instances", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.rds", "rds.instances", "contained_by",
                    "vpc.vswitches", "VSwitchId",
                    "{VSwitchId}"))
    rules.append(r(csp, "alicloud.rds", "rds.instances", "attached_to",
                    "ecs.securitygroups", "SecurityGroupId",
                    "{SecurityGroupId}"))

    # --- Redis ---
    rules.append(r(csp, "alicloud.r_kvstore", "r_kvstore.instances", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.r_kvstore", "r_kvstore.instances", "contained_by",
                    "vpc.vswitches", "VSwitchId",
                    "{VSwitchId}"))

    # --- RAM (IAM) ---
    rules.append(r(csp, "alicloud.ram", "ram.users", "member_of",
                    "ram.groups", "GroupName",
                    "{GroupName}"))
    rules.append(r(csp, "alicloud.ram", "ram.roles", "has_policy",
                    "ram.policies", "PolicyName",
                    "{PolicyName}"))

    # --- KMS ---
    rules.append(r(csp, "alicloud.kms", "kms.aliases", "attached_to",
                    "kms.keys", "KeyId",
                    "{KeyId}"))

    # --- CDN ---
    rules.append(r(csp, "alicloud.cdn", "cdn.domains", "serves_traffic_for",
                    "oss.buckets", "Sources[].Content",
                    "{Sources[].Content}"))

    # --- ActionTrail (Audit) ---
    rules.append(r(csp, "alicloud.actiontrail", "actiontrail.trails", "logging_enabled_to",
                    "oss.buckets", "OssBucketName",
                    "{OssBucketName}"))

    # --- Cloud Firewall ---
    rules.append(r(csp, "alicloud.cloudfw", "cloudfw.rules", "allows_traffic_from",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))

    # --- EventBridge ---
    rules.append(r(csp, "alicloud.eventbridge", "eventbridge.rules", "triggers",
                    "ecs.instances", "Targets[].Endpoint",
                    "{Targets[].Endpoint}"))

    # --- ESS (Auto Scaling) ---
    rules.append(r(csp, "alicloud.ess", "ess.scalinggroups", "contained_by",
                    "vpc.vpcs", "VpcId",
                    "{VpcId}"))
    rules.append(r(csp, "alicloud.ess", "ess.scalinggroups", "serves_traffic_for",
                    "slb.loadbalancers", "LoadBalancerIds[]",
                    "{LoadBalancerIds[]}"))

    return rules


# ============================================================================
# KUBERNETES RELATIONSHIP RULES
# ============================================================================

def generate_k8s_rules() -> List[Dict]:
    """Generate relationship rules for Kubernetes."""
    rules = []
    csp = "k8s"

    # --- Pods ---
    # Pod → Node
    rules.append(r(csp, "k8s.core", "core.pods", "runs_on",
                    "core.nodes", "spec.nodeName",
                    "{spec.nodeName}"))
    # Pod → Service Account
    rules.append(r(csp, "k8s.core", "core.pods", "assumes",
                    "core.serviceaccounts", "spec.serviceAccountName",
                    "{spec.serviceAccountName}"))
    # Pod → ConfigMap
    rules.append(r(csp, "k8s.core", "core.pods", "uses",
                    "core.configmaps", "spec.volumes[].configMap.name",
                    "{spec.volumes[].configMap.name}"))
    # Pod → Secret
    rules.append(r(csp, "k8s.core", "core.pods", "uses",
                    "core.secrets", "spec.volumes[].secret.secretName",
                    "{spec.volumes[].secret.secretName}"))
    # Pod → PVC
    rules.append(r(csp, "k8s.core", "core.pods", "uses",
                    "core.persistentvolumeclaims", "spec.volumes[].persistentVolumeClaim.claimName",
                    "{spec.volumes[].persistentVolumeClaim.claimName}"))
    # Pod → Container Image
    rules.append(r(csp, "k8s.core", "core.pods", "uses",
                    "core.images", "spec.containers[].image",
                    "{spec.containers[].image}"))
    # Pod → Namespace
    rules.append(r(csp, "k8s.core", "core.pods", "contained_by",
                    "core.namespaces", "metadata.namespace",
                    "{metadata.namespace}"))

    # --- Services ---
    # Service → Pods (via selector - tracked as label match)
    rules.append(r(csp, "k8s.core", "core.services", "serves_traffic_for",
                    "core.pods", "spec.selector",
                    "{spec.selector}"))
    # Service → Namespace
    rules.append(r(csp, "k8s.core", "core.services", "contained_by",
                    "core.namespaces", "metadata.namespace",
                    "{metadata.namespace}"))

    # --- Deployments / ReplicaSets / StatefulSets ---
    # Deployment → ReplicaSet
    rules.append(r(csp, "k8s.apps", "apps.deployments", "manages",
                    "apps.replicasets", "metadata.uid",
                    "{metadata.ownerReferences[].uid}"))
    # Deployment → Namespace
    rules.append(r(csp, "k8s.apps", "apps.deployments", "contained_by",
                    "core.namespaces", "metadata.namespace",
                    "{metadata.namespace}"))
    # ReplicaSet → Pod
    rules.append(r(csp, "k8s.apps", "apps.replicasets", "manages",
                    "core.pods", "metadata.uid",
                    "{metadata.ownerReferences[].uid}"))
    # StatefulSet → PVC
    rules.append(r(csp, "k8s.apps", "apps.statefulsets", "uses",
                    "core.persistentvolumeclaims", "spec.volumeClaimTemplates[].metadata.name",
                    "{spec.volumeClaimTemplates[].metadata.name}"))
    # DaemonSet → Pod
    rules.append(r(csp, "k8s.apps", "apps.daemonsets", "manages",
                    "core.pods", "metadata.uid",
                    "{metadata.ownerReferences[].uid}"))

    # --- Storage ---
    # PVC → PV
    rules.append(r(csp, "k8s.core", "core.persistentvolumeclaims", "uses",
                    "core.persistentvolumes", "spec.volumeName",
                    "{spec.volumeName}"))
    # PVC → StorageClass
    rules.append(r(csp, "k8s.core", "core.persistentvolumeclaims", "uses",
                    "storage.storageclasses", "spec.storageClassName",
                    "{spec.storageClassName}"))

    # --- Ingress ---
    # Ingress → Service
    rules.append(r(csp, "k8s.networking", "networking.ingresses", "routes_to",
                    "core.services", "spec.rules[].http.paths[].backend.service.name",
                    "{spec.rules[].http.paths[].backend.service.name}"))
    # Ingress → TLS Secret
    rules.append(r(csp, "k8s.networking", "networking.ingresses", "uses",
                    "core.secrets", "spec.tls[].secretName",
                    "{spec.tls[].secretName}"))
    # Ingress → IngressClass
    rules.append(r(csp, "k8s.networking", "networking.ingresses", "uses",
                    "networking.ingressclasses", "spec.ingressClassName",
                    "{spec.ingressClassName}"))

    # --- NetworkPolicy ---
    rules.append(r(csp, "k8s.networking", "networking.networkpolicies", "allows_traffic_from",
                    "core.pods", "spec.podSelector",
                    "{spec.podSelector}"))
    rules.append(r(csp, "k8s.networking", "networking.networkpolicies", "contained_by",
                    "core.namespaces", "metadata.namespace",
                    "{metadata.namespace}"))

    # --- RBAC ---
    # RoleBinding → Role
    rules.append(r(csp, "k8s.rbac", "rbac.rolebindings", "grants_access_to",
                    "rbac.roles", "roleRef.name",
                    "{roleRef.name}"))
    # RoleBinding → ServiceAccount
    rules.append(r(csp, "k8s.rbac", "rbac.rolebindings", "grants_access_to",
                    "core.serviceaccounts", "subjects[].name",
                    "{subjects[].name}"))
    # ClusterRoleBinding → ClusterRole
    rules.append(r(csp, "k8s.rbac", "rbac.clusterrolebindings", "grants_access_to",
                    "rbac.clusterroles", "roleRef.name",
                    "{roleRef.name}"))
    # ClusterRoleBinding → ServiceAccount
    rules.append(r(csp, "k8s.rbac", "rbac.clusterrolebindings", "grants_access_to",
                    "core.serviceaccounts", "subjects[].name",
                    "{subjects[].name}"))

    # --- CronJob / Job ---
    rules.append(r(csp, "k8s.batch", "batch.cronjobs", "triggers",
                    "batch.jobs", "metadata.uid",
                    "{metadata.ownerReferences[].uid}"))
    rules.append(r(csp, "k8s.batch", "batch.jobs", "manages",
                    "core.pods", "metadata.uid",
                    "{metadata.ownerReferences[].uid}"))

    # --- HPA ---
    rules.append(r(csp, "k8s.autoscaling", "autoscaling.horizontalpodautoscalers", "scales_with",
                    "apps.deployments", "spec.scaleTargetRef.name",
                    "{spec.scaleTargetRef.name}"))

    return rules


# ============================================================================
# HELPER
# ============================================================================

def r(csp_id: str, service_id: str, from_type: str, relation_type: str,
      to_type: str, source_field: str, target_uid_pattern: str,
      source_field_item: str = None) -> Dict:
    """Create a relationship rule dict."""
    return {
        "csp_id": csp_id,
        "service_id": service_id,
        "from_type": from_type,
        "relation_type": relation_type,
        "to_type": to_type,
        "source_field": source_field,
        "target_uid_pattern": target_uid_pattern,
        "source_field_item": source_field_item,
    }


def insert_rules(conn, rules: List[Dict], csp_id: str):
    """Insert rules into the relationship_rules table."""
    # Delete existing rules for this CSP first
    with conn.cursor() as cur:
        cur.execute("DELETE FROM relationship_rules WHERE csp_id = %s", (csp_id,))
        deleted = cur.rowcount
        if deleted:
            print(f"  Deleted {deleted} existing {csp_id} rules")

    # Insert new rules
    insert_sql = """
        INSERT INTO relationship_rules
        (csp_id, service_id, from_type, relation_type, to_type,
         source_field, target_uid_pattern, source_field_item, version)
        VALUES %s
        ON CONFLICT ON CONSTRAINT uq_rel_rule DO UPDATE SET
            target_uid_pattern = EXCLUDED.target_uid_pattern,
            source_field_item = EXCLUDED.source_field_item,
            version = EXCLUDED.version
    """

    values = [
        (
            rule["csp_id"],
            rule["service_id"],
            rule["from_type"],
            rule["relation_type"],
            rule["to_type"],
            rule["source_field"],
            rule["target_uid_pattern"],
            rule.get("source_field_item"),
            "1.0"
        )
        for rule in rules
    ]

    with conn.cursor() as cur:
        execute_values(cur, insert_sql, values,
                       template="(%s, %s, %s, %s, %s, %s, %s, %s, %s)")
    conn.commit()
    print(f"  Inserted {len(values)} {csp_id} rules")


def main():
    conn = get_conn()

    generators = {
        "azure": generate_azure_rules,
        "gcp": generate_gcp_rules,
        "oci": generate_oci_rules,
        "ibm": generate_ibm_rules,
        "alicloud": generate_alicloud_rules,
        "k8s": generate_k8s_rules,
    }

    # If specific CSPs requested via args, only generate those
    target_csps = sys.argv[1:] if len(sys.argv) > 1 else list(generators.keys())

    total = 0
    for csp_id in target_csps:
        if csp_id not in generators:
            print(f"Unknown CSP: {csp_id}")
            continue
        print(f"\n--- {csp_id.upper()} ---")
        rules = generators[csp_id]()
        print(f"  Generated {len(rules)} rules")
        insert_rules(conn, rules, csp_id)
        total += len(rules)

    # Print final summary
    print(f"\n{'='*60}")
    print(f"TOTAL: {total} rules generated across {len(target_csps)} CSPs")

    # Show final DB state
    with conn.cursor() as cur:
        cur.execute("""
            SELECT csp_id, COUNT(*) as rule_count,
                   COUNT(DISTINCT service_id) as services,
                   COUNT(DISTINCT relation_type) as relation_types
            FROM relationship_rules
            GROUP BY csp_id ORDER BY csp_id
        """)
        rows = cur.fetchall()
    print(f"\nDB State:")
    print(f"{'CSP':<12} {'Rules':>6} {'Services':>9} {'RelTypes':>9}")
    print("-" * 40)
    grand_total = 0
    for row in rows:
        print(f"{row[0]:<12} {row[1]:>6} {row[2]:>9} {row[3]:>9}")
        grand_total += row[1]
    print("-" * 40)
    print(f"{'TOTAL':<12} {grand_total:>6}")

    conn.close()


if __name__ == "__main__":
    main()
