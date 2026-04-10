#!/usr/bin/env python3
"""
Seed architecture_relationship_rules for Azure, GCP, OCI, IBM.
AWS rules are already seeded by create_architecture_tables.py.

Usage:
    python scripts/seed_csp_architecture_rules.py [--dry-run]
"""

import argparse
import os
import psycopg2
from psycopg2.extras import execute_values


def get_conn():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


# ══════════════════════════════════════════════════════════════════════
# GCP
# ══════════════════════════════════════════════════════════════════════
GCP_RULES = [
    # TOPOLOGY
    ("topology", "contains", "compute.networks", "compute.subnetworks", "network", None, None, 2, "none"),
    ("topology", "in_zone", "compute.subnetworks", "zone", "region", None, None, 2, "none"),
    ("topology", "peered_with", "compute.networks", "compute.networks", "peerings", "network", None, 2, "dashed"),
    ("topology", "has_firewall", "compute.networks", "compute.firewalls", "network", None, None, 2, "none"),

    # PLACEMENT
    ("placement", "in_subnet", "compute.instances", "compute.subnetworks", "networkInterfaces", "subnetwork", None, 3, "none"),
    ("placement", "in_network", "compute.instances", "compute.networks", "networkInterfaces", "network", None, 3, "none"),
    ("placement", "in_subnet", "sqladmin.instances", "compute.subnetworks", "settings.ipConfiguration.privateNetwork", None, None, 3, "none"),
    ("placement", "in_network", "container.clusters", "compute.networks", "network", None, None, 3, "none"),
    ("placement", "in_subnet", "container.clusters", "compute.subnetworks", "subnetwork", None, None, 3, "none"),
    ("placement", "in_subnet", "redis.instances", "compute.subnetworks", "authorizedNetwork", None, None, 3, "none"),
    ("placement", "in_network", "compute.forwardingRules", "compute.networks", "network", None, None, 3, "none"),
    ("placement", "in_subnet", "compute.forwardingRules", "compute.subnetworks", "subnetwork", None, None, 3, "none"),
    ("placement", "in_network", "run.services", "compute.networks", "template.metadata.annotations.run.googleapis.com/vpc-access-connector", None, None, 3, "none"),

    # COMPOSITION
    ("composition", "has_disk", "compute.instances", "compute.disks", "disks", "source", None, 3, "none"),
    ("composition", "has_sa", "compute.instances", "iam.serviceAccounts", "serviceAccounts", "email", None, 3, "none"),
    ("composition", "has_firewall", "compute.instances", "compute.firewalls", "tags.items", None, None, 3, "none"),
    ("composition", "has_node_pool", "container.clusters", "container.nodePools", None, None, None, 3, "none"),

    # DEPENDENCY
    ("dependency", "has_sa", "container.clusters", "iam.serviceAccounts", "nodeConfig.serviceAccount", None, None, 4, "dashed"),
    ("dependency", "has_sa", "cloudfunctions.functions", "iam.serviceAccounts", "serviceAccountEmail", None, None, 4, "dashed"),
    ("dependency", "has_sa", "run.services", "iam.serviceAccounts", "template.spec.serviceAccountName", None, None, 4, "dashed"),
    ("dependency", "encrypted_by", "compute.disks", "cloudkms.cryptoKeys", "diskEncryptionKey.kmsKeyName", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "storage.buckets", "cloudkms.cryptoKeys", "encryption.defaultKmsKeyName", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "sqladmin.instances", "cloudkms.cryptoKeys", "diskEncryptionConfiguration.kmsKeyName", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "bigtableadmin.instances", "cloudkms.cryptoKeys", "encryptionConfig.kmsKeyName", None, None, 4, "dotted"),
    ("dependency", "logs_to", "compute.instances", "storage.buckets", None, None, None, 4, "dotted"),

    # FLOW
    ("flow", "routes_to", "compute.forwardingRules", "compute.backendServices", "target", None, None, 5, "solid"),
    ("flow", "routes_to", "compute.backendServices", "compute.instances", "backends", "group", None, 5, "solid"),
    ("flow", "routes_to", "compute.globalForwardingRules", "compute.backendServices", "target", None, None, 5, "solid"),
    ("flow", "routes_to", "run.services", "sqladmin.instances", None, None, None, 5, "dashed"),
    ("flow", "routes_to", "cloudfunctions.functions", "storage.buckets", "sourceArchiveUrl", None, None, 5, "dashed"),
]

# ══════════════════════════════════════════════════════════════════════
# OCI
# ══════════════════════════════════════════════════════════════════════
OCI_RULES = [
    # TOPOLOGY
    ("topology", "contains", "core.vcn", "core.subnet", "vcnId", None, None, 2, "none"),
    ("topology", "attached_to", "core.vcn", "core.internet_gateway", "vcnId", None, None, 2, "solid"),
    ("topology", "attached_to", "core.vcn", "core.nat_gateway", "vcnId", None, None, 2, "solid"),
    ("topology", "attached_to", "core.vcn", "core.service_gateway", "vcnId", None, None, 2, "solid"),
    ("topology", "protected_by", "core.subnet", "core.security_list", "securityListIds", None, None, 2, "none"),
    ("topology", "protected_by", "core.subnet", "core.network_security_group", None, None, None, 2, "none"),
    ("topology", "peered_with", "core.vcn", "core.vcn", "localPeeringGateways", "peerId", None, 2, "dashed"),
    ("topology", "attached_to", "core.vcn", "core.drg", "drgAttachments", None, None, 2, "dashed"),

    # PLACEMENT
    ("placement", "in_subnet", "compute.instance", "core.subnet", "subnetId", None, None, 3, "none"),
    ("placement", "in_vcn", "compute.instance", "core.vcn", "vcnId", None, None, 3, "none"),
    ("placement", "in_subnet", "database.db_system", "core.subnet", "subnetId", None, None, 3, "none"),
    ("placement", "in_subnet", "database.autonomous_database", "core.subnet", "subnetId", None, None, 3, "none"),
    ("placement", "in_subnet", "container_engine.cluster", "core.subnet", "options.kubernetesNetworkConfig.podsCidrBlock", None, None, 3, "none"),
    ("placement", "in_subnet", "load_balancer.load_balancer", "core.subnet", "subnetIds", None, None, 3, "none"),
    ("placement", "in_subnet", "network_load_balancer.network_load_balancer", "core.subnet", "subnetId", None, None, 3, "none"),
    ("placement", "in_subnet", "functions.application", "core.subnet", "subnetIds", None, None, 3, "none"),
    ("placement", "in_subnet", "nosql.table", "core.subnet", None, None, None, 3, "none"),

    # COMPOSITION
    ("composition", "has_nsg", "compute.instance", "core.network_security_group", "nsgIds", None, None, 3, "none"),
    ("composition", "has_volume", "compute.instance", "block_storage.volume", "bootVolumeId", None, None, 3, "none"),
    ("composition", "has_vnic", "compute.instance", "core.vnic", "vnicAttachments", "vnicId", None, 3, "none"),
    ("composition", "has_nsg", "database.db_system", "core.network_security_group", "nsgIds", None, None, 3, "none"),
    ("composition", "has_nsg", "load_balancer.load_balancer", "core.network_security_group", "networkSecurityGroupIds", None, None, 3, "none"),

    # DEPENDENCY
    ("dependency", "encrypted_by", "block_storage.volume", "key_management.vault", "kmsKeyId", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "object_storage.bucket", "key_management.vault", "kmsKeyId", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "database.autonomous_database", "key_management.vault", "kmsKeyId", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "database.db_system", "key_management.vault", "kmsKeyId", None, None, 4, "dotted"),
    ("dependency", "logs_to", "core.vcn", "object_storage.bucket", "flowLogDestination", None, None, 4, "dotted"),

    # FLOW
    ("flow", "routes_to", "load_balancer.load_balancer", "compute.instance", "backendSets", None, None, 5, "solid"),
    ("flow", "routes_to", "network_load_balancer.network_load_balancer", "compute.instance", "backendSets", None, None, 5, "solid"),
    ("flow", "routes_to", "apigateway.gateway", "functions.function", "routes", None, None, 5, "solid"),
]

# ══════════════════════════════════════════════════════════════════════
# AZURE
# ══════════════════════════════════════════════════════════════════════
AZURE_RULES = [
    # TOPOLOGY
    ("topology", "contains", "network.virtualNetworks", "network.subnets", "subnets", "id", None, 2, "none"),
    ("topology", "peered_with", "network.virtualNetworks", "network.virtualNetworks", "virtualNetworkPeerings", "remoteVirtualNetwork.id", None, 2, "dashed"),
    ("topology", "protected_by", "network.subnets", "network.networkSecurityGroups", "networkSecurityGroup.id", None, None, 2, "none"),
    ("topology", "has_route_table", "network.subnets", "network.routeTables", "routeTable.id", None, None, 2, "none"),
    ("topology", "attached_to", "network.virtualNetworks", "network.virtualNetworkGateways", None, None, None, 2, "solid"),

    # PLACEMENT
    ("placement", "in_subnet", "compute.virtualMachines", "network.subnets", "networkProfile.networkInterfaces", None, None, 3, "none"),
    ("placement", "in_vnet", "compute.virtualMachines", "network.virtualNetworks", None, None, None, 3, "none"),
    ("placement", "in_subnet", "sql.servers", "network.subnets", "virtualNetworkRules", "virtualNetworkSubnetId", None, 3, "none"),
    ("placement", "in_subnet", "containerservice.managedClusters", "network.subnets", "agentPoolProfiles", "vnetSubnetID", None, 3, "none"),
    ("placement", "in_vnet", "containerservice.managedClusters", "network.virtualNetworks", "networkProfile.networkPlugin", None, None, 3, "none"),
    ("placement", "in_subnet", "web.sites", "network.subnets", "virtualNetworkSubnetId", None, None, 3, "none"),
    ("placement", "in_subnet", "dbforpostgresql.flexibleServers", "network.subnets", "network.delegatedSubnetResourceId", None, None, 3, "none"),
    ("placement", "in_subnet", "dbformysql.flexibleServers", "network.subnets", "network.delegatedSubnetResourceId", None, None, 3, "none"),
    ("placement", "in_subnet", "cache.redis", "network.subnets", "subnetId", None, None, 3, "none"),
    ("placement", "in_subnet", "network.loadBalancers", "network.subnets", "frontendIPConfigurations", "subnet.id", None, 3, "none"),
    ("placement", "in_subnet", "network.applicationGateways", "network.subnets", "gatewayIPConfigurations", "subnet.id", None, 3, "none"),
    ("placement", "in_subnet", "network.privateEndpoints", "network.subnets", "subnet.id", None, None, 3, "none"),

    # COMPOSITION
    ("composition", "has_nic", "compute.virtualMachines", "network.networkInterfaces", "networkProfile.networkInterfaces", "id", None, 3, "none"),
    ("composition", "has_nsg", "compute.virtualMachines", "network.networkSecurityGroups", None, None, None, 3, "none"),
    ("composition", "has_disk", "compute.virtualMachines", "compute.disks", "storageProfile.dataDisks", "managedDisk.id", None, 3, "none"),
    ("composition", "has_os_disk", "compute.virtualMachines", "compute.disks", "storageProfile.osDisk.managedDisk.id", None, None, 3, "none"),
    ("composition", "has_nsg", "network.networkInterfaces", "network.networkSecurityGroups", "networkSecurityGroup.id", None, None, 3, "none"),
    ("composition", "has_nsg", "containerservice.managedClusters", "network.networkSecurityGroups", None, None, None, 3, "none"),

    # DEPENDENCY
    ("dependency", "has_identity", "compute.virtualMachines", "msi.userAssignedIdentities", "identity.userAssignedIdentities", None, None, 4, "dashed"),
    ("dependency", "has_identity", "containerservice.managedClusters", "msi.userAssignedIdentities", "identity.userAssignedIdentities", None, None, 4, "dashed"),
    ("dependency", "has_identity", "web.sites", "msi.userAssignedIdentities", "identity.userAssignedIdentities", None, None, 4, "dashed"),
    ("dependency", "encrypted_by", "compute.disks", "keyvault.vaults", "encryption.diskEncryptionSetId", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "storage.storageAccounts", "keyvault.vaults", "encryption.keySource", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "sql.servers", "keyvault.vaults", "encryptionProtector", None, None, 4, "dotted"),
    ("dependency", "logs_to", "monitor.diagnosticSettings", "storage.storageAccounts", "storageAccountId", None, None, 4, "dotted"),
    ("dependency", "logs_to", "monitor.diagnosticSettings", "operationalinsights.workspaces", "workspaceId", None, None, 4, "dotted"),

    # FLOW
    ("flow", "routes_to", "network.loadBalancers", "compute.virtualMachines", "backendAddressPools", None, None, 5, "solid"),
    ("flow", "routes_to", "network.applicationGateways", "compute.virtualMachines", "backendAddressPools", None, None, 5, "solid"),
    ("flow", "routes_to", "network.applicationGateways", "web.sites", "backendAddressPools", None, None, 5, "solid"),
    ("flow", "routes_to", "cdn.profiles", "storage.storageAccounts", "origins", None, None, 5, "solid"),
    ("flow", "routes_to", "network.frontDoors", "web.sites", "backendPools", None, None, 5, "solid"),
    ("flow", "routes_to", "network.privateEndpoints", "storage.storageAccounts", "privateLinkServiceConnections", None, None, 5, "dashed"),
    ("flow", "routes_to", "network.privateEndpoints", "sql.servers", "privateLinkServiceConnections", None, None, 5, "dashed"),
]

# ══════════════════════════════════════════════════════════════════════
# IBM
# ══════════════════════════════════════════════════════════════════════
IBM_RULES = [
    # TOPOLOGY
    ("topology", "contains", "vpc.vpc", "vpc.subnet", "subnets", None, None, 2, "none"),
    ("topology", "attached_to", "vpc.vpc", "vpc.public_gateway", None, None, None, 2, "solid"),
    ("topology", "protected_by", "vpc.subnet", "vpc.network_acl", "networkAcl.id", None, None, 2, "none"),

    # PLACEMENT
    ("placement", "in_subnet", "vpc.instance", "vpc.subnet", "primaryNetworkInterface.subnet.id", None, None, 3, "none"),
    ("placement", "in_vpc", "vpc.instance", "vpc.vpc", "vpc.id", None, None, 3, "none"),
    ("placement", "in_subnet", "containers.cluster", "vpc.subnet", "workerPools", "zones.subnets.id", None, 3, "none"),
    ("placement", "in_subnet", "vpc.load_balancer", "vpc.subnet", "subnets", "id", None, 3, "none"),
    ("placement", "in_subnet", "databases.deployment", "vpc.subnet", None, None, None, 3, "none"),

    # COMPOSITION
    ("composition", "has_sg", "vpc.instance", "vpc.security_group", "networkInterfaces", "securityGroups.id", None, 3, "none"),
    ("composition", "has_volume", "vpc.instance", "vpc.volume", "volumeAttachments", "volume.id", None, 3, "none"),
    ("composition", "has_nic", "vpc.instance", "vpc.network_interface", "networkInterfaces", "id", None, 3, "none"),
    ("composition", "has_sg", "vpc.load_balancer", "vpc.security_group", "securityGroups", "id", None, 3, "none"),

    # DEPENDENCY
    ("dependency", "encrypted_by", "vpc.volume", "key_protect.key", "encryptionKey.crn", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "object_storage.bucket", "key_protect.key", "crn", None, None, 4, "dotted"),
    ("dependency", "encrypted_by", "databases.deployment", "key_protect.key", "keyProtectKey", None, None, 4, "dotted"),

    # FLOW
    ("flow", "routes_to", "vpc.load_balancer", "vpc.instance", "pools", "members", None, 5, "solid"),
    ("flow", "routes_to", "code_engine.app", "databases.deployment", None, None, None, 5, "dashed"),
]


ALL_CSP_RULES = {
    "gcp": GCP_RULES,
    "oci": OCI_RULES,
    "azure": AZURE_RULES,
    "ibm": IBM_RULES,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    conn = get_conn()
    cur = conn.cursor()

    for csp, rules in ALL_CSP_RULES.items():
        values = []
        for r in rules:
            cat, rtype, from_rt, to_rt, src_field, src_item, target_pat, layer, style = r
            values.append((
                csp, cat, rtype, from_rt, to_rt,
                src_field, src_item, target_pat, layer, style,
                None, None, False, True,
            ))

        if args.dry_run:
            print(f"{csp}: {len(values)} rules (dry run)")
            by_cat = {}
            for v in values:
                by_cat[v[1]] = by_cat.get(v[1], 0) + 1
            for c, n in sorted(by_cat.items()):
                print(f"  {c}: {n}")
            continue

        cur.execute("DELETE FROM architecture_relationship_rules WHERE csp = %s", (csp,))
        execute_values(cur, """
            INSERT INTO architecture_relationship_rules (
                csp, rel_category, rel_type, from_resource_type, to_resource_type,
                source_field, source_field_item, target_uid_pattern, arch_layer, line_style,
                line_color, line_label, bidirectional, is_active
            ) VALUES %s
        """, values, page_size=100)
        conn.commit()
        print(f"{csp}: {len(values)} rules inserted")

    if not args.dry_run:
        cur.execute("""
            SELECT csp, rel_category, count(*)
            FROM architecture_relationship_rules
            GROUP BY csp, rel_category
            ORDER BY csp, rel_category
        """)
        print("\nAll rules by CSP + category:")
        for r in cur.fetchall():
            print(f"  {r[0]:10s} {r[1]:15s} {r[2]}")

        cur.execute("SELECT csp, count(*) FROM architecture_relationship_rules GROUP BY csp ORDER BY csp")
        print("\nTotals:")
        total = 0
        for r in cur.fetchall():
            print(f"  {r[0]}: {r[1]}")
            total += r[1]
        print(f"  TOTAL: {total}")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
