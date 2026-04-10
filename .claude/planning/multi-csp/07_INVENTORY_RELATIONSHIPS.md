# Inventory Security Relationships — All CSPs

## Current State

Table: `resource_security_relationship_rules` (2,055 rows, AWS only)
Table: `architecture_relationship_rules` (164 rows, orphaned — not used by pipeline)

The inventory engine uses `resource_security_relationship_rules` to build the
security graph in Neo4j. Every non-AWS CSP is missing entries.

## Design Principles

1. Only security-relevant relationships — not management or operational ones
2. Relationship types align to MITRE ATT&CK:
   - EXPOSES (attack surface)
   - ACCESSES (privilege chain)
   - ENCRYPTS / PROTECTED_BY (data protection)
   - ROUTES_TO (network path)
   - CONTAINS (blast radius)
   - AUTHENTICATES_VIA (identity chain)
3. All rules have provider column — `WHERE provider='azure'` etc.
4. Sub-services link to parent: StorageAccount CONTAINS BlobContainer

## Azure Security Relationships (to add)

Priority rules for `resource_security_relationship_rules`:

| parent_type | child_type | relationship_type | link_field | provider |
|---|---|---|---|---|
| VirtualMachine | NetworkInterface | ROUTES_TO | vm.networkInterfaces[].id | azure |
| NetworkInterface | NetworkSecurityGroup | PROTECTED_BY | nic.networkSecurityGroup.id | azure |
| NetworkSecurityGroup | Subnet | PROTECTS | nsg.subnets[].id | azure |
| VirtualMachine | ManagedDisk | CONTAINS | vm.storageProfile.osDisk.managedDisk.id | azure |
| StorageAccount | BlobContainer | CONTAINS | container.storageAccount | azure |
| StorageAccount | PrivateEndpointConnection | PROTECTED_BY | storage.privateEndpointConnections[].id | azure |
| KeyVault | Secret | CONTAINS | secret.vaultUri | azure |
| KeyVault | Key | CONTAINS | key.kid | azure |
| AppService | ManagedIdentity | AUTHENTICATES_VIA | app.identity.principalId | azure |
| ServicePrincipal | RoleAssignment | ACCESSES | sp.id | azure |
| AKSCluster | NodePool | CONTAINS | pool.clusterId | azure |
| AKSCluster | ManagedIdentity | AUTHENTICATES_VIA | aks.identity.principalId | azure |
| LoadBalancer | BackendPool | ROUTES_TO | lb.backendAddressPools[].id | azure |
| VirtualNetwork | Subnet | CONTAINS | subnet.virtualNetwork.id | azure |
| Subnet | NetworkSecurityGroup | PROTECTED_BY | subnet.networkSecurityGroup.id | azure |

## GCP Security Relationships (to add)

| parent_type | child_type | relationship_type | link_field | provider |
|---|---|---|---|---|
| GCEInstance | ServiceAccount | AUTHENTICATES_VIA | instance.serviceAccounts[].email | gcp |
| GCEInstance | FirewallRule | PROTECTED_BY | firewall.targetTags → instance.tags | gcp |
| FirewallRule | VPCNetwork | CONTAINS | firewall.network | gcp |
| GKECluster | NodePool | CONTAINS | nodepool.cluster | gcp |
| GKECluster | ServiceAccount | AUTHENTICATES_VIA | cluster.nodeConfig.serviceAccount | gcp |
| CloudFunction | ServiceAccount | AUTHENTICATES_VIA | function.serviceAccountEmail | gcp |
| CloudRunService | ServiceAccount | AUTHENTICATES_VIA | service.spec.template.serviceAccountName | gcp |
| CloudSQLInstance | VPCNetwork | ROUTES_TO | instance.ipConfiguration.privateNetwork | gcp |
| StorageBucket | IAMPolicy | PROTECTED_BY | bucket.iamConfiguration | gcp |
| BigQueryDataset | IAMPolicy | PROTECTED_BY | dataset.access | gcp |
| KMSKeyRing | CryptoKey | CONTAINS | key.name | gcp |
| VPCNetwork | Subnet | CONTAINS | subnet.network | gcp |
| Project | IAMPolicy | PROTECTED_BY | policy.resourceId | gcp |

## Kubernetes Security Relationships (to add)

| parent_type | child_type | relationship_type | link_field | provider |
|---|---|---|---|---|
| Pod | ServiceAccount | AUTHENTICATES_VIA | pod.spec.serviceAccountName | k8s |
| Pod | Node | CONTAINS | pod.spec.nodeName | k8s |
| Pod | Secret | ACCESSES | pod.spec.volumes[].secret | k8s |
| Pod | ConfigMap | ACCESSES | pod.spec.volumes[].configMap | k8s |
| ClusterRoleBinding | ClusterRole | ACCESSES | binding.roleRef.name | k8s |
| ClusterRoleBinding | ServiceAccount | GRANTS | binding.subjects[].name | k8s |
| RoleBinding | Role | ACCESSES | binding.roleRef.name | k8s |
| ServiceAccount | Secret | CONTAINS | sa.secrets[].name | k8s |
| Namespace | NetworkPolicy | PROTECTED_BY | policy.namespace | k8s |
| Ingress | Service | EXPOSES | ingress.spec.rules[].http.paths[].service | k8s |
| Service | Pod | ROUTES_TO | service.selector | k8s |
| Deployment | Pod | CONTAINS | pod.ownerReferences[].name | k8s |

## OCI Security Relationships (to add, when creds available)

| parent_type | child_type | relationship_type | link_field | provider |
|---|---|---|---|---|
| Instance | VCN | ROUTES_TO | instance.subnetId | oci |
| Instance | BootVolume | CONTAINS | instance.bootVolumeId | oci |
| Subnet | SecurityList | PROTECTED_BY | subnet.securityListIds[] | oci |
| Subnet | NetworkSecurityGroup | PROTECTED_BY | nsg.subnetId | oci |
| Bucket | Policy | PROTECTED_BY | bucket.policyName | oci |
| DBSystem | VCN | ROUTES_TO | db.subnetId | oci |
| User | Group | CONTAINS | groupMembership.userId | oci |
| Group | Policy | ACCESSES | policy.compartmentId | oci |

## Implementation Task

For each CSP, the implementation is:

1. Write SQL INSERT statements for all relationship rules
2. Add to `consolidated_services/database/schemas/inventory_schema.sql` as seed data
3. Test inventory engine correctly resolves relationships for new provider
4. Verify Neo4j graph contains correct edges after scan

## Asset Classification Rules (per CSP)

The `service_classification` table controls what appears in the Assets tab:

Rules:
- ASSET: Has a resource_uid, is a persistent resource (VM, DB, storage, network)
- NOT ASSET: Ephemeral, metadata-only, or sub-resource without independent lifecycle

### Azure Asset Types (keep in Assets tab)
VirtualMachine, StorageAccount, SQLServer, KeyVault, VirtualNetwork,
NetworkSecurityGroup, AppService, AKSCluster, CosmosDB, LoadBalancer,
ApplicationGateway, Subnet, ManagedDisk, ContainerRegistry

### GCP Asset Types
GCEInstance, CloudSQLInstance, GCSBucket, GKECluster, CloudFunction,
CloudRunService, VPCNetwork, KMSKeyRing, BigQueryDataset, PubSubTopic,
CloudSpanner, MemoryStore, ArtifactRegistry

### K8s Asset Types
Pod, Deployment, Service, Namespace, Node, ServiceAccount, ClusterRole,
ClusterRoleBinding, NetworkPolicy, Ingress, ConfigMap, Secret (count only)

### OCI Asset Types
Instance, BootVolume, BlockVolume, VCN, Subnet, Bucket, DBSystem,
AutonomousDatabase, LoadBalancer, Function