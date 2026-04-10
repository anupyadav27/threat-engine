---
story_id: AZ-06
title: Seed Azure Inventory Relationship Rules
status: done
sprint: azure-track-wave-1
depends_on: []
blocks: [AZ-15b]
sme: DBA + Security analyst
estimate: 0.5 days
---

# Story: Seed Azure Inventory Relationship Rules

## Context
The inventory engine builds a security graph by joining `inventory_relationships` (actual resource connections) with `resource_security_relationship_rules` (security-typed relationship definitions). Currently 2,055 rows exist for AWS only. Azure has 0 rows.

This is a **HARD prerequisite** (migration gate) — the inventory engine cannot build Azure security edges, blast radius, or attack paths without these rows. Must be deployed before the Azure pipeline is declared production-ready (AZ-15b).

## Files to Create

- `consolidated_services/database/migrations/seed_azure_relationships.sql`

## SQL Content

```sql
-- Azure Security Relationship Rules
-- 15 rows covering the primary attack paths in Azure environments

INSERT INTO resource_security_relationship_rules
  (parent_type, child_type, relationship_type, link_field, provider, attack_path_category, description)
VALUES
  ('VirtualMachine',    'NetworkInterface',             'ROUTES_TO',         'vm.networkInterfaces[].id',                          'azure', 'network_path',      'VM network interface attachment'),
  ('NetworkInterface',  'NetworkSecurityGroup',         'PROTECTED_BY',      'nic.networkSecurityGroup.id',                        'azure', 'defense_bypass',    'NIC-level NSG controls inbound/outbound'),
  ('NetworkSecurityGroup','Subnet',                     'PROTECTS',          'nsg.subnets[].id',                                   'azure', 'defense_bypass',    'NSG applied at subnet scope'),
  ('VirtualMachine',    'ManagedDisk',                  'CONTAINS',          'vm.storageProfile.osDisk.managedDisk.id',            'azure', 'data_access',       'OS disk attached to VM'),
  ('StorageAccount',    'BlobContainer',                'CONTAINS',          'container.storageAccount',                           'azure', 'data_access',       'Blob containers within storage account'),
  ('StorageAccount',    'PrivateEndpointConnection',    'PROTECTED_BY',      'storage.privateEndpointConnections[].id',            'azure', 'network_path',      'Private endpoint restricts public access'),
  ('KeyVault',          'Secret',                       'CONTAINS',          'secret.vaultUri',                                    'azure', 'credential_access', 'Secrets stored in Key Vault'),
  ('KeyVault',          'Key',                          'CONTAINS',          'key.kid',                                            'azure', 'credential_access', 'Encryption keys stored in Key Vault'),
  ('AppService',        'ManagedIdentity',              'AUTHENTICATES_VIA', 'app.identity.principalId',                           'azure', 'privilege_escalation','App Service uses managed identity for auth'),
  ('ServicePrincipal',  'RoleAssignment',               'ACCESSES',          'sp.id',                                              'azure', 'privilege_escalation','SP role assignments define access scope'),
  ('AKSCluster',        'NodePool',                     'CONTAINS',          'pool.clusterId',                                     'azure', 'lateral_movement',  'AKS node pools within cluster'),
  ('AKSCluster',        'ManagedIdentity',              'AUTHENTICATES_VIA', 'aks.identity.principalId',                           'azure', 'privilege_escalation','AKS cluster managed identity'),
  ('LoadBalancer',      'BackendPool',                  'ROUTES_TO',         'lb.backendAddressPools[].id',                        'azure', 'network_path',      'Load balancer routes to backend pool'),
  ('VirtualNetwork',    'Subnet',                       'CONTAINS',          'subnet.virtualNetwork.id',                           'azure', 'network_path',      'Subnets within virtual network'),
  ('Subnet',            'NetworkSecurityGroup',         'PROTECTED_BY',      'subnet.networkSecurityGroup.id',                     'azure', 'defense_bypass',    'NSG applied to subnet')
ON CONFLICT (parent_type, child_type, provider) DO UPDATE SET
  relationship_type    = EXCLUDED.relationship_type,
  link_field           = EXCLUDED.link_field,
  attack_path_category = EXCLUDED.attack_path_category,
  description          = EXCLUDED.description,
  updated_at           = NOW();
```

## Acceptance Criteria
- [ ] `SELECT COUNT(*) FROM resource_security_relationship_rules WHERE provider='azure'` = 15
- [ ] All 15 rows have non-null `attack_path_category`
- [ ] SQL is idempotent (safe to re-run — uses ON CONFLICT DO UPDATE)
- [ ] Migration file exists at correct path

## Definition of Done
- [ ] SQL file created and reviewed by security analyst
- [ ] Applied to dev/staging DB
- [ ] `attack_path_category` values reviewed: covers network_path, defense_bypass, data_access, credential_access, privilege_escalation, lateral_movement