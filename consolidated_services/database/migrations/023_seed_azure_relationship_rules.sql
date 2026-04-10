-- Migration: 023_seed_azure_relationship_rules.sql
-- Date: 2026-04-09
-- Description:
--   Seeds 15 Azure security relationship rules into resource_security_relationship_rules.
--   These rules enable the inventory engine to build Azure security edges, blast radius,
--   and attack paths in Neo4j — a HARD prerequisite for Azure pipeline production readiness.
--
--   Source field paths use Azure SDK as_dict() snake_case field names.
--   All target_uid_pattern values use {value} (scalar) or {item} (array element) —
--   the extracted value IS the full Azure Resource ID (resource_uid).
--
-- Target DB: threat_engine_inventory
-- Reference: AZ-06 story, load_relationship_rules_to_db.py schema

INSERT INTO resource_security_relationship_rules
    (csp, service, from_resource_type, relation_type, to_resource_type,
     source_field, source_field_item, target_uid_pattern,
     is_active, rule_source, rule_metadata)
VALUES

  -- ── Network topology ─────────────────────────────────────────────────────────

  -- VM → NIC: VM.network_profile.network_interfaces is array of {id: "/sub/.../nic"}
  ('azure', 'compute',          'VirtualMachine',          'routes_to',         'NetworkInterface',
   'network_profile.network_interfaces', 'id',    '{item}',  TRUE, 'azure_curated', '{"attack_path_category":"network_path","description":"VM network interface attachment"}'),

  -- NIC → NSG: NIC.network_security_group.id is a full Azure Resource ID string
  ('azure', 'network',          'NetworkInterface',         'protected_by',      'NetworkSecurityGroup',
   'network_security_group.id',          NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"defense_bypass","description":"NIC-level NSG controls inbound/outbound"}'),

  -- VNet → Subnet: VNet.subnets is array of {id: "/sub/.../subnet"}
  ('azure', 'network',          'VirtualNetwork',           'contains',          'Subnet',
   'subnets',                            'id',    '{item}',  TRUE, 'azure_curated', '{"attack_path_category":"network_path","description":"Subnets within virtual network"}'),

  -- Subnet → NSG: Subnet.network_security_group.id is a full Azure Resource ID string
  ('azure', 'network',          'Subnet',                   'protected_by',      'NetworkSecurityGroup',
   'network_security_group.id',          NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"defense_bypass","description":"NSG applied at subnet scope"}'),

  -- NSG → Subnet (reverse edge for inbound path tracing)
  ('azure', 'network',          'NetworkSecurityGroup',     'protects',          'Subnet',
   'subnets',                            'id',    '{item}',  TRUE, 'azure_curated', '{"attack_path_category":"defense_bypass","description":"NSG applied to subnets (reverse edge)"}'),

  -- LB → Subnet: LB frontend IP config references subnet
  ('azure', 'network',          'LoadBalancer',             'routes_to',         'Subnet',
   'frontend_ip_configurations',         'subnet.id', '{item}', TRUE, 'azure_curated', '{"attack_path_category":"network_path","description":"Load balancer frontend references subnet"}'),

  -- ── Compute / storage ────────────────────────────────────────────────────────

  -- VM → ManagedDisk: OS disk attachment
  ('azure', 'compute',          'VirtualMachine',           'contains',          'ManagedDisk',
   'storage_profile.os_disk.managed_disk.id', NULL, '{value}', TRUE, 'azure_curated', '{"attack_path_category":"data_access","description":"OS managed disk attached to VM"}'),

  -- ManagedDisk → KeyVault: disk encryption set references KV key
  ('azure', 'compute',          'ManagedDisk',              'encrypted_by',      'KeyVault',
   'encryption.disk_encryption_set_id',  NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"credential_access","description":"Disk encryption set references Key Vault key"}'),

  -- StorageAccount → PrivateEndpointConnection: private network lockdown
  ('azure', 'storage',          'StorageAccount',           'protected_by',      'PrivateEndpointConnection',
   'private_endpoint_connections',       'id',    '{item}',  TRUE, 'azure_curated', '{"attack_path_category":"network_path","description":"Private endpoint restricts public access to storage"}'),

  -- ── Identity / privilege ─────────────────────────────────────────────────────

  -- AppService → ManagedIdentity: MSI authentication path
  ('azure', 'web',              'AppService',               'authenticates_via', 'ManagedIdentity',
   'identity.principal_id',              NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"privilege_escalation","description":"App Service uses managed identity for auth"}'),

  -- AKSCluster → ManagedIdentity: cluster control-plane identity
  ('azure', 'containerservice', 'AKSCluster',               'authenticates_via', 'ManagedIdentity',
   'identity.principal_id',              NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"privilege_escalation","description":"AKS cluster managed identity"}'),

  -- ── AKS / SQL network topology ───────────────────────────────────────────────

  -- AKSCluster → VirtualNetwork: cluster node pool subnet → VNet
  ('azure', 'containerservice', 'AKSCluster',               'contained_by',      'VirtualNetwork',
   'agent_pool_profiles',                'vnet_subnet_id', '{item}', TRUE, 'azure_curated', '{"attack_path_category":"lateral_movement","description":"AKS node pool subnet links to VNet"}'),

  -- SQLServer → VirtualNetwork: VNet service endpoint rules
  ('azure', 'sql',              'SQLServer',                'contained_by',      'VirtualNetwork',
   'virtual_network_rules',              'virtual_network_subnet_id', '{item}', TRUE, 'azure_curated', '{"attack_path_category":"network_path","description":"SQL Server VNet service endpoint rule"}'),

  -- ── Key Vault ────────────────────────────────────────────────────────────────

  -- KeyVault → AccessPolicy principal (identity with vault access)
  ('azure', 'keyvault',         'KeyVault',                 'controlled_by',     'ServicePrincipal',
   'properties.access_policies',         'object_id', '{item}', TRUE, 'azure_curated', '{"attack_path_category":"credential_access","description":"Key Vault access policy grants identity access to secrets/keys"}'),

  -- RoleAssignment → ServicePrincipal: role binding to SP
  ('azure', 'authorization',    'RoleAssignment',           'grants_access_to',  'ServicePrincipal',
   'principal_id',                       NULL,    '{value}', TRUE, 'azure_curated', '{"attack_path_category":"privilege_escalation","description":"Role assignment grants SP access to Azure scope"}')

ON CONFLICT (csp, from_resource_type, relation_type, to_resource_type, source_field)
DO UPDATE SET
    service            = EXCLUDED.service,
    source_field_item  = EXCLUDED.source_field_item,
    target_uid_pattern = EXCLUDED.target_uid_pattern,
    is_active          = TRUE,
    rule_source        = EXCLUDED.rule_source,
    rule_metadata      = EXCLUDED.rule_metadata,
    updated_at         = NOW();

-- Verify:
-- SELECT COUNT(*) FROM resource_security_relationship_rules WHERE csp = 'azure';
-- Expected: 15
