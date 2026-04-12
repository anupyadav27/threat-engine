-- Azure audit_activity expansion rules

-- threat.azure.audit.acr_credentials_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.acr_credentials_list', 'containerregistry', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.ContainerRegistry/registries/listCredentials/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.acr_credentials_list', 'containerregistry', 'azure', 'medium',
    $t$Azure ACR: Registry Admin Credentials Listed$t$, $t$Admin credentials for an Azure Container Registry were listed. These allow full push/pull access to all images.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.acr_token_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.acr_token_list', 'containerregistry', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.ContainerRegistry/registries/tokens/listPasswords/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.acr_token_list', 'containerregistry', 'azure', 'medium',
    $t$Azure ACR: Registry Token Passwords Listed$t$, $t$Scoped access token passwords for an Azure Container Registry were listed.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.ca_policy_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.ca_policy_create', 'aad', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "microsoft.directory/conditionalAccessPolicies/create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.ca_policy_create', 'aad', 'azure', 'medium',
    $t$Azure AD: Conditional Access Policy Created$t$, $t$A new Azure AD Conditional Access policy was created. Changes may weaken authentication requirements.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.ca_policy_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.ca_policy_delete', 'aad', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "microsoft.directory/conditionalAccessPolicies/delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.ca_policy_delete', 'aad', 'azure', 'medium',
    $t$Azure AD: Conditional Access Policy Deleted$t$, $t$An Azure AD Conditional Access policy was deleted, potentially removing MFA or location-based access controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.ca_named_location_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.ca_named_location_create', 'aad', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "microsoft.directory/namedLocations/create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.ca_named_location_create', 'aad', 'azure', 'medium',
    $t$Azure AD: Named Location (Trusted Network) Created$t$, $t$A named location (trusted IP range) was added. Attackers may add their own IPs to bypass Conditional Access rules.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.nsg_flow_log_disable
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.nsg_flow_log_disable', 'network', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Network/networkWatchers/flowLogs/delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.nsg_flow_log_disable', 'network', 'azure', 'medium',
    $t$Azure Network Watcher: NSG Flow Log Deleted$t$, $t$An NSG flow log resource was deleted, removing network traffic visibility for the associated NSG.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.public_ip_assign
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.public_ip_assign', 'network', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.Network/networkInterfaces/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.public_ip_assign', 'network', 'azure', 'medium',
    $t$Azure Network: NIC Configuration Updated (Possible Public IP Assignment)$t$, $t$A network interface configuration was updated, which may include associating a new public IP address.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.vnet_dns_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.vnet_dns_update', 'network', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.Network/virtualNetworks/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.vnet_dns_update', 'network', 'azure', 'medium',
    $t$Azure VNet: Virtual Network Configuration Updated$t$, $t$Virtual network configuration was updated, potentially changing DNS servers or address space.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.sql_server_firewall
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.sql_server_firewall', 'sql', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Sql/servers/firewallRules/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.sql_server_firewall', 'sql', 'azure', 'medium',
    $t$Azure SQL: Server Firewall Rule Modified$t$, $t$A SQL Server firewall rule was created or updated. Overly broad rules may expose the database to the internet.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.sql_transparent_encryption
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.sql_transparent_encryption', 'sql', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Sql/servers/databases/transparentDataEncryption/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.sql_transparent_encryption', 'sql', 'azure', 'medium',
    $t$Azure SQL: Transparent Data Encryption Setting Changed$t$, $t$TDE settings for an Azure SQL database were modified. Disabling TDE removes encryption at rest.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.sql_vulnerability_scan
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.sql_vulnerability_scan', 'sql', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Sql/servers/vulnerabilityAssessments/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.sql_vulnerability_scan', 'sql', 'azure', 'medium',
    $t$Azure SQL: Vulnerability Assessment Setting Modified$t$, $t$SQL Server vulnerability assessment settings were changed. Disabling this removes periodic security scanning.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.storage_lifecycle_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.storage_lifecycle_delete', 'storage', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Storage/storageAccounts/managementPolicies/delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.storage_lifecycle_delete', 'storage', 'azure', 'medium',
    $t$Azure Storage: Lifecycle Management Policy Deleted$t$, $t$Storage account lifecycle policy was deleted, potentially preserving sensitive data beyond intended retention.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.storage_private_endpoint
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.storage_private_endpoint', 'storage', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.Storage/storageAccounts/privateEndpointConnections/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.storage_private_endpoint', 'storage', 'azure', 'medium',
    $t$Azure Storage: Private Endpoint Connection Modified$t$, $t$A private endpoint connection for a storage account was modified, potentially changing network access controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.event_hub_key_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.event_hub_key_list', 'eventhub', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.EventHub/namespaces/authorizationRules/listkeys/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.event_hub_key_list', 'eventhub', 'azure', 'medium',
    $t$Azure Event Hub: Namespace Authorization Keys Listed$t$, $t$Event Hub namespace SAS keys were listed. These keys grant send/listen access to the namespace.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.service_bus_key_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.service_bus_key_list', 'servicebus', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.ServiceBus/namespaces/authorizationRules/listkeys/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.service_bus_key_list', 'servicebus', 'azure', 'medium',
    $t$Azure Service Bus: Namespace Authorization Keys Listed$t$, $t$Service Bus namespace SAS keys were listed. These keys grant access to all queues and topics.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.redis_key_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.redis_key_list', 'cache', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Cache/redis/listKeys/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.redis_key_list', 'cache', 'azure', 'medium',
    $t$Azure Redis Cache: Access Keys Listed$t$, $t$Redis Cache primary and secondary keys were listed. These provide full access to the cache instance.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.backup_vault_policy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.backup_vault_policy', 'recoveryservices', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.RecoveryServices/vaults/backupPolicies/delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.backup_vault_policy', 'recoveryservices', 'azure', 'medium',
    $t$Azure Backup: Backup Policy Deleted$t$, $t$A Recovery Services vault backup policy was deleted. This may remove scheduled backups for protected resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.backup_protection_disable
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.backup_protection_disable', 'recoveryservices', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.backup_protection_disable', 'recoveryservices', 'azure', 'medium',
    $t$Azure Backup: Backup Protection Disabled for Item$t$, $t$Backup protection was disabled for a resource, stopping future backups and exposing it to unrecoverable deletion.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.aks_stop
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.aks_stop', 'containerservice', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.ContainerService/managedClusters/stop/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.aks_stop', 'containerservice', 'azure', 'medium',
    $t$Azure AKS: Cluster Stopped$t$, $t$An AKS cluster was stopped. This terminates all running workloads on the cluster.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.aks_rbac_binding
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.aks_rbac_binding', 'containerservice', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.aks_rbac_binding', 'containerservice', 'azure', 'medium',
    $t$Azure AKS: Cluster Access Profile Credentials Listed$t$, $t$AKS cluster access profile credentials were retrieved, providing kubectl access to the cluster.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.function_key_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.function_key_list', 'web', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Web/sites/host/listkeys/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.function_key_list', 'web', 'azure', 'medium',
    $t$Azure Functions: Function App Host Keys Listed$t$, $t$Function App host (master + function) keys were listed. These keys allow invoking any function in the app.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.management_group_move
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.management_group_move', 'managementgroups', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.Management/managementGroups/subscriptions/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.management_group_move', 'managementgroups', 'azure', 'medium',
    $t$Azure: Subscription Moved to Different Management Group$t$, $t$A subscription was moved to a different management group, potentially changing policy inheritance and access controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.policy_exemption_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.policy_exemption_create', 'resources', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Authorization/policyExemptions/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.policy_exemption_create', 'resources', 'azure', 'medium',
    $t$Azure Policy: Policy Exemption Created$t$, $t$A policy exemption was created. This waives a policy requirement for a scope, reducing compliance coverage.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.app_publishing_credentials
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.app_publishing_credentials', 'web', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Web/sites/publishxml/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.app_publishing_credentials', 'web', 'azure', 'medium',
    $t$Azure App Service: Publishing Credentials Retrieved$t$, $t$App Service publishing credentials (FTP/WebDeploy) were retrieved, enabling code deployment to the web app.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.app_config_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.app_config_list', 'web', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "equals", "field": "operation", "value": "Microsoft.Web/sites/config/list/action"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.app_config_list', 'web', 'azure', 'medium',
    $t$Azure App Service: App Configuration and Secrets Listed$t$, $t$App Service configuration (including connection strings and app settings with secrets) was listed.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.azure.audit.user_assigned_mi_credentials
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.azure.audit.user_assigned_mi_credentials', 'managedidentity', 'azure', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "azure_activity"}, {"op": "contains", "field": "operation", "value": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.azure.audit.user_assigned_mi_credentials', 'managedidentity', 'azure', 'medium',
    $t$Azure Managed Identity: Federated Identity Credential Created$t$, $t$A federated identity credential was added to a user-assigned managed identity, allowing external workloads to impersonate it.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;
