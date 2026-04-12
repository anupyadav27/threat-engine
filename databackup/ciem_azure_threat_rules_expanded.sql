-- CIEM Azure Threat Detection Rules (Expanded)
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_secret_metadata','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/secrets/readMetadata/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_secret_metadata','keyvault','azure',
  'medium','Azure Key Vault: Secret Metadata Read','Key Vault secret names were enumerated. Listing secrets is a reconnaissance precursor to targeted theft.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_key_metadata','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/keys/readMetadata/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_key_metadata','keyvault','azure',
  'medium','Azure Key Vault: Key Metadata Read','Key Vault key names were enumerated.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_cert_metadata','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/certificates/readMetadata/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_cert_metadata','keyvault','azure',
  'medium','Azure Key Vault: Certificate Metadata Read','Key Vault certificate names were enumerated.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_deploy_action','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/deploy/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_deploy_action','keyvault','azure',
  'medium','Azure Key Vault: Vault Deployed For Template','A Key Vault was referenced in an ARM template deployment. Keys may be exposed to automated processes.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_purge','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/purge/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_purge','keyvault','azure',
  'medium','Azure Key Vault: Vault Purged (Irreversible Delete)','A soft-deleted Key Vault was permanently purged. All keys, secrets, and certificates are unrecoverable.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_key_purge','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/keys/purge/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_key_purge','keyvault','azure',
  'medium','Azure Key Vault: Key Purged','A soft-deleted Key Vault key was permanently purged.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.kv_secret_purge','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/secrets/purge/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.kv_secret_purge','keyvault','azure',
  'medium','Azure Key Vault: Secret Purged','A soft-deleted Key Vault secret was permanently purged.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_run_command','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/runCommand/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_run_command','compute','azure',
  'medium','Azure VM: Run Command Executed','A Run Command script was executed inside a VM. This is a remote execution vector equivalent to SSH/WinRM.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_capture','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/capture/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_capture','compute','azure',
  'medium','Azure VM: VM Image Captured','A running VM was captured as a generalized image. This can expose sensitive data from disk.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_generalize','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/generalize/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_generalize','compute','azure',
  'medium','Azure VM: VM Generalized','A VM was generalized (sysprep) — a precursor to capturing disk for potential exfiltration.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_reimage','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/reimage/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_reimage','compute','azure',
  'medium','Azure VM: VM Reimaged','A VM was reimaged. This replaces the OS disk and can destroy evidence of compromise.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_redeploy','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/redeploy/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_redeploy','compute','azure',
  'medium','Azure VM: VM Redeployed','A VM was redeployed to a different host. Can be used to disrupt monitoring or evade detection.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_boot_diagnostics','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/retrieveBootDiagnosticsData/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_boot_diagnostics','compute','azure',
  'medium','Azure VM: Boot Diagnostics Data Retrieved','Boot diagnostics data (including screenshots and serial output) was retrieved from a VM.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.disk_begin_access','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/disks/beginGetAccess/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.disk_begin_access','compute','azure',
  'medium','Azure Disk: Disk Export Access Initiated','Direct disk access was initiated for an Azure managed disk. SAS URIs allow disk content download.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_reset_agent','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/resetVMAgent/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_reset_agent','compute','azure',
  'medium','Azure VM: VM Agent Reset','The Azure VM Agent was reset. This can disable monitoring agents and alter VM behavior.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vmss_run_command','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachineScaleSets/runCommand/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vmss_run_command','compute','azure',
  'medium','Azure VMSS: Run Command Executed on Scale Set','A Run Command script was executed across a VM Scale Set instance.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.vm_extension_run','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/runCommand/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.vm_extension_run','compute','azure',
  'medium','Azure VM: Custom Script Extension Triggered','A Custom Script Extension executed on a VM. Script extensions can run arbitrary code.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.storage_regen_key','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/regeneratekey/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.storage_regen_key','storage','azure',
  'medium','Azure Storage: Account Key Regenerated','A storage account access key was regenerated. Old keys are immediately invalidated, potentially disrupting services.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.storage_delegation_key','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.storage_delegation_key','storage','azure',
  'medium','Azure Storage: User Delegation Key Generated','A user delegation key was generated for Azure Blob Storage. Delegation keys create short-lived SAS tokens.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.storage_sas_account','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/ListAccountSas/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.storage_sas_account','storage','azure',
  'medium','Azure Storage: Account SAS Token Listed','An Account SAS token was listed for a storage account, granting broad access to storage resources.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.storage_blob_immutability','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/blobServices/containers/clearLegalHold/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.storage_blob_immutability','storage','azure',
  'medium','Azure Storage: Blob Immutability Policy Modified','A blob immutability (WORM) policy was changed, potentially allowing modification of compliance records.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.aks_admin_creds','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.aks_admin_creds','containerservice','azure',
  'medium','Azure AKS: Cluster Admin Credentials Retrieved','AKS cluster admin credentials were retrieved. Admin kubeconfig grants full cluster access.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.aks_user_creds','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.aks_user_creds','containerservice','azure',
  'medium','Azure AKS: Cluster User Credentials Retrieved','AKS cluster user credentials were retrieved.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.aks_monitor_creds','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.aks_monitor_creds','containerservice','azure',
  'medium','Azure AKS: Cluster Monitoring Credentials Retrieved','AKS cluster monitoring credentials were retrieved. These provide read access to cluster metrics.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.aks_upgrade','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/upgradeNodeImageVersion/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.aks_upgrade','containerservice','azure',
  'medium','Azure AKS: Cluster Kubernetes Version Upgraded','AKS cluster Kubernetes version was upgraded. Forced upgrades can trigger node restarts and monitoring gaps.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.net_packet_capture','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/networkWatchers/packetCaptures/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.net_packet_capture','network','azure',
  'medium','Azure Network Watcher: Packet Capture Created','A packet capture session was created in Azure Network Watcher. Captures can intercept network traffic.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.net_vnet_peering','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.net_vnet_peering','network','azure',
  'medium','Azure VNet: VNet Peering Created','A new VNet peering was created. Peering connects isolated networks and can bypass security boundaries.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.net_flow_log','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/networkWatchers/flowLogs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.net_flow_log','network','azure',
  'medium','Azure Network Watcher: Flow Log Updated','A Network Watcher flow log was created or updated. Changes may reduce network visibility.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.net_vpn_sharedkey','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/connections/sharedKey/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.net_vpn_sharedkey','network','azure',
  'medium','Azure VPN: VPN Shared Key Retrieved','The shared pre-authentication key for an Azure VPN connection was retrieved.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.net_expressroute_auth','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/expressRouteCircuits/authorizations/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.net_expressroute_auth','network','azure',
  'medium','Azure ExpressRoute: Authorization Key Listed','An ExpressRoute circuit authorization key was listed, providing access to the circuit.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.automation_runbook_write','automation','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Automation/automationAccounts/runbooks/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.automation_runbook_write','automation','azure',
  'medium','Azure Automation: Runbook Created or Modified','An Azure Automation runbook was created or modified. Runbooks execute code on managed systems.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.automation_job_start','automation','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Automation/automationAccounts/jobs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.automation_job_start','automation','azure',
  'medium','Azure Automation: Job Started','An Azure Automation runbook job was started. Jobs execute scripts on Azure infrastructure.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.automation_credential','automation','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Automation/automationAccounts/credentials/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.automation_credential','automation','azure',
  'medium','Azure Automation: Credential Asset Modified','An Azure Automation credential asset was created or updated. These store username/password pairs.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.automation_variable','automation','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Automation/automationAccounts/variables/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.automation_variable','automation','azure',
  'medium','Azure Automation: Variable Asset Modified','An Azure Automation variable was written. Variables can store secrets accessible to runbooks.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.devops_pipeline_run','devtestlab','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DevTestLab/labs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.devops_pipeline_run','devtestlab','azure',
  'medium','Azure DevOps: Pipeline Execution','An Azure DevOps pipeline or release was triggered. Pipelines can deploy to production environments.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.logic_app_trigger','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/workflows/triggers/run/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.logic_app_trigger','logic','azure',
  'medium','Azure Logic App: Workflow Triggered','An Azure Logic App workflow was triggered. Logic Apps can orchestrate actions across services.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.security_auto_provision','security','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Security/autoProvisioningSettings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.security_auto_provision','security','azure',
  'medium','Azure Security Center: Auto-Provisioning Settings Changed','Microsoft Defender for Cloud auto-provisioning settings were changed. This controls agent deployment.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.security_pricing','security','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Security/pricings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.security_pricing','security','azure',
  'medium','Azure Defender: Plan Pricing Changed','Microsoft Defender for Cloud pricing tier was changed. Downgrades reduce threat detection coverage.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.security_workspace','security','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Security/workspaceSettings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.security_workspace','security','azure',
  'medium','Azure Security Center: Workspace Settings Changed','The Log Analytics workspace for Microsoft Defender for Cloud was changed.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.security_contact','security','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Security/securityContacts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.security_contact','security','azure',
  'medium','Azure Security Center: Security Contact Deleted','A Microsoft Defender for Cloud security contact was deleted, removing alert notification recipients.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.diagnostic_delete','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/diagnosticSettings/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.diagnostic_delete','insights','azure',
  'medium','Azure Monitor: Diagnostic Settings Deleted','Azure Monitor diagnostic settings were deleted. This removes log forwarding to storage/SIEM.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.activity_alert_delete','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/activityLogAlerts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.activity_alert_delete','insights','azure',
  'medium','Azure Monitor: Activity Log Alert Deleted','An Azure Monitor activity log alert was deleted. Alerts notify on security-relevant events.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.log_workspace_delete','operationalinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.OperationalInsights/workspaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.log_workspace_delete','operationalinsights','azure',
  'medium','Azure Log Analytics: Workspace Deleted','A Log Analytics workspace was deleted. This destroys log retention and SIEM connectivity.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.sp_credential_add','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"servicePrincipals/credentials"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.sp_credential_add','authorization','azure',
  'medium','Azure: Service Principal Credential Added','A credential (password/certificate) was added to a service principal, creating a new auth secret.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.app_credential_add','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"applications/credentials"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.app_credential_add','authorization','azure',
  'medium','Azure AD: Application Credential Added','A credential was added to an Azure AD application registration, creating a client secret.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.subscription_transfer','subscription','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"Microsoft.Billing/billingAccounts"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.subscription_transfer','subscription','azure',
  'medium','Azure: Subscription Billing Ownership Transferred','Azure subscription billing ownership was transferred, potentially changing administrative control.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.blueprint_assign','blueprint','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"Microsoft.Blueprint/blueprintAssignments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.blueprint_assign','blueprint','azure',
  'medium','Azure Blueprints: Blueprint Assigned','An Azure Blueprint was assigned to a subscription. Blueprints can deploy policies, RBACs, and resources.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.sql_audit_disable','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/auditingSettings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.sql_audit_disable','sql','azure',
  'medium','Azure SQL: Auditing Settings Disabled','Azure SQL Server auditing was disabled. This removes logging of database access and changes.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.sql_alert_disable','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/securityAlertPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.sql_alert_disable','sql','azure',
  'medium','Azure SQL: Threat Detection Policy Changed','Azure SQL Server Advanced Threat Protection policy was changed, potentially reducing alerting.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.cosmos_key_list','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/listKeys/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.cosmos_key_list','documentdb','azure',
  'medium','Azure Cosmos DB: Account Keys Listed','Cosmos DB account keys were listed. These keys provide full database read/write access.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.audit.cosmos_conn_strings','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.audit.cosmos_conn_strings','documentdb','azure',
  'medium','Azure Cosmos DB: Connection Strings Listed','Cosmos DB connection strings were listed. Connection strings contain embedded credentials.',
  'threat_detection','audit_activity','azure_activity',
  'azure_activity_audit_activity','audit_activity',
  'log','{"azure_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_telnet_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_telnet_allow','nsg_flow','azure',
  'medium','Azure NSG: Telnet Traffic Allowed (Port 23)','Telnet traffic (port 23) was allowed. Telnet transmits credentials in plaintext.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_smtp_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"25"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_smtp_allow','nsg_flow','azure',
  'medium','Azure NSG: SMTP Traffic Allowed (Port 25)','SMTP traffic (port 25) was allowed. Open SMTP can enable spam relay and data exfiltration.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_winrm_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"in","field":"network.dst_port","value":["5985","5986"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_winrm_allow','nsg_flow','azure',
  'high','Azure NSG: WinRM Traffic Allowed (Ports 5985/5986)','Windows Remote Management traffic was allowed. WinRM enables remote PowerShell execution.',
  'threat_detection','execute','azure_nsg_flow',
  'azure_nsg_flow_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_redis_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"6379"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_redis_allow','nsg_flow','azure',
  'medium','Azure NSG: Redis Port Exposed (Port 6379)','Redis traffic (port 6379) was allowed. Exposed Redis instances are frequently compromised.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_es_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"9200"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_es_allow','nsg_flow','azure',
  'medium','Azure NSG: Elasticsearch Port Exposed (Port 9200)','Elasticsearch HTTP API (port 9200) was allowed. Exposed ES clusters are a common data breach vector.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_memcached_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"11211"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_memcached_allow','nsg_flow','azure',
  'medium','Azure NSG: Memcached Port Exposed (Port 11211)','Memcached traffic (port 11211) was allowed. Exposed Memcached is exploited for DDoS amplification.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_http_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"80"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_http_allow','nsg_flow','azure',
  'medium','Azure NSG: HTTP Traffic Allowed (Port 80)','HTTP traffic (port 80) was allowed inbound. Unencrypted HTTP exposes data in transit.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_https_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"443"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_https_allow','nsg_flow','azure',
  'medium','Azure NSG: HTTPS Traffic Allowed (Port 443)','HTTPS traffic (port 443) was allowed. Monitor for C2 over HTTPS.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_telnet_deny','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"D"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_telnet_deny','nsg_flow','azure',
  'medium','Azure NSG: Telnet Traffic Blocked','Telnet (port 23) was denied — expected, but high volumes indicate scanning.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_smb_lateral','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"in","field":"network.dst_port","value":["445","139"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_smb_lateral','nsg_flow','azure',
  'medium','Azure NSG: SMB Lateral Movement Detected','SMB traffic (port 445) between internal hosts was allowed — possible lateral movement.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.vm_runcommand','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"runCommand"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.vm_runcommand','compute','azure',
  'high','Azure VM: Run Command Executed via Activity Log','An Azure VM Run Command was executed, allowing arbitrary script execution inside the VM.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.automation_start','automation','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"automationAccounts/jobs"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.automation_start','automation','azure',
  'high','Azure Automation: Runbook Job Started','An Azure Automation runbook job was started, executing code on managed infrastructure.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.container_create','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.container_create','containerinstance','azure',
  'high','Azure Container Instance: Container Group Created','A new Azure Container Instance group was created. ACI can execute arbitrary container workloads.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.container_exec','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"containerGroups/containers/exec"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.container_exec','containerinstance','azure',
  'high','Azure Container Instance: Container Exec Session','An exec session was opened in an Azure Container Instance.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.function_key_list','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"sites/functions/keys"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.function_key_list','web','azure',
  'high','Azure Function: Function Keys Listed','Azure Function API keys were listed. These keys authenticate function invocations.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.aks_node_drain','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"managedClusters/agentPools"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.aks_node_drain','containerservice','azure',
  'high','Azure AKS: Node Pool Drained','An AKS node pool was drained, removing all pods from nodes and potentially disrupting workloads.',
  'threat_detection','execute','azure_activity',
  'azure_activity_execute','execute',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.c2.defender_c2_channel','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"CommandAndControl"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.c2.defender_c2_channel','defender','azure',
  'critical','Azure Defender: C2 Communication Channel Detected','Microsoft Defender for Cloud detected a potential command-and-control communication channel.',
  'threat_detection','c2','azure_defender',
  'azure_defender_c2','c2',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control"]','["T1071","T1568"]',95,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.c2.defender_reverse_shell','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"ReverseShell"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.c2.defender_reverse_shell','defender','azure',
  'critical','Azure Defender: Reverse Shell Activity Detected','Microsoft Defender for Cloud detected possible reverse shell or interactive shell activity.',
  'threat_detection','c2','azure_defender',
  'azure_defender_c2','c2',
  'log','{"azure_ciem"}','ciem_engine',
  '["command-and-control"]','["T1071","T1568"]',95,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.malware.defender_ransomware','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"Ransomware"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.malware.defender_ransomware','defender','azure',
  'critical','Azure Defender: Ransomware Activity Detected','Microsoft Defender for Cloud detected ransomware-like behavior on an Azure resource.',
  'threat_detection','malware','azure_defender',
  'azure_defender_malware','malware',
  'log','{"azure_ciem"}','ciem_engine',
  '["execution","impact"]','["T1204","T1485"]',95,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.cryptomining.defender_crypto','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"CryptoMining"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.cryptomining.defender_crypto','defender','azure',
  'high','Azure Defender: Cryptomining Activity Detected','Microsoft Defender for Cloud detected cryptomining workloads on an Azure resource.',
  'threat_detection','cryptomining','azure_defender',
  'azure_defender_cryptomining','cryptomining',
  'log','{"azure_ciem"}','ciem_engine',
  '["impact"]','["T1496"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authorization.storage_denied','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"storage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authorization.storage_denied','storage','azure',
  'high','Azure Storage: Authorization Failure','Access to an Azure Storage resource was denied. Repeated denials may indicate unauthorized access attempts.',
  'threat_detection','authorization','azure_activity',
  'azure_activity_authorization','authorization',
  'log','{"azure_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authorization.sql_denied','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"sql"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authorization.sql_denied','sql','azure',
  'high','Azure SQL: Authorization Failure','Access to an Azure SQL resource was denied.',
  'threat_detection','authorization','azure_activity',
  'azure_activity_authorization','authorization',
  'log','{"azure_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authorization.keyvault_denied','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"keyvault"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authorization.keyvault_denied','keyvault','azure',
  'high','Azure Key Vault: Authorization Failure','Access to a Key Vault resource was denied. This may indicate unauthorized access to secrets.',
  'threat_detection','authorization','azure_activity',
  'azure_activity_authorization','authorization',
  'log','{"azure_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authorization.containerservice_denied','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"containerservice"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authorization.containerservice_denied','containerservice','azure',
  'high','Azure AKS: Authorization Failure','An AKS resource operation was denied. May indicate privilege escalation attempt.',
  'threat_detection','authorization','azure_activity',
  'azure_activity_authorization','authorization',
  'log','{"azure_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.error.defender_config_error','security','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"equals","field":"severity","value":"Informational"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.error.defender_config_error','security','azure',
  'low','Azure Defender: Security Configuration Error','A security configuration error was detected in Microsoft Defender for Cloud.',
  'threat_detection','error','azure_defender',
  'azure_defender_error','error',
  'log','{"azure_ciem"}','ciem_engine',
  '["defense-evasion"]','["T1562"]',25,'auto','azure'
) ON CONFLICT DO NOTHING;

COMMIT;
