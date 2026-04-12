-- CIEM OCI Threat Detection Rules (Expanded)
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.list_api_keys','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"ListApiKeys"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.list_api_keys','identity','oci',
  'medium','OCI IAM: API Keys Listed','API signing keys for an OCI user were listed. Key enumeration may precede targeted credential theft.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.get_tenancy','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"GetTenancy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.get_tenancy','identity','oci',
  'medium','OCI IAM: Tenancy Information Retrieved','OCI tenancy information was retrieved. Tenancy details can be used for reconnaissance.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.list_identity_providers','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"ListIdentityProviders"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.list_identity_providers','identity','oci',
  'medium','OCI IAM: Identity Providers Listed','Identity providers (SAML/SCIM) were listed. Federation config reveals auth infrastructure.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.update_tenancy','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"UpdateTenancy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.update_tenancy','identity','oci',
  'medium','OCI IAM: Tenancy Updated','OCI tenancy settings were updated — high-impact change affecting the entire cloud environment.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.list_dynamic_groups','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"ListDynamicGroups"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.list_dynamic_groups','identity','oci',
  'medium','OCI IAM: Dynamic Groups Listed','Dynamic groups were listed. These grant IAM permissions to OCI resources based on matching rules.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.password_policy_update','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"UpdateAuthenticationPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.password_policy_update','identity','oci',
  'medium','OCI IAM: Password Policy Updated','The OCI tenancy password policy was updated. Weakening the policy reduces authentication security.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.mfa_totp_remove','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"DeleteMfaTotpDevice"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.mfa_totp_remove','identity','oci',
  'medium','OCI IAM: MFA Device Removed','A TOTP (MFA) device was removed from an OCI user account, weakening account security.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.get_windows_creds','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"GetWindowsInstanceInitialCredentials"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.get_windows_creds','compute','oci',
  'medium','OCI Compute: Windows Initial Credentials Retrieved','Windows instance initial credentials (password) were retrieved. Contains admin password.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.get_console_history','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"GetConsoleHistory"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.get_console_history','compute','oci',
  'medium','OCI Compute: Console History Retrieved','Instance serial console history was retrieved. Console output may contain sensitive startup data.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.capture_console_history','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"CaptureConsoleHistory"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.capture_console_history','compute','oci',
  'medium','OCI Compute: Console History Captured','A new console history capture was initiated for an OCI instance.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.instance_action','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"InstanceAction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.instance_action','compute','oci',
  'medium','OCI Compute: Instance Action Triggered','A power action (START/STOP/RESET/SOFTSTOP) was triggered on an OCI instance.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.kms_decrypt','keymanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.keymanagement"},{"op":"equals","field":"operation","value":"Decrypt"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.kms_decrypt','keymanagement','oci',
  'medium','OCI KMS: Data Decrypted Using KMS Key','Data was decrypted using an OCI KMS key. Decrypt operations indicate access to encrypted data.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.kms_list_keys','keymanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.keymanagement"},{"op":"equals","field":"operation","value":"ListKeys"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.kms_list_keys','keymanagement','oci',
  'medium','OCI KMS: Keys Listed','KMS encryption keys were listed. Key enumeration precedes targeted key access.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.vault_list_secrets','vault','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"ListSecrets"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.vault_list_secrets','vault','oci',
  'medium','OCI Vault: Secrets Listed','Secrets in the OCI Vault were listed. Secret name enumeration is a reconnaissance technique.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.vault_get_secret','vault','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"GetSecretBundle"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.vault_get_secret','vault','oci',
  'medium','OCI Vault: Secret Bundle Retrieved','A secret value (bundle) was retrieved from OCI Vault. Review who accessed what secret.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.adb_generate_wallet','database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"GenerateAutonomousDatabaseWallet"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.adb_generate_wallet','database','oci',
  'medium','OCI Autonomous DB: Wallet (Credentials) Generated','A database wallet was generated for an Autonomous Database. Wallets contain connection credentials.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.db_export','database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"CreateExadataInfrastructure"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.db_export','database','oci',
  'medium','OCI Database: Data Pump Export Initiated','A Data Pump export was initiated from an OCI database. Exports contain full database contents.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.db_backup_export','database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.db_backup_export','database','oci',
  'medium','OCI Database: Backup Exported','An OCI database backup was created or exported, enabling offline access to all data.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.audit_config_update','audit','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.audit"},{"op":"equals","field":"operation","value":"UpdateConfiguration"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.audit_config_update','audit','oci',
  'medium','OCI Audit: Audit Configuration Updated','OCI Audit service configuration was updated. Changes may alter retention or event collection.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.log_group_delete','logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"DeleteLogGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.log_group_delete','logging','oci',
  'medium','OCI Logging: Log Group Deleted','A log group was deleted from OCI Logging. Log deletion removes audit trail evidence.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.log_delete','logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"DeleteLog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.log_delete','logging','oci',
  'medium','OCI Logging: Log Deleted','A log resource was deleted from OCI Logging, removing security event history.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.oke_get_kubeconfig','containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"CreateKubeconfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.oke_get_kubeconfig','containerengine','oci',
  'medium','OCI OKE: Kubernetes Kubeconfig Retrieved','A kubeconfig was generated for an OKE cluster. Kubeconfigs grant direct cluster API access.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.vcn_route_update','network','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"UpdateRouteTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.vcn_route_update','network','oci',
  'medium','OCI VCN: Route Table Updated','A VCN route table was updated. Unauthorized route changes can redirect traffic for interception.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.vcn_security_list_update','network','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"UpdateSecurityList"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.vcn_security_list_update','network','oci',
  'medium','OCI VCN: Security List Updated','A VCN security list was updated. Changes can open or close network access unexpectedly.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.audit.vcn_nsg_rules_update','network','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"UpdateNetworkSecurityGroupSecurityRules"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.audit.vcn_nsg_rules_update','network','oci',
  'medium','OCI VCN: NSG Security Rules Updated','Network Security Group rules were updated for an OCI VCN.',
  'threat_detection','audit_activity','oci_audit',
  'oci_audit_audit_activity','audit_activity',
  'log','{"oci_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_telnet_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_telnet_accept','vcn_flow','oci',
  'medium','OCI VCN: Telnet Traffic Allowed (Port 23)','Telnet (port 23) was allowed through OCI VCN. Plaintext protocol exposing credentials.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"oci_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_winrm_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"in","field":"network.dst_port","value":["5985","5986"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_winrm_accept','vcn_flow','oci',
  'high','OCI VCN: WinRM Traffic Allowed (Ports 5985/5986)','WinRM traffic allowed through OCI VCN. Enables remote PowerShell execution.',
  'threat_detection','execute','oci_vcn_flow',
  'oci_vcn_flow_execute','execute',
  'log','{"oci_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_redis_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"6379"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_redis_accept','vcn_flow','oci',
  'medium','OCI VCN: Redis Port Exposed (Port 6379)','Redis (port 6379) was allowed. Unauthenticated Redis leads to RCE.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"oci_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_smtp_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"25"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_smtp_accept','vcn_flow','oci',
  'medium','OCI VCN: SMTP Traffic Allowed (Port 25)','SMTP (port 25) was allowed through OCI VCN. Open relays enable data exfiltration.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"oci_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_http_allow','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"80"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_http_allow','vcn_flow','oci',
  'medium','OCI VCN: HTTP Traffic Allowed (Port 80)','HTTP (port 80) was allowed. Unencrypted traffic exposes data in transit.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"oci_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_telnet_reject','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_telnet_reject','vcn_flow','oci',
  'medium','OCI VCN: Telnet Blocked','Telnet (port 23) was rejected. High volumes indicate scanning.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"oci_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.authorization.vault_denied','vault','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.authorization.vault_denied','vault','oci',
  'high','OCI Vault: Unauthorized Vault Operation','An unauthorized Vault operation was denied. May indicate credential theft attempt.',
  'threat_detection','authorization','oci_audit',
  'oci_audit_authorization','authorization',
  'log','{"oci_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.authorization.kms_denied','keymanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"com.oraclecloud.keymanagement"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.authorization.kms_denied','keymanagement','oci',
  'high','OCI KMS: Unauthorized KMS Operation','An unauthorized KMS operation was denied. May indicate key extraction attempt.',
  'threat_detection','authorization','oci_audit',
  'oci_audit_authorization','authorization',
  'log','{"oci_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.authorization.object_denied','objectstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"com.oraclecloud.objectstorage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.authorization.object_denied','objectstorage','oci',
  'high','OCI Object Storage: Unauthorized Access','An unauthorized Object Storage operation was denied.',
  'threat_detection','authorization','oci_audit',
  'oci_audit_authorization','authorization',
  'log','{"oci_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

COMMIT;
