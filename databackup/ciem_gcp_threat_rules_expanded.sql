-- CIEM GCP Threat Detection Rules (Expanded)
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.sa_generate_id_token','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iamcredentials.googleapis.com"},{"op":"contains","field":"operation","value":"GenerateIdToken"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.sa_generate_id_token','iam','gcp',
  'medium','GCP IAM: Service Account ID Token Generated','An ID token was generated for a service account, enabling impersonation of the SA identity.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.sa_sign_blob','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iamcredentials.googleapis.com"},{"op":"contains","field":"operation","value":"SignBlob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.sa_sign_blob','iam','gcp',
  'medium','GCP IAM: Service Account Blob Signed','A data blob was signed using a service account key, enabling service account impersonation flows.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.sa_sign_jwt','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iamcredentials.googleapis.com"},{"op":"contains","field":"operation","value":"SignJwt"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.sa_sign_jwt','iam','gcp',
  'medium','GCP IAM: Service Account JWT Signed','A JWT was signed using a service account — can be used for API impersonation.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.iam_get_policy','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"GetIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.iam_get_policy','iam','gcp',
  'medium','GCP IAM: IAM Policy Retrieved','An IAM policy was read from a GCP resource. Mass policy enumeration indicates IAM reconnaissance.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.sa_list','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"ListServiceAccounts"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.sa_list','iam','gcp',
  'medium','GCP IAM: Service Accounts Listed','Service accounts were listed for a project. Enumeration of SAs is a common privilege escalation precursor.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.sa_key_list','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"ListServiceAccountKeys"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.sa_key_list','iam','gcp',
  'medium','GCP IAM: Service Account Keys Listed','Keys for a service account were listed. Key enumeration may indicate credential harvesting.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.roles_list','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"ListRoles"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.roles_list','iam','gcp',
  'medium','GCP IAM: IAM Roles Listed','Custom or predefined IAM roles were listed. Role enumeration is a common reconnaissance technique.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.workload_pool_create','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkloadIdentityPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.workload_pool_create','iam','gcp',
  'medium','GCP IAM: Workload Identity Pool Created','A Workload Identity Pool was created, enabling external identities to authenticate as GCP service accounts.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.kms_decrypt','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"Decrypt"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.kms_decrypt','cloudkms','gcp',
  'medium','GCP KMS: Data Decrypted Using KMS Key','Data was decrypted using a Cloud KMS key. Decrypt operations indicate access to encrypted data.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.kms_get_key','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"GetCryptoKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.kms_get_key','cloudkms','gcp',
  'medium','GCP KMS: KMS Crypto Key Retrieved','KMS key metadata was retrieved. Key enumeration may precede key extraction or misuse.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.kms_key_schedule_destroy','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"ScheduleDestroyCryptoKeyVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.kms_key_schedule_destroy','cloudkms','gcp',
  'medium','GCP KMS: Key Version Scheduled for Destruction','A KMS key version was scheduled for destruction. Key deletion causes permanent data loss.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.kms_set_iam_policy','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"SetIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.kms_set_iam_policy','cloudkms','gcp',
  'medium','GCP KMS: KMS Key IAM Policy Modified','The IAM policy on a KMS key was changed. Unauthorized modifications grant key access.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.storage_get_iam','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"GetIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.storage_get_iam','storage','gcp',
  'medium','GCP Storage: Bucket IAM Policy Retrieved','The IAM policy for a Cloud Storage bucket was retrieved — common reconnaissance before privilege escalation.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.storage_patch_bucket','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.buckets.patch"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.storage_patch_bucket','storage','gcp',
  'medium','GCP Storage: Bucket Metadata Updated','Cloud Storage bucket metadata was updated. Changes can affect access controls and versioning.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.storage_hmac_key','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"CreateHmacKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.storage_hmac_key','storage','gcp',
  'medium','GCP Storage: HMAC Key Created','An HMAC key was created for Cloud Storage. HMAC keys provide service-account-level access via S3 API.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.storage_unlock_bucket','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"LockRetentionPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.storage_unlock_bucket','storage','gcp',
  'medium','GCP Storage: Retention Policy Unlocked','A storage bucket retention policy lock was removed, allowing object deletion that was previously prohibited.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_set_metadata','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"SetMetadata"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_set_metadata','compute','gcp',
  'medium','GCP Compute: Instance Metadata Updated (SSH Keys)','Instance metadata was updated on a GCP VM. Metadata changes can add SSH public keys for unauthorized access.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_common_metadata','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"SetCommonInstanceMetadata"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_common_metadata','compute','gcp',
  'medium','GCP Compute: Project-Wide SSH Keys Updated','Project-wide common instance metadata was changed. This can add SSH keys that apply to ALL project VMs.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_serial_port','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"GetSerialPortOutput"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_serial_port','compute','gcp',
  'medium','GCP Compute: Serial Port Output Retrieved','VM serial port output was retrieved. Serial port output may contain sensitive boot and runtime data.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_snapshot_export','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"compute.snapshots.insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_snapshot_export','compute','gcp',
  'medium','GCP Compute: Disk Snapshot Created','A persistent disk snapshot was created. Snapshots can be used to exfiltrate disk contents.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_image_iam','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"compute.images.setIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_image_iam','compute','gcp',
  'medium','GCP Compute: Image IAM Policy Set','The IAM policy on a Compute image was changed. Unauthorized sharing exposes image contents.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_firewall_disable','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"compute.firewalls.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_firewall_disable','compute','gcp',
  'medium','GCP Compute: Firewall Rule Disabled','A GCP VPC firewall rule was disabled or deleted. This opens network access that was previously blocked.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.compute_add_access_config','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"AddAccessConfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.compute_add_access_config','compute','gcp',
  'medium','GCP Compute: External IP Attached to VM','An access config (external IP) was added to a GCP VM instance, exposing it to the internet.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.gke_rotate_credentials','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"RotateClusterCredentials"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.gke_rotate_credentials','container','gcp',
  'medium','GCP GKE: Cluster Credentials Rotated','GKE cluster credentials were rotated. Improper rotation can disrupt workloads and authentication.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.gke_set_master_auth','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"SetMasterAuth"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.gke_set_master_auth','container','gcp',
  'medium','GCP GKE: GKE Master Authentication Modified','GKE master authentication configuration was changed. This controls how the cluster API server is accessed.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.gke_set_network_policy','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"SetNetworkPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.gke_set_network_policy','container','gcp',
  'medium','GCP GKE: GKE Network Policy Changed','GKE cluster network policy was changed. Disabling network policy allows unrestricted pod-to-pod communication.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.gke_privileged_node','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"CreateNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.gke_privileged_node','container','gcp',
  'medium','GCP GKE: Node Pool with Privileged Containers','A GKE node pool was created with settings that may allow privileged container workloads.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.logging_delete_sink','logging','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteSink"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.logging_delete_sink','logging','gcp',
  'medium','GCP Logging: Log Sink Deleted','A Cloud Logging export sink was deleted. This removes log forwarding to SIEM/storage.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.logging_update_bucket','logging','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateBucket"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.logging_update_bucket','logging','gcp',
  'medium','GCP Logging: Log Bucket Retention Changed','A Cloud Logging log bucket retention period was changed, potentially reducing log availability.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.logging_create_exclusion','logging','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"CreateExclusion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.logging_create_exclusion','logging','gcp',
  'medium','GCP Logging: Log Exclusion Created','A Cloud Logging exclusion filter was created. Exclusions prevent specific logs from being ingested.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.logging_delete_log','logging','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteLog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.logging_delete_log','logging','gcp',
  'medium','GCP Logging: Log Entries Deleted','Log entries were deleted from Cloud Logging. Log deletion removes audit trail evidence.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.monitoring_alert_delete','monitoring','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteAlertPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.monitoring_alert_delete','monitoring','gcp',
  'medium','GCP Monitoring: Alert Policy Deleted','A Cloud Monitoring alert policy was deleted, removing alerting for security-relevant metrics.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.bq_table_iam','bigquery','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"SetIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.bq_table_iam','bigquery','gcp',
  'medium','GCP BigQuery: Table IAM Policy Modified','The IAM policy on a BigQuery table was changed, potentially exposing sensitive data.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.bq_data_extract','bigquery','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"jobservice.insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.bq_data_extract','bigquery','gcp',
  'medium','GCP BigQuery: Data Exported to Storage','A BigQuery data export job was created. Large-scale exports can indicate data exfiltration.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.cloudsql_export','sqladmin','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesExport"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.cloudsql_export','sqladmin','gcp',
  'medium','GCP Cloud SQL: Database Exported','A Cloud SQL database was exported to Cloud Storage. Exports contain full database contents.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.cloudsql_user_create','sqladmin','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlUsersInsert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.cloudsql_user_create','sqladmin','gcp',
  'medium','GCP Cloud SQL: Database User Created','A new database user was created in a Cloud SQL instance.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.cloudsql_ssl_create','sqladmin','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlSslCertsInsert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.cloudsql_ssl_create','sqladmin','gcp',
  'medium','GCP Cloud SQL: SSL Certificate Created','An SSL certificate was created for a Cloud SQL instance, providing a new authentication credential.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.spanner_db_drop','spanner','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"DropDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.spanner_db_drop','spanner','gcp',
  'medium','GCP Spanner: Database Dropped','A Spanner database was dropped. This is an irreversible operation destroying all data.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.secret_version_add','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"AddSecretVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.secret_version_add','secretmanager','gcp',
  'medium','GCP Secret Manager: New Secret Version Added','A new version was added to a Secret Manager secret. New versions may contain rotated credentials.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.secret_list','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"ListSecrets"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.secret_list','secretmanager','gcp',
  'medium','GCP Secret Manager: Secrets Listed','All secrets in a project were listed. Enumeration of secret names is a reconnaissance technique.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.audit.secret_iam_modify','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"SetIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.audit.secret_iam_modify','secretmanager','gcp',
  'medium','GCP Secret Manager: Secret IAM Policy Modified','The IAM policy on a Secret Manager secret was changed, potentially granting unauthorized access.',
  'threat_detection','audit_activity','gcp_audit',
  'gcp_audit_audit_activity','audit_activity',
  'log','{"gcp_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_telnet_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_telnet_allow','vpc_flow','gcp',
  'medium','GCP VPC: Telnet Traffic Allowed (Port 23)','Telnet (port 23) was allowed through GCP VPC firewall. Plaintext protocol exposing credentials.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_smtp_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"25"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_smtp_allow','vpc_flow','gcp',
  'medium','GCP VPC: SMTP Traffic Allowed (Port 25)','SMTP traffic (port 25) allowed. Open relays can enable spam and data exfiltration.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_winrm_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"in","field":"network.dst_port","value":["5985","5986"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_winrm_allow','vpc_flow','gcp',
  'high','GCP VPC: WinRM Traffic Allowed (Ports 5985/5986)','WinRM traffic allowed. Enables remote PowerShell execution on Windows instances.',
  'threat_detection','execute','gcp_vpc_flow',
  'gcp_vpc_flow_execute','execute',
  'log','{"gcp_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_redis_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"6379"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_redis_allow','vpc_flow','gcp',
  'medium','GCP VPC: Redis Port Exposed (Port 6379)','Redis (port 6379) was allowed. Unauthenticated Redis access leads to RCE.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_es_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"9200"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_es_allow','vpc_flow','gcp',
  'medium','GCP VPC: Elasticsearch Port Exposed (Port 9200)','Elasticsearch HTTP (port 9200) was allowed. Exposed ES is a common data breach vector.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_memcached_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"11211"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_memcached_allow','vpc_flow','gcp',
  'medium','GCP VPC: Memcached Port Exposed (Port 11211)','Memcached (port 11211) was allowed. Exploited for reflection DDoS and cache poisoning.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_telnet_denied','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"DENIED"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_telnet_denied','vpc_flow','gcp',
  'medium','GCP VPC: Telnet Traffic Blocked','Telnet traffic (port 23) was denied by GCP VPC firewall.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"gcp_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.execute.gke_cluster_admin','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_gke_audit"},{"op":"contains","field":"operation","value":"clusterrolebindings"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.execute.gke_cluster_admin','container','gcp',
  'high','GCP GKE: Cluster-Admin Role Binding Created','A cluster-admin RBAC binding was created in GKE, granting full cluster control.',
  'threat_detection','execute','gcp_gke_audit',
  'gcp_gke_audit_execute','execute',
  'log','{"gcp_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.execute.gke_privileged_pod','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_gke_audit"},{"op":"contains","field":"operation","value":"securityContext"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.execute.gke_privileged_pod','container','gcp',
  'high','GCP GKE: Privileged Pod Created','A privileged pod was created in GKE. Privileged containers can escape to the underlying node.',
  'threat_detection','execute','gcp_gke_audit',
  'gcp_gke_audit_execute','execute',
  'log','{"gcp_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authorization.kms_denied','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authorization.kms_denied','cloudkms','gcp',
  'high','GCP KMS: Unauthorized KMS Operation','An unauthorized KMS key operation was denied. May indicate lateral movement or key extraction.',
  'threat_detection','authorization','gcp_audit',
  'gcp_audit_authorization','authorization',
  'log','{"gcp_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authorization.bigquery_denied','bigquery','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authorization.bigquery_denied','bigquery','gcp',
  'high','GCP BigQuery: Unauthorized Data Access','An unauthorized BigQuery data access was denied. May indicate data exfiltration attempt.',
  'threat_detection','authorization','gcp_audit',
  'gcp_audit_authorization','authorization',
  'log','{"gcp_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authorization.spanner_denied','spanner','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"spanner.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authorization.spanner_denied','spanner','gcp',
  'high','GCP Spanner: Unauthorized Access','An unauthorized Spanner operation was denied.',
  'threat_detection','authorization','gcp_audit',
  'gcp_audit_authorization','authorization',
  'log','{"gcp_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authorization.secretmanager_denied','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authorization.secretmanager_denied','secretmanager','gcp',
  'high','GCP Secret Manager: Unauthorized Secret Access','An unauthorized Secret Manager operation was denied. Repeated attempts indicate secret harvesting.',
  'threat_detection','authorization','gcp_audit',
  'gcp_audit_authorization','authorization',
  'log','{"gcp_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

COMMIT;
