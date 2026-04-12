-- CIEM IBM Threat Detection Rules (Expanded)
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.list_api_keys','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.account.apikey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.list_api_keys','iam_identity','ibm',
  'medium','IBM IAM: API Keys Listed','IBM IAM API keys were listed. Key enumeration may precede targeted credential theft.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.list_service_ids','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.serviceid.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.list_service_ids','iam_identity','ibm',
  'medium','IBM IAM: Service IDs Listed','IBM Service IDs were listed. Service ID enumeration reveals programmatic access identities.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.get_service_id','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.serviceid.get"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.get_service_id','iam_identity','ibm',
  'medium','IBM IAM: Service ID Retrieved','An IBM Service ID was read. Service IDs are used for programmatic API authentication.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.list_trusted_profiles','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.profile.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.list_trusted_profiles','iam_identity','ibm',
  'medium','IBM IAM: Trusted Profiles Listed','IBM Trusted Profiles were listed. Trusted profiles grant compute resources access to cloud services.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.api_key_lock','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.apikey.lock"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.api_key_lock','iam_identity','ibm',
  'medium','IBM IAM: API Key Locked','An IBM IAM API key was locked. Locking prevents the key from being used for authentication.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.mfa_update','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.mfa-enrollment.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.mfa_update','iam_identity','ibm',
  'medium','IBM IAM: MFA Settings Updated','IBM IAM MFA (multi-factor authentication) settings were updated. Weakening MFA reduces account security.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.list_policies','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.policy.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.list_policies','iam','ibm',
  'medium','IBM IAM: Access Policies Listed','IBM IAM access policies were listed. Policy enumeration reveals what actions identities can perform.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.get_policy','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.policy.get"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.get_policy','iam','ibm',
  'medium','IBM IAM: Access Policy Retrieved','An IBM IAM access policy was read.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.access_group_list','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":"iam.access-group.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.access_group_list','iam','ibm',
  'medium','IBM IAM: Access Groups Listed','IBM IAM Access Groups were listed. Access groups aggregate users and service IDs sharing policies.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.authorization_create','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.authorization.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.authorization_create','iam','ibm',
  'medium','IBM IAM: Service Authorization Created','A service-to-service authorization was created, granting one IBM service access to another.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.cos_list_buckets','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.cos_list_buckets','cloud_object_storage','ibm',
  'medium','IBM COS: Buckets Listed','Cloud Object Storage buckets were listed. Bucket enumeration reveals data assets.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.cos_get_bucket_policy','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket-acl.get"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.cos_get_bucket_policy','cloud_object_storage','ibm',
  'medium','IBM COS: Bucket IAM Policy Retrieved','The IAM policy for a COS bucket was retrieved. Policy reads reveal access control configuration.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.cos_hmac_key_create','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket-credentials.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.cos_hmac_key_create','cloud_object_storage','ibm',
  'medium','IBM COS: HMAC Credentials Created','HMAC credentials were created for IBM COS. HMAC keys enable S3-compatible programmatic access.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.cos_key_list','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket-credentials.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.cos_key_list','cloud_object_storage','ibm',
  'medium','IBM COS: COS Keys Listed','IBM COS service credentials were listed.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.kms_list_keys','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.kms_list_keys','kms','ibm',
  'medium','IBM Key Protect: Keys Listed','Key Protect encryption keys were listed. Key enumeration is a precursor to key extraction.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.kms_wrap_key','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.wrap"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.kms_wrap_key','kms','ibm',
  'medium','IBM Key Protect: Key Wrap Operation','A key wrap operation was performed with Key Protect. Wrap/unwrap is used in envelope encryption.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.kms_unwrap_key','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.unwrap"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.kms_unwrap_key','kms','ibm',
  'medium','IBM Key Protect: Key Unwrap Operation','A key unwrap (decrypt) operation was performed with Key Protect, decrypting a data encryption key.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.kms_rotate_key','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.rotate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.kms_rotate_key','kms','ibm',
  'medium','IBM Key Protect: Key Rotated','A Key Protect key was rotated. Improper rotation can disrupt encryption-dependent services.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.kms_disable_key','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.disable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.kms_disable_key','kms','ibm',
  'medium','IBM Key Protect: Encryption Key Disabled','A Key Protect key was disabled. Disabling a key renders encrypted data inaccessible.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.vpc_sg_rule_create','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":"is.security-group-rule.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.vpc_sg_rule_create','is','ibm',
  'medium','IBM VPC: Security Group Rule Created','A new security group rule was added in IBM VPC. Rules control network access to compute instances.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.vpc_sg_rule_delete','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":"is.security-group-rule.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.vpc_sg_rule_delete','is','ibm',
  'medium','IBM VPC: Security Group Rule Deleted','A security group rule was removed from IBM VPC. Removal may open previously blocked traffic.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.iks_get_kubeconfig','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":"containers.cluster.config.get"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.iks_get_kubeconfig','containers_kubernetes','ibm',
  'medium','IBM IKS: Kubernetes Kubeconfig Retrieved','A kubeconfig was retrieved for an IBM Kubernetes Service cluster. Grants direct cluster API access.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.iks_list_clusters','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":"containers.cluster.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.iks_list_clusters','containers_kubernetes','ibm',
  'medium','IBM IKS: Kubernetes Clusters Listed','IBM Kubernetes Service clusters were listed. Enumeration reveals available cluster targets.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.secrets_get','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":"secrets-manager.secret.read"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.secrets_get','secrets_manager','ibm',
  'medium','IBM Secrets Manager: Secret Value Retrieved','A secret value was retrieved from IBM Secrets Manager.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.secrets_list','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":"secrets-manager.secret.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.secrets_list','secrets_manager','ibm',
  'medium','IBM Secrets Manager: Secrets Listed','Secrets were listed in IBM Secrets Manager. Enumeration of secret names is reconnaissance.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.activity_pause','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":"logdna.account.pause_ingestion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.activity_pause','logdna','ibm',
  'medium','IBM Activity Tracker: Log Collection Paused','IBM Activity Tracker log collection was paused. This creates a gap in the security audit trail.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.audit.event_streams_creds','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":"messagehub.cluster.read"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.audit.event_streams_creds','messagehub','ibm',
  'medium','IBM Event Streams: Service Credentials Listed','IBM Event Streams (Kafka) service credentials were listed, exposing broker connection details.',
  'threat_detection','audit_activity','ibm_activity',
  'ibm_activity_audit_activity','audit_activity',
  'log','{"ibm_ciem"}','ciem_engine',
  '["discovery","collection"]','["T1530","T1087","T1526"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_telnet_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"23"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_telnet_accept','vpc_flow','ibm',
  'medium','IBM VPC: Telnet Traffic Allowed (Port 23)','Telnet (port 23) was allowed. Plaintext protocol exposing credentials.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ibm_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_winrm_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"in","field":"network.dst_port","value":["5985","5986"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_winrm_accept','vpc_flow','ibm',
  'high','IBM VPC: WinRM Traffic Allowed (Ports 5985/5986)','WinRM allowed through IBM VPC. Enables remote PowerShell execution.',
  'threat_detection','execute','ibm_vpc_flow',
  'ibm_vpc_flow_execute','execute',
  'log','{"ibm_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_redis_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"6379"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_redis_accept','vpc_flow','ibm',
  'medium','IBM VPC: Redis Port Exposed (Port 6379)','Redis (port 6379) was allowed. Unauthenticated Redis instances are frequently compromised.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ibm_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_smtp_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"25"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_smtp_accept','vpc_flow','ibm',
  'medium','IBM VPC: SMTP Traffic Allowed (Port 25)','SMTP (port 25) allowed. Open relay enables spam and data exfiltration.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ibm_ciem"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_rdp_reject','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_rdp_reject','vpc_flow','ibm',
  'critical','IBM VPC: RDP Traffic Blocked — Possible Brute Force','RDP (port 3389) was rejected, indicating brute-force or scanning activity.',
  'threat_detection','brute_force','ibm_vpc_flow',
  'ibm_vpc_flow_brute_force','brute_force',
  'log','{"ibm_ciem"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authorization.kms_denied','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"kms"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authorization.kms_denied','kms','ibm',
  'high','IBM Key Protect: Unauthorized Key Operation','An unauthorized Key Protect operation was denied. May indicate key extraction attempt.',
  'threat_detection','authorization','ibm_activity',
  'ibm_activity_authorization','authorization',
  'log','{"ibm_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authorization.cos_denied','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"cloud_object_storage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authorization.cos_denied','cloud_object_storage','ibm',
  'high','IBM COS: Unauthorized Access','An unauthorized COS operation was denied. Repeated denials indicate data access probing.',
  'threat_detection','authorization','ibm_activity',
  'ibm_activity_authorization','authorization',
  'log','{"ibm_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authorization.secrets_denied','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"secrets_manager"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authorization.secrets_denied','secrets_manager','ibm',
  'high','IBM Secrets Manager: Unauthorized Secret Access','An unauthorized Secrets Manager operation was denied.',
  'threat_detection','authorization','ibm_activity',
  'ibm_activity_authorization','authorization',
  'log','{"ibm_ciem"}','ciem_engine',
  '["defense-evasion","privilege-escalation"]','["T1098","T1134"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.execute.code_engine_run','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":"codeengine.job-run.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.execute.code_engine_run','codeengine','ibm',
  'high','IBM Code Engine: Job Run Created','An IBM Code Engine job run was created. Code Engine executes arbitrary container workloads.',
  'threat_detection','execute','ibm_activity',
  'ibm_activity_execute','execute',
  'log','{"ibm_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.execute.vpc_instance_start','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":"is.instance.start"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.execute.vpc_instance_start','is','ibm',
  'high','IBM VPC: Instance Started','An IBM VPC virtual server instance was started.',
  'threat_detection','execute','ibm_activity',
  'ibm_activity_execute','execute',
  'log','{"ibm_ciem"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

COMMIT;
