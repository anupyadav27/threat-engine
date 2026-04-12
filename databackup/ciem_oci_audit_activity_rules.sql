-- OCI audit_activity expansion rules

-- threat.oci.audit.dynamic_group_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.dynamic_group_create', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "CreateDynamicGroup"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.dynamic_group_create', 'identity', 'oci', 'medium',
    $t$OCI IAM: Dynamic Group Created$t$, $t$An OCI dynamic group was created. Dynamic groups grant instance principals access to OCI resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.dynamic_group_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.dynamic_group_update', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "UpdateDynamicGroup"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.dynamic_group_update', 'identity', 'oci', 'medium',
    $t$OCI IAM: Dynamic Group Updated$t$, $t$An OCI dynamic group was updated. Changes to matching rules may extend resource access to unintended instances.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.compartment_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.compartment_create', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "CreateCompartment"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.compartment_create', 'identity', 'oci', 'medium',
    $t$OCI IAM: Compartment Created$t$, $t$A new OCI compartment was created. Compartments isolate resources and their policies.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.compartment_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.compartment_delete', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "DeleteCompartment"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.compartment_delete', 'identity', 'oci', 'medium',
    $t$OCI IAM: Compartment Deleted$t$, $t$An OCI compartment was deleted. Deleting a compartment removes all resources within it.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.federation_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.federation_create', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "CreateIdentityProvider"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.federation_create', 'identity', 'oci', 'medium',
    $t$OCI IAM: Identity Federation Provider Created$t$, $t$An identity federation provider (SAML/OIDC) was created, enabling external users to authenticate to OCI.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.saml_assertion_map
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.saml_assertion_map', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "CreateIdpGroupMapping"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.saml_assertion_map', 'identity', 'oci', 'medium',
    $t$OCI IAM: IdP Group Mapping Created$t$, $t$An IdP group was mapped to an OCI group, granting external identity users access to OCI resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.auth_token_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.auth_token_list', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "ListAuthTokens"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.auth_token_list', 'identity', 'oci', 'medium',
    $t$OCI IAM: Auth Tokens Listed$t$, $t$Auth tokens (used for third-party API access) were listed. These tokens provide programmatic access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.smtp_credentials_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.smtp_credentials_list', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "ListSmtpCredentials"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.smtp_credentials_list', 'identity', 'oci', 'medium',
    $t$OCI IAM: SMTP Credentials Listed$t$, $t$SMTP credentials were listed. These allow sending email via OCI Email Delivery service.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.user_group_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.user_group_list', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "ListUserGroupMemberships"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.user_group_list', 'identity', 'oci', 'medium',
    $t$OCI IAM: User Group Memberships Listed$t$, $t$User group memberships were enumerated. This reveals privilege mapping across OCI groups.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.mfa_device_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.mfa_device_delete', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "DeleteMfaTotpDevice"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.mfa_device_delete', 'identity', 'oci', 'medium',
    $t$OCI IAM: MFA Device Deleted from User$t$, $t$An MFA TOTP device was deleted from an OCI user account, weakening authentication.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.iam_user_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.iam_user_create', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "CreateUser"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.iam_user_create', 'identity', 'oci', 'medium',
    $t$OCI IAM: User Account Created$t$, $t$A new OCI IAM user was created. Monitor for unauthorized user creation that may establish persistence.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.policy_get
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.policy_get', 'identity', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identity"}, {"op": "contains", "field": "operation", "value": "GetPolicy"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.policy_get', 'identity', 'oci', 'medium',
    $t$OCI IAM: Policy Retrieved$t$, $t$An OCI IAM policy was retrieved. Attackers enumerate policies to understand granted permissions.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.kms_key_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.kms_key_create', 'kms', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.keymanagement"}, {"op": "contains", "field": "operation", "value": "CreateKey"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.kms_key_create', 'kms', 'oci', 'medium',
    $t$OCI KMS: Encryption Key Created$t$, $t$A new OCI KMS encryption key was created. Monitor for unexpected key creation that may be used to encrypt exfiltrated data.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.kms_key_import
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.kms_key_import', 'kms', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.keymanagement"}, {"op": "contains", "field": "operation", "value": "ImportKeyVersion"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.kms_key_import', 'kms', 'oci', 'medium',
    $t$OCI KMS: Key Material Imported$t$, $t$External key material was imported into OCI KMS, replacing Oracle-managed entropy with a user-controlled key.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.vault_secret_version
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.vault_secret_version', 'vault', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.vault"}, {"op": "contains", "field": "operation", "value": "CreateSecretVersion"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.vault_secret_version', 'vault', 'oci', 'medium',
    $t$OCI Vault: New Secret Version Created$t$, $t$A new version was added to an OCI Vault secret. This may rotate credentials or inject malicious values.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.vault_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.vault_delete', 'vault', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.vault"}, {"op": "contains", "field": "operation", "value": "ScheduleVaultDeletion"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.vault_delete', 'vault', 'oci', 'medium',
    $t$OCI Vault: Vault Scheduled for Deletion$t$, $t$An OCI Vault was scheduled for deletion. This will destroy all keys and secrets after the waiting period.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.object_storage_policy
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.object_storage_policy', 'objectstorage', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.objectstorage"}, {"op": "contains", "field": "operation", "value": "UpdateBucket"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.object_storage_policy', 'objectstorage', 'oci', 'medium',
    $t$OCI Object Storage: Bucket Configuration Updated$t$, $t$OCI Object Storage bucket configuration was updated, potentially changing access policies or versioning settings.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.object_storage_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.object_storage_list', 'objectstorage', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.objectstorage"}, {"op": "contains", "field": "operation", "value": "ListBuckets"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.object_storage_list', 'objectstorage', 'oci', 'medium',
    $t$OCI Object Storage: Buckets Listed$t$, $t$OCI Object Storage buckets were enumerated. Listing buckets reveals available data stores for targeted exfiltration.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.object_get
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.object_get', 'objectstorage', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.objectstorage"}, {"op": "contains", "field": "operation", "value": "GetObject"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.object_get', 'objectstorage', 'oci', 'medium',
    $t$OCI Object Storage: Object Retrieved$t$, $t$An object was retrieved from OCI Object Storage. Monitor for access to sensitive configuration or data files.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.streaming_creds_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.streaming_creds_list', 'streaming', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.streaming"}, {"op": "contains", "field": "operation", "value": "ListStreams"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.streaming_creds_list', 'streaming', 'oci', 'medium',
    $t$OCI Streaming: Streams Listed$t$, $t$OCI Streaming (managed Kafka) streams were listed. Streams can carry sensitive event data.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.streaming_message_get
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.streaming_message_get', 'streaming', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.streaming"}, {"op": "contains", "field": "operation", "value": "GetMessages"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.streaming_message_get', 'streaming', 'oci', 'medium',
    $t$OCI Streaming: Messages Retrieved from Stream$t$, $t$Messages were read from an OCI streaming topic. Sensitive operational data may be exposed.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.functions_invoke_audit
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.functions_invoke_audit', 'functions', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.functions"}, {"op": "contains", "field": "operation", "value": "InvokeFunction"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.functions_invoke_audit', 'functions', 'oci', 'medium',
    $t$OCI Functions: Function Invoked$t$, $t$An OCI function was invoked. Unauthorized function invocations may execute malicious code or access sensitive resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.resource_manager_job
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.resource_manager_job', 'resourcemanager', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.resourcemanager"}, {"op": "contains", "field": "operation", "value": "CreateJob"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.resource_manager_job', 'resourcemanager', 'oci', 'medium',
    $t$OCI Resource Manager: Terraform Job Created$t$, $t$An OCI Resource Manager (Terraform) job was created. Infrastructure-as-code jobs can create, modify, or destroy resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.adb_rotate_wallet
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.adb_rotate_wallet', 'database', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.database"}, {"op": "contains", "field": "operation", "value": "RotateAutonomousDatabaseEncryptionKey"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.adb_rotate_wallet', 'database', 'oci', 'medium',
    $t$OCI Autonomous DB: Encryption Key Rotated$t$, $t$The encryption key for an Autonomous Database was rotated. Unexpected key rotation may indicate compromise.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.db_home_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.db_home_delete', 'database', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.database"}, {"op": "contains", "field": "operation", "value": "DeleteDbHome"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.db_home_delete', 'database', 'oci', 'medium',
    $t$OCI Database: DB Home Deleted$t$, $t$An OCI Database Home was deleted, removing all databases within it. This is a destructive operation.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.db_system_stop
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.db_system_stop', 'database', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.database"}, {"op": "contains", "field": "operation", "value": "DbNodeAction"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.db_system_stop', 'database', 'oci', 'medium',
    $t$OCI Database: DB Node Action Triggered$t$, $t$An action (stop/start/reset) was triggered on an OCI DB node. Stopping nodes causes database downtime.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.certificate_issued
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.certificate_issued', 'certificates', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.certificatesmanagement"}, {"op": "contains", "field": "operation", "value": "CreateCertificate"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.certificate_issued', 'certificates', 'oci', 'medium',
    $t$OCI Certificates: Certificate Created$t$, $t$A TLS certificate was created via OCI Certificates service. Monitor for unauthorized certificate issuance.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.service_connector_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.service_connector_create', 'sch', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.sch"}, {"op": "contains", "field": "operation", "value": "CreateServiceConnector"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.service_connector_create', 'sch', 'oci', 'medium',
    $t$OCI Service Connector Hub: Connector Created (Log Routing)$t$, $t$A Service Connector hub was created to route data between OCI services. May be used to exfiltrate logs or stream data.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.log_unified_search
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.log_unified_search', 'loggingsearch', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.loggingsearch"}, {"op": "contains", "field": "operation", "value": "SearchLogs"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.log_unified_search', 'loggingsearch', 'oci', 'medium',
    $t$OCI Logging: Log Search Executed$t$, $t$OCI unified logging was searched. Attackers may query logs to understand what monitoring is in place.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.event_rule_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.event_rule_create', 'events', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.events"}, {"op": "contains", "field": "operation", "value": "CreateRule"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.event_rule_create', 'events', 'oci', 'medium',
    $t$OCI Events: Event Rule Created$t$, $t$An OCI Events service rule was created. Event rules trigger actions (notifications, functions) on resource changes.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.identity_domain_deactivate
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.identity_domain_deactivate', 'identitydomain', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.identitydomains"}, {"op": "contains", "field": "operation", "value": "deactivate"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.identity_domain_deactivate', 'identitydomain', 'oci', 'medium',
    $t$OCI Identity Domain: Domain Deactivated$t$, $t$An OCI Identity Domain was deactivated, preventing all users in the domain from authenticating.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.oci.audit.drg_route_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.oci.audit.drg_route_create', 'network', 'oci', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "oci_audit"}, {"op": "equals", "field": "service", "value": "com.oraclecloud.virtualnetwork"}, {"op": "contains", "field": "operation", "value": "CreateDrgRouteTable"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.oci.audit.drg_route_create', 'network', 'oci', 'medium',
    $t$OCI DRG: Dynamic Routing Gateway Route Table Created$t$, $t$A DRG route table was created, potentially redirecting inter-VCN traffic through an attacker-controlled path.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;
