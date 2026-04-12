-- IBM audit_activity expansion rules

-- threat.ibm.audit.account_settings_get
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.account_settings_get', 'iam_identity', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "iam_identity"}, {"op": "contains", "field": "operation", "value": "iam-identity.account.get"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.account_settings_get', 'iam_identity', 'ibm', 'medium',
    $t$IBM IAM: Account Settings Retrieved$t$, $t$IBM Cloud account identity settings (MFA config, session limits) were retrieved. Used for reconnaissance of auth controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.iam_account_settings_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.iam_account_settings_update', 'iam_identity', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "iam_identity"}, {"op": "contains", "field": "operation", "value": "iam-identity.account.update"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.iam_account_settings_update', 'iam_identity', 'ibm', 'medium',
    $t$IBM IAM: Account Identity Settings Updated$t$, $t$IBM Cloud account identity settings (MFA, session length, IP restrictions) were updated, potentially weakening auth controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.user_invite
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.user_invite', 'user_management', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "user_management"}, {"op": "contains", "field": "operation", "value": "user-management.user.invite"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.user_invite', 'user_management', 'ibm', 'medium',
    $t$IBM Cloud: User Invited to Account$t$, $t$A user was invited to the IBM Cloud account. Unexpected invitations may establish unauthorized access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.user_remove
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.user_remove', 'user_management', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "user_management"}, {"op": "contains", "field": "operation", "value": "user-management.user.remove"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.user_remove', 'user_management', 'ibm', 'medium',
    $t$IBM Cloud: User Removed from Account$t$, $t$A user was removed from the IBM Cloud account. This may be used to eliminate audit trails or lock out administrators.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.iam_service_policy_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.iam_service_policy_delete', 'iam', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "iam"}, {"op": "contains", "field": "operation", "value": "iam.policy.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.iam_service_policy_delete', 'iam', 'ibm', 'medium',
    $t$IBM IAM: Service Access Policy Deleted$t$, $t$An IAM service access policy was deleted, potentially removing restrictions on service-to-service calls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.iam_trusted_profile_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.iam_trusted_profile_update', 'iam_identity', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "iam_identity"}, {"op": "contains", "field": "operation", "value": "iam-identity.profile.update"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.iam_trusted_profile_update', 'iam_identity', 'ibm', 'medium',
    $t$IBM IAM: Trusted Profile Updated$t$, $t$An IAM trusted profile (compute resource identity) was updated. Changes may expand what resources can assume the profile.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.cbr_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.cbr_delete', 'context_based_restrictions', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "context_based_restrictions"}, {"op": "contains", "field": "operation", "value": "context-based-restrictions.rule.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.cbr_delete', 'context_based_restrictions', 'ibm', 'medium',
    $t$IBM CBR: Context-Based Restriction Rule Deleted$t$, $t$A context-based restriction rule was deleted, removing network or resource-based access controls.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.cbr_zone_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.cbr_zone_delete', 'context_based_restrictions', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "context_based_restrictions"}, {"op": "contains", "field": "operation", "value": "context-based-restrictions.zone.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.cbr_zone_delete', 'context_based_restrictions', 'ibm', 'medium',
    $t$IBM CBR: Context-Based Restriction Zone Deleted$t$, $t$A CBR network zone was deleted, potentially expanding the allowed source networks for service access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.resource_instance_creds_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.resource_instance_creds_list', 'resource_controller', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "resource_controller"}, {"op": "contains", "field": "operation", "value": "resource-controller.key.list"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.resource_instance_creds_list', 'resource_controller', 'ibm', 'medium',
    $t$IBM Resource: Service Instance Credentials Listed$t$, $t$Service credentials (API keys) for a resource instance were listed. These credentials provide direct service access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.resource_instance_creds_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.resource_instance_creds_create', 'resource_controller', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "resource_controller"}, {"op": "contains", "field": "operation", "value": "resource-controller.key.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.resource_instance_creds_create', 'resource_controller', 'ibm', 'medium',
    $t$IBM Resource: Service Instance Credentials Created$t$, $t$New credentials were created for a resource instance. New credentials provide additional access paths to the service.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.resource_instance_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.resource_instance_delete', 'resource_controller', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "resource_controller"}, {"op": "contains", "field": "operation", "value": "resource-controller.instance.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.resource_instance_delete', 'resource_controller', 'ibm', 'medium',
    $t$IBM Resource: Service Instance Deleted$t$, $t$A resource service instance was deleted. This is a destructive action that removes the service and its data.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.cos_object_read
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.cos_object_read', 'cloud_object_storage', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "cloud_object_storage"}, {"op": "contains", "field": "operation", "value": "cloud-object-storage.object.read"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.cos_object_read', 'cloud_object_storage', 'ibm', 'medium',
    $t$IBM COS: Object Read from Bucket$t$, $t$An object was read from an IBM Cloud Object Storage bucket. Monitor for access to sensitive data stores.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.cos_replication_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.cos_replication_create', 'cloud_object_storage', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "cloud_object_storage"}, {"op": "contains", "field": "operation", "value": "cloud-object-storage.bucket-replication.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.cos_replication_create', 'cloud_object_storage', 'ibm', 'medium',
    $t$IBM COS: Bucket Replication Configuration Created$t$, $t$Bucket replication was configured, routing all object copies to another destination that may be attacker-controlled.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.cos_lifecycle_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.cos_lifecycle_delete', 'cloud_object_storage', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "cloud_object_storage"}, {"op": "contains", "field": "operation", "value": "cloud-object-storage.bucket-lifecycle.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.cos_lifecycle_delete', 'cloud_object_storage', 'ibm', 'medium',
    $t$IBM COS: Bucket Lifecycle Policy Deleted$t$, $t$Bucket lifecycle policy was deleted, potentially preserving sensitive data beyond intended retention period.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.vpc_floating_ip_add
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.vpc_floating_ip_add', 'is', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "is"}, {"op": "contains", "field": "operation", "value": "is.floating-ip.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.vpc_floating_ip_add', 'is', 'ibm', 'medium',
    $t$IBM VPC: Floating IP Created (Public Exposure)$t$, $t$A floating IP was created in IBM VPC, potentially assigning a public IP address to a private instance.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.vpc_acl_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.vpc_acl_create', 'is', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "is"}, {"op": "contains", "field": "operation", "value": "is.network-acl.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.vpc_acl_create', 'is', 'ibm', 'medium',
    $t$IBM VPC: Network ACL Created$t$, $t$A new network ACL was created in IBM VPC, modifying traffic filtering for associated subnets.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.vpc_image_export
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.vpc_image_export', 'is', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "is"}, {"op": "contains", "field": "operation", "value": "is.image.export"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.vpc_image_export', 'is', 'ibm', 'medium',
    $t$IBM VPC: Custom Image Exported$t$, $t$A VPC custom image was exported to COS. Exported images may contain sensitive data or OS configurations.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.vpc_ssh_key_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.vpc_ssh_key_create', 'is', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "is"}, {"op": "contains", "field": "operation", "value": "is.key.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.vpc_ssh_key_create', 'is', 'ibm', 'medium',
    $t$IBM VPC: SSH Key Created$t$, $t$An SSH key was created in IBM VPC. New SSH keys can be injected into instances at creation for unauthorized access.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.iks_worker_reboot
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.iks_worker_reboot', 'containers_kubernetes', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "containers_kubernetes"}, {"op": "contains", "field": "operation", "value": "containers.worker.reboot"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.iks_worker_reboot', 'containers_kubernetes', 'ibm', 'medium',
    $t$IBM IKS: Worker Node Rebooted$t$, $t$An IKS Kubernetes worker node was rebooted. May be used to disrupt workloads or force pod restarts.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.code_engine_app_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.code_engine_app_create', 'codeengine', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "codeengine"}, {"op": "contains", "field": "operation", "value": "codeengine.application.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.code_engine_app_create', 'codeengine', 'ibm', 'medium',
    $t$IBM Code Engine: Application Deployed$t$, $t$A Code Engine application was deployed. Monitor for unauthorized serverless workload deployments.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.code_engine_job_run
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.code_engine_job_run', 'codeengine', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "codeengine"}, {"op": "contains", "field": "operation", "value": "codeengine.jobrun.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.code_engine_job_run', 'codeengine', 'ibm', 'medium',
    $t$IBM Code Engine: Job Run Created$t$, $t$A Code Engine batch job run was created. Unexpected job executions may perform unauthorized data processing.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.transit_gw_connect
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.transit_gw_connect', 'transit', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "transit"}, {"op": "contains", "field": "operation", "value": "transit.connection.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.transit_gw_connect', 'transit', 'ibm', 'medium',
    $t$IBM Transit Gateway: Connection Created$t$, $t$A Transit Gateway connection was created, linking two networks. Unexpected connections may enable lateral movement.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.directlink_gw_list
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.directlink_gw_list', 'directlink', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "directlink"}, {"op": "contains", "field": "operation", "value": "directlink.gateway.list"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.directlink_gw_list', 'directlink', 'ibm', 'medium',
    $t$IBM Direct Link: Gateways Listed$t$, $t$Direct Link gateways were listed. This reveals on-premises network connectivity and potential pivot targets.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.schematics_workspace_run
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.schematics_workspace_run', 'schematics', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "schematics"}, {"op": "contains", "field": "operation", "value": "schematics.workspace-run.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.schematics_workspace_run', 'schematics', 'ibm', 'medium',
    $t$IBM Schematics: Workspace Job Run Created$t$, $t$An IBM Schematics (Terraform) workspace job was triggered. Jobs can create, modify, or destroy cloud resources.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.appid_client_secret
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.appid_client_secret', 'appid', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "appid"}, {"op": "contains", "field": "operation", "value": "appid.application.read"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.appid_client_secret', 'appid', 'ibm', 'medium',
    $t$IBM App ID: Application Client Secret Retrieved$t$, $t$App ID application secrets were retrieved. These secrets authenticate OAuth2 client applications.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.scc_scope_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.scc_scope_create', 'compliance', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "compliance"}, {"op": "contains", "field": "operation", "value": "compliance.posture.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.scc_scope_create', 'compliance', 'ibm', 'medium',
    $t$IBM Security and Compliance Center: Scope Created$t$, $t$A new SCC scope was created, defining which IBM Cloud resources to evaluate for compliance.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.monitoring_alert_delete
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.monitoring_alert_delete', 'sysdig_monitor', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "sysdig_monitor"}, {"op": "contains", "field": "operation", "value": "sysdig-monitor.alert.delete"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.monitoring_alert_delete', 'sysdig_monitor', 'ibm', 'medium',
    $t$IBM Monitoring: Alert Rule Deleted$t$, $t$A monitoring alert rule was deleted, removing visibility into performance anomalies or security events.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.monitoring_dashboard_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.monitoring_dashboard_update', 'sysdig_monitor', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "sysdig_monitor"}, {"op": "contains", "field": "operation", "value": "sysdig-monitor.dashboard.update"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.monitoring_dashboard_update', 'sysdig_monitor', 'ibm', 'medium',
    $t$IBM Monitoring: Dashboard Updated$t$, $t$A monitoring dashboard was updated. Dashboards reveal what operational metrics are being tracked.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.kms_key_import
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.kms_key_import', 'kms', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "kms"}, {"op": "contains", "field": "operation", "value": "kms.secrets.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.kms_key_import', 'kms', 'ibm', 'medium',
    $t$IBM Key Protect: Key Created or Imported$t$, $t$A root key was created or imported into IBM Key Protect. Imported keys use external key material.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.secrets_rotation_update
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.secrets_rotation_update', 'secrets_manager', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "secrets_manager"}, {"op": "contains", "field": "operation", "value": "secrets-manager.secret-rotation.set"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.secrets_rotation_update', 'secrets_manager', 'ibm', 'medium',
    $t$IBM Secrets Manager: Secret Auto-Rotation Configuration Updated$t$, $t$Secret auto-rotation settings were updated. Disabling rotation keeps credentials active indefinitely.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.toolchain_pipeline_run
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.toolchain_pipeline_run', 'toolchain', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "toolchain"}, {"op": "contains", "field": "operation", "value": "toolchain.pipeline-run.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.toolchain_pipeline_run', 'toolchain', 'ibm', 'medium',
    $t$IBM Toolchain: CI/CD Pipeline Run Triggered$t$, $t$A Continuous Delivery pipeline run was triggered. Unexpected pipeline runs may deploy unauthorized code.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;

-- threat.ibm.audit.satellite_location_create
BEGIN;
INSERT INTO rule_checks(rule_id, service, provider, check_type, check_config, is_active, source, generated_by)
VALUES ('threat.ibm.audit.satellite_location_create', 'satellite', 'ibm', 'log', '{"conditions": {"all": [{"op": "equals", "field": "source_type", "value": "ibm_activity"}, {"op": "equals", "field": "service", "value": "satellite"}, {"op": "contains", "field": "operation", "value": "satellite.location.create"}]}}'::jsonb, true, 'ciem', 'ciem_audit_expansion')
ON CONFLICT DO NOTHING;
INSERT INTO rule_metadata(rule_id, service, provider, severity, title, description, domain, subcategory,
    metadata_source, source, generated_by, threat_tags)
VALUES ('threat.ibm.audit.satellite_location_create', 'satellite', 'ibm', 'medium',
    $t$IBM Satellite: Satellite Location Created$t$, $t$An IBM Satellite location was created, extending IBM Cloud to an on-premises or edge environment.$t$,
    'threat_detection', 'audit_activity', 'ciem', 'ciem', 'ciem_audit_expansion',
    '["T1087","T1530","T1526","T1082"]'::jsonb)
ON CONFLICT DO NOTHING;
COMMIT;
