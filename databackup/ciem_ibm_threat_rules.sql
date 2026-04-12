-- CIEM IBM Threat Detection Rules
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_ssh_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_ssh_accept','vpc_flow','ibm',
  'medium','IBM VPC: SSH Traffic Allowed','SSH traffic (port 22) was allowed through IBM Cloud VPC network access controls.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_rdp_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_rdp_accept','vpc_flow','ibm',
  'medium','IBM VPC: RDP Traffic Allowed','RDP traffic (port 3389) was allowed through IBM Cloud VPC network access controls.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_db_accept','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"in","field":"network.dst_port","value":["3306","5432","1433","27017","6379"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_db_accept','vpc_flow','ibm',
  'medium','IBM VPC: Database Port Exposed','Database ports (3306/5432/1433/27017/6379) were allowed through IBM Cloud VPC.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_dns','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.dst_port","value":"53"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_dns','vpc_flow','ibm',
  'medium','IBM VPC: DNS Traffic Detected','DNS traffic (port 53) detected through IBM VPC. High volumes may indicate C2 tunneling.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_ssh_reject','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_ssh_reject','vpc_flow','ibm',
  'critical','IBM VPC: SSH Traffic Blocked — Possible Brute Force','SSH traffic (port 22) was rejected by IBM VPC, indicating brute-force or scanning activity.',
  'threat_detection','brute_force','ibm_vpc_flow',
  'ibm_vpc_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.network.vpc_rejected','vpc_flow','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.network.vpc_rejected','vpc_flow','ibm',
  'medium','IBM VPC: Traffic Rejected','Network traffic was rejected by IBM VPC security rules. May indicate port scanning.',
  'threat_detection','network','ibm_vpc_flow',
  'ibm_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.iam_policy_create','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.policy.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.iam_policy_create','iam_identity','ibm',
  'critical','IBM IAM: Policy Created','A new IBM Cloud IAM access policy was created, granting permissions to identities.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.access_group_member','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.access-group-member.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.access_group_member','iam_identity','ibm',
  'critical','IBM IAM: User Added to Access Group','A member was added to an IBM Cloud IAM Access Group, inheriting all group permissions.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.service_api_key_create','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.serviceid-apikey.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.service_api_key_create','iam_identity','ibm',
  'critical','IBM IAM: Service ID API Key Created','An API key was created for an IBM Service ID. Service ID keys provide programmatic access.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.user_api_key_create','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.user-apikey.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.user_api_key_create','iam_identity','ibm',
  'critical','IBM IAM: User API Key Created','An API key was created for an IBM Cloud user. API keys provide long-lived authentication credentials.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.service_id_create','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.serviceid.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.service_id_create','iam_identity','ibm',
  'critical','IBM IAM: Service ID Created','A new IBM Cloud Service ID was created. Service IDs are used for programmatic API access.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.privilege_escalation.trusted_profile_create','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.profile.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.privilege_escalation.trusted_profile_create','iam_identity','ibm',
  'critical','IBM IAM: Trusted Profile Created','A new IBM Cloud Trusted Profile was created, enabling federated access to IBM Cloud resources.',
  'threat_detection','privilege_escalation','ibm_activity',
  'ibm_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authentication.login_failed','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity.user.login"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authentication.login_failed','iam_identity','ibm',
  'high','IBM IAM: User Login Failed','An IBM Cloud user login failed. Repeated failures may indicate brute-force or account takeover.',
  'threat_detection','authentication','ibm_activity',
  'ibm_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authentication.api_key_failed','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":"iam-identity"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authentication.api_key_failed','iam_identity','ibm',
  'high','IBM IAM: API Key Authentication Failed','Authentication using an IBM Cloud API key failed. May indicate key rotation needed or attack.',
  'threat_detection','authentication','ibm_activity',
  'ibm_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.authentication.iam_auth_failed','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"iam"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.authentication.iam_auth_failed','iam','ibm',
  'high','IBM IAM: Authorization Failed','An IBM Cloud IAM authorization check failed. May indicate privilege probing.',
  'threat_detection','authentication','ibm_activity',
  'ibm_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.reconnaissance.kms_key_list','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.reconnaissance.kms_key_list','kms','ibm',
  'medium','IBM KMS: Encryption Keys Listed','IBM Key Protect encryption keys were listed. Key enumeration may precede key extraction attempts.',
  'threat_detection','reconnaissance','ibm_activity',
  'ibm_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.reconnaissance.secrets_list','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":"secrets-manager.secret.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.reconnaissance.secrets_list','secrets_manager','ibm',
  'medium','IBM Secrets Manager: Secrets Listed','Secrets in IBM Secrets Manager were listed. Enumeration may precede unauthorized secret access.',
  'threat_detection','reconnaissance','ibm_activity',
  'ibm_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.reconnaissance.iam_policy_list','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":"iam.policy.list"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.reconnaissance.iam_policy_list','iam','ibm',
  'medium','IBM IAM: Policies Listed','IBM Cloud IAM policies were listed. Policy enumeration is a common reconnaissance technique.',
  'threat_detection','reconnaissance','ibm_activity',
  'ibm_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.execute.containers_pod_exec','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":"containers.pod.exec"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.execute.containers_pod_exec','is','ibm',
  'high','IBM Containers: Pod Exec Command Executed','An exec command was run inside an IBM Containers Kubernetes pod.',
  'threat_detection','execute','ibm_activity',
  'ibm_activity_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.execute.function_invoke','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":"functions.action.invoke"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.execute.function_invoke','functions','ibm',
  'high','IBM Functions: Action Invoked','An IBM Cloud Functions action was invoked. Review for unauthorized code execution.',
  'threat_detection','execute','ibm_activity',
  'ibm_activity_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.threat.security_high','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"security_insights"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.threat.security_high','iam_identity','ibm',
  'high','IBM Security: High Severity Finding','IBM Cloud Security detected a high severity security event requiring investigation.',
  'threat_detection','threat','ibm_activity',
  'ibm_activity_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.threat.kms_key_delete','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":"kms.secrets.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.threat.kms_key_delete','kms','ibm',
  'high','IBM KMS: Encryption Key Deleted','An IBM Key Protect encryption key was deleted. Key deletion may cause data inaccessibility.',
  'threat_detection','threat','ibm_activity',
  'ibm_activity_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.threat.secrets_delete','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":"secrets-manager.secret.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.threat.secrets_delete','secrets_manager','ibm',
  'high','IBM Secrets Manager: Secret Deleted','A secret was deleted from IBM Secrets Manager. May disrupt applications or indicate data destruction.',
  'threat_detection','threat','ibm_activity',
  'ibm_activity_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.exfiltration.cos_bucket_public','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket-acl.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.exfiltration.cos_bucket_public','cloud_object_storage','ibm',
  'critical','IBM Cloud Object Storage: Bucket ACL Modified','IBM COS bucket access control was modified, potentially exposing data publicly.',
  'threat_detection','exfiltration','ibm_activity',
  'ibm_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.ibm.exfiltration.cos_credentials','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":"cloud-object-storage.bucket-credentials.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.ibm.exfiltration.cos_credentials','cloud_object_storage','ibm',
  'critical','IBM Cloud Object Storage: HMAC Credentials Created','HMAC credentials were created for IBM COS, enabling programmatic storage access.',
  'threat_detection','exfiltration','ibm_activity',
  'ibm_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','ibm'
) ON CONFLICT DO NOTHING;

COMMIT;
