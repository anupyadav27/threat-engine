-- CIEM OCI Threat Detection Rules
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_ssh_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_ssh_accept','vcn_flow','oci',
  'medium','OCI VCN: SSH Traffic Allowed','SSH traffic (port 22) was allowed through an OCI VCN Security List or NSG.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_rdp_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_rdp_accept','vcn_flow','oci',
  'medium','OCI VCN: RDP Traffic Allowed','RDP traffic (port 3389) was allowed through an OCI VCN Security List or NSG.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_db_accept','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"ACCEPT"},{"op":"in","field":"network.dst_port","value":["3306","5432","1521","27017","6379"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_db_accept','vcn_flow','oci',
  'medium','OCI VCN: Database Port Exposed','Database ports (3306/5432/1521/27017/6379) were allowed through OCI VCN.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_dns','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.dst_port","value":"53"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_dns','vcn_flow','oci',
  'medium','OCI VCN: DNS Traffic Detected','DNS traffic (port 53) detected through OCI VCN. May indicate C2 tunneling if volumes are high.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_ssh_reject','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_ssh_reject','vcn_flow','oci',
  'critical','OCI VCN: SSH Traffic Blocked — Possible Brute Force','SSH traffic (port 22) was rejected by OCI VCN, indicating brute-force or scanning activity.',
  'threat_detection','brute_force','oci_vcn_flow',
  'oci_vcn_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_rdp_reject','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_rdp_reject','vcn_flow','oci',
  'critical','OCI VCN: RDP Traffic Blocked — Possible Brute Force','RDP traffic (port 3389) was rejected by OCI VCN, indicating brute-force or scanning activity.',
  'threat_detection','brute_force','oci_vcn_flow',
  'oci_vcn_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.network.vcn_rejected','vcn_flow','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_vcn_flow"},{"op":"equals","field":"network.flow_action","value":"REJECT"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.network.vcn_rejected','vcn_flow','oci',
  'medium','OCI VCN: Traffic Rejected','Network traffic was rejected by OCI VCN rules. Unusual reject patterns may indicate port scanning.',
  'threat_detection','network','oci_vcn_flow',
  'oci_vcn_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_critical','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"equals","field":"severity","value":"CRITICAL"},{"op":"equals","field":"operation","value":"ProblemDetected"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_critical','cloudguard','oci',
  'high','OCI Cloud Guard: Critical Problem Detected','Oracle Cloud Guard detected a Critical severity security problem. Immediate action required.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_high','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"equals","field":"severity","value":"HIGH"},{"op":"equals","field":"operation","value":"ProblemDetected"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_high','cloudguard','oci',
  'high','OCI Cloud Guard: High Severity Problem Detected','Oracle Cloud Guard detected a High severity security problem in OCI resources.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_threat','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"equals","field":"operation","value":"ThreatDetected"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_threat','cloudguard','oci',
  'high','OCI Cloud Guard: Threat Detected','Oracle Cloud Guard raised a threat detection event for an OCI resource.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_security_zone','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"equals","field":"operation","value":"SecurityZoneViolation"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_security_zone','cloudguard','oci',
  'high','OCI Cloud Guard: Security Zone Violation','An OCI Security Zone policy violation was detected. Resources must conform to security zone requirements.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_responder','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"in","field":"operation","value":["ResponderExecuted","TriggerResponder"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_responder','cloudguard','oci',
  'high','OCI Cloud Guard: Responder Executed','A Cloud Guard Responder was triggered in response to a security problem.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_detector_change','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"in","field":"operation","value":["UpdateDetectorRecipe","DeleteDetectorRecipe","CreateDetectorRecipe"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_detector_change','cloudguard','oci',
  'high','OCI Cloud Guard: Detector Recipe Modified','A Cloud Guard Detector Recipe was created, updated, or deleted, potentially disabling threat detection.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_target_change','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"in","field":"operation","value":["UpdateTarget","DeleteTarget","CreateTarget"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_target_change','cloudguard','oci',
  'high','OCI Cloud Guard: Target Configuration Modified','A Cloud Guard monitoring target was modified. Changes may reduce security monitoring coverage.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.threat.cloudguard_managed_list','cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_cloudguard"},{"op":"in","field":"operation","value":["UpdateManagedList","DeleteManagedList","CreateManagedList"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.threat.cloudguard_managed_list','cloudguard','oci',
  'high','OCI Cloud Guard: Managed List Modified','A Cloud Guard Managed List (trusted IPs, approved resources) was modified.',
  'threat_detection','threat','oci_cloudguard',
  'oci_cloudguard_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.policy_create','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreatePolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.policy_create','identity','oci',
  'critical','OCI IAM: Policy Created','A new OCI IAM policy was created. Policies control access to all OCI resources.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.policy_update','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"UpdatePolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.policy_update','identity','oci',
  'critical','OCI IAM: Policy Updated','An OCI IAM policy was updated, potentially granting additional permissions.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.group_member_add','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"AddUserToGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.group_member_add','identity','oci',
  'critical','OCI IAM: User Added to Group','A user was added to an OCI IAM group, inheriting all group permissions.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.api_key_create','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"UploadApiKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.api_key_create','identity','oci',
  'critical','OCI IAM: API Key Created','A new API signing key was added to an OCI user. API keys provide persistent programmatic access.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.auth_token_create','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreateAuthToken"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.auth_token_create','identity','oci',
  'critical','OCI IAM: Auth Token Created','A new auth token was created for an OCI user. Auth tokens are used for Swift API access.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.privilege_escalation.user_created','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreateUser"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.privilege_escalation.user_created','identity','oci',
  'critical','OCI IAM: New User Created','A new OCI IAM user was created. Review for unauthorized account creation.',
  'threat_detection','privilege_escalation','oci_audit',
  'oci_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.authentication.identity_failed','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.authentication.identity_failed','identity','oci',
  'high','OCI IAM: Authentication Failure','An OCI IAM operation failed with an authentication error. Review for unauthorized access attempts.',
  'threat_detection','authentication','oci_audit',
  'oci_audit_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.authentication.compute_failed','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.authentication.compute_failed','compute','oci',
  'high','OCI Compute: Authentication Failure','An OCI Compute operation failed with an authentication error.',
  'threat_detection','authentication','oci_audit',
  'oci_audit_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.execute.bastion_session','bastion','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bastion"},{"op":"equals","field":"operation","value":"CreateSession"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.execute.bastion_session','bastion','oci',
  'high','OCI Bastion: Session Created','A Bastion Service session was created to access OCI resources. Review session targets and users.',
  'threat_detection','execute','oci_audit',
  'oci_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.execute.instance_console','compute','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"CreateInstanceConsoleConnection"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.execute.instance_console','compute','oci',
  'high','OCI Compute: Instance Console Connection Created','A console connection to an OCI compute instance was established. May indicate unauthorized instance access.',
  'threat_detection','execute','oci_audit',
  'oci_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.execute.oke_node_pool_create','containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"CreateNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.execute.oke_node_pool_create','containerengine','oci',
  'high','OCI OKE: Node Pool Created','A new OKE (Kubernetes) node pool was created. Review for unauthorized cluster expansion.',
  'threat_detection','execute','oci_audit',
  'oci_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.reconnaissance.vault_secret_list','vault','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"ListSecrets"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.reconnaissance.vault_secret_list','vault','oci',
  'medium','OCI Vault: Secrets Listed','Secrets in OCI Vault were listed. Enumeration of secrets may precede credential theft.',
  'threat_detection','reconnaissance','oci_audit',
  'oci_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.reconnaissance.policy_list','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"ListPolicies"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.reconnaissance.policy_list','identity','oci',
  'medium','OCI IAM: Policies Listed','OCI IAM policies were listed. Policy enumeration is a common reconnaissance technique.',
  'threat_detection','reconnaissance','oci_audit',
  'oci_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.reconnaissance.user_list','identity','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"ListUsers"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.reconnaissance.user_list','identity','oci',
  'medium','OCI IAM: Users Listed','OCI IAM users were listed. User enumeration may indicate reconnaissance of the identity plane.',
  'threat_detection','reconnaissance','oci_audit',
  'oci_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.exfiltration.bucket_public_access','objectstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.objectstorage"},{"op":"equals","field":"operation","value":"UpdateBucket"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.exfiltration.bucket_public_access','objectstorage','oci',
  'critical','OCI Object Storage: Bucket Made Public','An OCI Object Storage bucket was made publicly accessible, risking data exposure.',
  'threat_detection','exfiltration','oci_audit',
  'oci_audit_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.oci.exfiltration.pre_auth_request','objectstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.objectstorage"},{"op":"equals","field":"operation","value":"CreatePreauthenticatedRequest"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.oci.exfiltration.pre_auth_request','objectstorage','oci',
  'critical','OCI Object Storage: Pre-Authenticated Request Created','A pre-authenticated request was created for an OCI bucket, allowing external data access.',
  'threat_detection','exfiltration','oci_audit',
  'oci_audit_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','oci'
) ON CONFLICT DO NOTHING;

COMMIT;
