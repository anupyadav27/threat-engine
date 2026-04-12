-- CIEM GCP Threat Detection Rules
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_ssh_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_ssh_allow','vpc_flow','gcp',
  'medium','GCP VPC: SSH Traffic Allowed','SSH traffic (port 22) was allowed through GCP VPC firewall. Review for unauthorized remote access.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_rdp_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_rdp_allow','vpc_flow','gcp',
  'medium','GCP VPC: RDP Traffic Allowed','RDP traffic (port 3389) was allowed through GCP VPC firewall. Remote Desktop may expose systems.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_db_allow','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"ALLOWED"},{"op":"in","field":"network.dst_port","value":["3306","5432","1433","27017","6379"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_db_allow','vpc_flow','gcp',
  'medium','GCP VPC: Database Port Exposed','Database ports (3306/5432/1433/27017/6379) were allowed through GCP VPC firewall.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_dns','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.dst_port","value":"53"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_dns','vpc_flow','gcp',
  'medium','GCP VPC: DNS Traffic Detected','DNS traffic (port 53) detected. Unusual DNS traffic volumes may indicate C2 tunneling.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_ssh_denied','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"DENIED"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_ssh_denied','vpc_flow','gcp',
  'critical','GCP VPC: SSH Traffic Blocked — Possible Brute Force','SSH traffic (port 22) was denied by GCP VPC firewall, indicating brute-force or scanning activity.',
  'threat_detection','brute_force','gcp_vpc_flow',
  'gcp_vpc_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_rdp_denied','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"DENIED"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_rdp_denied','vpc_flow','gcp',
  'critical','GCP VPC: RDP Traffic Blocked — Possible Brute Force','RDP traffic (port 3389) was denied by GCP VPC firewall, indicating brute-force or scanning.',
  'threat_detection','brute_force','gcp_vpc_flow',
  'gcp_vpc_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.network.vpc_rejected','vpc_flow','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_vpc_flow"},{"op":"equals","field":"network.flow_action","value":"DENIED"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.network.vpc_rejected','vpc_flow','gcp',
  'medium','GCP VPC: Traffic Denied by Firewall','Network traffic was denied by a GCP VPC firewall rule. Repeated denies may indicate port scanning.',
  'threat_detection','network','gcp_vpc_flow',
  'gcp_vpc_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_critical','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"equals","field":"severity","value":"CRITICAL"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_critical','scc','gcp',
  'high','GCP SCC: Critical Security Finding','Google Cloud Security Command Center raised a Critical severity finding. Immediate investigation required.',
  'threat_detection','threat','gcp_scc',
  'gcp_scc_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_high','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"equals","field":"severity","value":"HIGH"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_high','scc','gcp',
  'high','GCP SCC: High Severity Security Finding','Google Cloud Security Command Center raised a High severity security finding.',
  'threat_detection','threat','gcp_scc',
  'gcp_scc_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_anomalous_access','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"ANOMALOUS_ACCESS"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_anomalous_access','scc','gcp',
  'medium','GCP SCC: Anomalous Access Detected','GCP Security Command Center detected anomalous access patterns to Google Cloud resources.',
  'threat_detection','reconnaissance','gcp_scc',
  'gcp_scc_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_brute_force','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"BRUTE_FORCE"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_brute_force','scc','gcp',
  'critical','GCP SCC: Brute Force Attack Detected','GCP Security Command Center detected a brute force attack against GCP resources.',
  'threat_detection','brute_force','gcp_scc',
  'gcp_scc_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_cryptomining','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"CRYPTO_MINING"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_cryptomining','scc','gcp',
  'high','GCP SCC: Cryptomining Activity Detected','GCP Security Command Center detected cryptomining activity on a GCP resource.',
  'threat_detection','cryptomining','gcp_scc',
  'gcp_scc_cryptomining','cryptomining',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1496"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_data_exfil','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"DATA_EXFILTRATION"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_data_exfil','scc','gcp',
  'critical','GCP SCC: Data Exfiltration Detected','GCP Security Command Center detected a data exfiltration event from GCP resources.',
  'threat_detection','exfiltration','gcp_scc',
  'gcp_scc_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_malware','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"MALWARE"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_malware','scc','gcp',
  'critical','GCP SCC: Malware Detected','GCP Security Command Center detected malware activity on a GCP resource.',
  'threat_detection','malware','gcp_scc',
  'gcp_scc_malware','malware',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution","impact"]','["T1204","T1485"]',95,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_misconfiguration','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"MISCONFIGURATION"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_misconfiguration','scc','gcp',
  'high','GCP SCC: Security Misconfiguration','GCP Security Command Center identified a security misconfiguration in GCP resources.',
  'threat_detection','threat','gcp_scc',
  'gcp_scc_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.threat.scc_policy_violation','scc','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_scc"},{"op":"contains","field":"operation","value":"POLICY_VIOLATION"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.threat.scc_policy_violation','scc','gcp',
  'high','GCP SCC: Policy Violation Detected','GCP Security Command Center detected a policy violation in GCP resource configuration.',
  'threat_detection','threat','gcp_scc',
  'gcp_scc_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.execute.gke_pod_exec','gke','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_gke_audit"},{"op":"contains","field":"operation","value":"pods/exec"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.execute.gke_pod_exec','gke','gcp',
  'high','GCP GKE: Pod Exec Command Executed','An exec command was run inside a GKE pod. Review for container breakout or lateral movement.',
  'threat_detection','execute','gcp_gke_audit',
  'gcp_gke_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.execute.gke_pod_attach','gke','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_gke_audit"},{"op":"contains","field":"operation","value":"pods/attach"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.execute.gke_pod_attach','gke','gcp',
  'high','GCP GKE: Pod Attach Session','A process attached to a running GKE pod. May indicate unauthorized container access.',
  'threat_detection','execute','gcp_gke_audit',
  'gcp_gke_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.execute.gke_portforward','gke','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_gke_audit"},{"op":"contains","field":"operation","value":"pods/portforward"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.execute.gke_portforward','gke','gcp',
  'high','GCP GKE: Port Forwarding Established','Port forwarding was established to a GKE pod, potentially exposing internal GCP services.',
  'threat_detection','execute','gcp_gke_audit',
  'gcp_gke_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.set_iam_policy','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"contains","field":"operation","value":"setIamPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.set_iam_policy','iam','gcp',
  'critical','GCP IAM: Policy Binding Modified (setIamPolicy)','An IAM policy was modified via setIamPolicy. Unauthorized bindings grant persistent privileged access.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.sa_key_create','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServiceAccountKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.sa_key_create','iam','gcp',
  'critical','GCP IAM: Service Account Key Created','A service account key was created. Keys provide long-lived credentials outside the GCP console.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.sa_token_generate','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iamcredentials.googleapis.com"},{"op":"contains","field":"operation","value":"GenerateAccessToken"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.sa_token_generate','iam','gcp',
  'critical','GCP IAM: Service Account Access Token Generated','An access token was generated for a service account, potentially for privilege escalation.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.create_role','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateRole"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.create_role','iam','gcp',
  'critical','GCP IAM: Custom Role Created','A custom IAM role was created. Malicious custom roles can grant excessive permissions.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.workload_identity','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"workloadIdentityPools"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.workload_identity','iam','gcp',
  'critical','GCP IAM: Workload Identity Pool Modified','A Workload Identity Pool was created or modified, potentially allowing external identities to assume GCP roles.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.privilege_escalation.org_policy_set','cloudresourcemanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudresourcemanager.googleapis.com"},{"op":"contains","field":"operation","value":"SetOrgPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.privilege_escalation.org_policy_set','cloudresourcemanager','gcp',
  'critical','GCP: Organization Policy Set','An organization-level policy was set. Changes to org policies can affect all projects under the org.',
  'threat_detection','privilege_escalation','gcp_audit',
  'gcp_audit_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.reconnaissance.secret_access_failed','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.reconnaissance.secret_access_failed','secretmanager','gcp',
  'medium','GCP Secret Manager: Unauthorized Secret Access','Unauthorized attempt to access a GCP Secret Manager secret was denied.',
  'threat_detection','reconnaissance','gcp_audit',
  'gcp_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.reconnaissance.storage_failed','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"storage.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.reconnaissance.storage_failed','storage','gcp',
  'medium','GCP Storage: Unauthorized Bucket Operation','Unauthorized attempt to access a GCP Cloud Storage bucket was denied.',
  'threat_detection','reconnaissance','gcp_audit',
  'gcp_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.reconnaissance.iam_failed','iam','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"iam.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.reconnaissance.iam_failed','iam','gcp',
  'medium','GCP IAM: Unauthorized Operation','Unauthorized IAM operation was denied, possibly indicating privilege enumeration.',
  'threat_detection','reconnaissance','gcp_audit',
  'gcp_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.reconnaissance.kms_failed','cloudkms','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.reconnaissance.kms_failed','cloudkms','gcp',
  'medium','GCP KMS: Unauthorized Key Operation','Unauthorized attempt to access a GCP KMS key was denied. May indicate key extraction attempt.',
  'threat_detection','reconnaissance','gcp_audit',
  'gcp_audit_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authentication.compute_auth_failed','compute','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"compute.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authentication.compute_auth_failed','compute','gcp',
  'high','GCP Compute: Authentication Failure','A GCP Compute Engine operation failed due to authentication error.',
  'threat_detection','authentication','gcp_audit',
  'gcp_audit_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.authentication.container_auth_failed','container','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"container.googleapis.com"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.authentication.container_auth_failed','container','gcp',
  'high','GCP Container: Authentication Failure','A GCP Container/GKE operation failed due to authentication error.',
  'threat_detection','authentication','gcp_audit',
  'gcp_audit_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.exfiltration.storage_hmac_create','storage','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"CreateHmacKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.exfiltration.storage_hmac_create','storage','gcp',
  'critical','GCP Storage: HMAC Key Created','A Cloud Storage HMAC key was created. HMAC keys provide programmatic access for data exfiltration.',
  'threat_detection','exfiltration','gcp_audit',
  'gcp_audit_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.exfiltration.bigquery_export','bigquery','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"Extract"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.exfiltration.bigquery_export','bigquery','gcp',
  'critical','GCP BigQuery: Data Extract/Export','A BigQuery data extraction or export job was created, potentially indicating data exfiltration.',
  'threat_detection','exfiltration','gcp_audit',
  'gcp_audit_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.gcp.exfiltration.secret_access','secretmanager','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"AccessSecretVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.gcp.exfiltration.secret_access','secretmanager','gcp',
  'critical','GCP Secret Manager: Secret Accessed','A secret was accessed from GCP Secret Manager. Review for unauthorized credential access.',
  'threat_detection','exfiltration','gcp_audit',
  'gcp_audit_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','gcp'
) ON CONFLICT DO NOTHING;

COMMIT;
