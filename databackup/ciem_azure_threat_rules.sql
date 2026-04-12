-- CIEM Azure Threat Detection Rules
BEGIN;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_ssh_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_ssh_allow','nsg_flow','azure',
  'medium','Azure NSG: SSH Inbound Allowed','SSH traffic (port 22) was allowed through an Azure Network Security Group. Review for unauthorized remote access.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_rdp_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_rdp_allow','nsg_flow','azure',
  'medium','Azure NSG: RDP Inbound Allowed','RDP traffic (port 3389) was allowed through an Azure NSG. Remote Desktop may expose systems to unauthorized access.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_smb_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"445"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_smb_allow','nsg_flow','azure',
  'medium','Azure NSG: SMB Traffic Allowed','SMB traffic (port 445) was allowed. Lateral movement via SMB is a common ransomware vector.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_db_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"in","field":"network.dst_port","value":["1433","3306","5432","1521","27017"]}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_db_allow','nsg_flow','azure',
  'medium','Azure NSG: Database Port Exposed','Database ports (1433/3306/5432/1521/27017) were allowed through an Azure NSG from outside.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_ssh_deny','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"D"},{"op":"equals","field":"network.dst_port","value":"22"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_ssh_deny','nsg_flow','azure',
  'critical','Azure NSG: SSH Traffic Blocked — Possible Brute Force','SSH traffic (port 22) was denied by an Azure NSG, indicating potential brute-force or scanning activity.',
  'threat_detection','brute_force','azure_nsg_flow',
  'azure_nsg_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_rdp_deny','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"D"},{"op":"equals","field":"network.dst_port","value":"3389"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_rdp_deny','nsg_flow','azure',
  'critical','Azure NSG: RDP Traffic Blocked — Possible Brute Force','RDP traffic (port 3389) was denied by an Azure NSG, indicating potential brute-force or scanning activity.',
  'threat_detection','brute_force','azure_nsg_flow',
  'azure_nsg_flow_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_smb_deny','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"D"},{"op":"equals","field":"network.dst_port","value":"445"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_smb_deny','nsg_flow','azure',
  'medium','Azure NSG: SMB Traffic Blocked','SMB traffic (port 445) was denied, possibly blocking lateral movement or ransomware propagation.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_rejected','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"D"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_rejected','nsg_flow','azure',
  'medium','Azure NSG: Traffic Denied','Network traffic was denied by an Azure NSG rule. Unexpected deny patterns may indicate scanning or attack.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.network.nsg_dns_allow','nsg_flow','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_nsg_flow"},{"op":"equals","field":"network.flow_action","value":"A"},{"op":"equals","field":"network.dst_port","value":"53"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.network.nsg_dns_allow','nsg_flow','azure',
  'medium','Azure NSG: DNS Traffic Allowed','DNS traffic (port 53) allowed through NSG. Large volumes or external DNS may indicate C2 tunneling.',
  'threat_detection','network','azure_nsg_flow',
  'azure_nsg_flow_network','network',
  'log','{"ciem_engine"}','ciem_engine',
  '["command-and-control","lateral-movement"]','["T1046","T1071","T1133"]',50,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_critical','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"equals","field":"severity","value":"Critical"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_critical','defender','azure',
  'high','Azure Defender: Critical Security Alert','Microsoft Defender for Cloud raised a Critical severity security alert. Immediate investigation required.',
  'threat_detection','threat','azure_defender',
  'azure_defender_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_high','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"equals","field":"severity","value":"High"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_high','defender','azure',
  'high','Azure Defender: High Severity Security Alert','Microsoft Defender for Cloud raised a High severity security alert.',
  'threat_detection','threat','azure_defender',
  'azure_defender_threat','threat',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","execution","persistence"]','["T1195","T1059"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_malware','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"Malware"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_malware','defender','azure',
  'critical','Azure Defender: Malware Detected','Microsoft Defender for Cloud detected malware activity on an Azure resource.',
  'threat_detection','malware','azure_defender',
  'azure_defender_malware','malware',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution","impact"]','["T1204","T1485"]',95,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_brute_force','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"Brute"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_brute_force','defender','azure',
  'critical','Azure Defender: Brute Force Attack Detected','Microsoft Defender for Cloud detected a brute force attack against an Azure resource.',
  'threat_detection','brute_force','azure_defender',
  'azure_defender_brute_force','brute_force',
  'log','{"ciem_engine"}','ciem_engine',
  '["credential-access"]','["T1110"]',85,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_credential_access','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"CredentialAccess"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_credential_access','defender','azure',
  'high','Azure Defender: Credential Access Attempt','Microsoft Defender for Cloud detected a credential access attempt, possible credential theft.',
  'threat_detection','authentication','azure_defender',
  'azure_defender_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_privilege_esc','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"PrivilegeEscalation"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_privilege_esc','defender','azure',
  'critical','Azure Defender: Privilege Escalation Detected','Microsoft Defender for Cloud detected a privilege escalation attempt.',
  'threat_detection','privilege_escalation','azure_defender',
  'azure_defender_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_data_exfil','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"DataExfiltration"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_data_exfil','defender','azure',
  'critical','Azure Defender: Data Exfiltration Detected','Microsoft Defender for Cloud detected a data exfiltration attempt from an Azure resource.',
  'threat_detection','exfiltration','azure_defender',
  'azure_defender_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_anomalous_access','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"AnomalousAccess"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_anomalous_access','defender','azure',
  'medium','Azure Defender: Anomalous Resource Access','Microsoft Defender for Cloud detected anomalous access patterns to Azure resources.',
  'threat_detection','reconnaissance','azure_defender',
  'azure_defender_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.threat.defender_suspicious_login','defender','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_defender"},{"op":"contains","field":"operation","value":"SuspiciousLogin"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.threat.defender_suspicious_login','defender','azure',
  'high','Azure Defender: Suspicious Login Activity','Microsoft Defender for Cloud detected suspicious login activity, possible account compromise.',
  'threat_detection','authentication','azure_defender',
  'azure_defender_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.aks_pod_exec','aks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_aks_audit"},{"op":"contains","field":"operation","value":"pods/exec"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.aks_pod_exec','aks','azure',
  'high','Azure AKS: Pod Exec Command Executed','An exec command was run inside an AKS pod. This may indicate container breakout or lateral movement.',
  'threat_detection','execute','azure_aks_audit',
  'azure_aks_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.aks_pod_attach','aks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_aks_audit"},{"op":"contains","field":"operation","value":"pods/attach"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.aks_pod_attach','aks','azure',
  'high','Azure AKS: Pod Attach Session','A process attached to a running AKS pod. Review for unauthorized container access.',
  'threat_detection','execute','azure_aks_audit',
  'azure_aks_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.aks_portforward','aks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_aks_audit"},{"op":"contains","field":"operation","value":"pods/portforward"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.aks_portforward','aks','azure',
  'high','Azure AKS: Port Forwarding Established','Port forwarding was set up to an AKS pod, potentially exposing internal services.',
  'threat_detection','execute','azure_aks_audit',
  'azure_aks_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.execute.aks_privileged_pod','aks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_aks_audit"},{"op":"contains","field":"operation","value":"privileged"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.execute.aks_privileged_pod','aks','azure',
  'high','Azure AKS: Privileged Pod Created','A privileged pod was created in AKS. Privileged containers can escape to the host node.',
  'threat_detection','execute','azure_aks_audit',
  'azure_aks_audit_execute','execute',
  'log','{"ciem_engine"}','ciem_engine',
  '["execution"]','["T1059","T1610"]',80,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.elevate_access','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"elevateAccess"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.elevate_access','authorization','azure',
  'critical','Azure: Global Admin Elevation of Access','User activated Global Administrator access via elevateAccess. This grants full Azure AD and subscription access.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.role_assignment','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/roleAssignments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.role_assignment','authorization','azure',
  'critical','Azure: Role Assignment Created','A new Azure RBAC role assignment was created. Unauthorized role assignments grant persistent access.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.custom_role','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"roleDefinitions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.custom_role','authorization','azure',
  'critical','Azure: Custom Role Definition Created or Modified','An Azure custom RBAC role was created or updated. Malicious custom roles can grant excessive permissions.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.policy_assignment','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/policyAssignments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.policy_assignment','authorization','azure',
  'critical','Azure: Policy Assignment Created','An Azure Policy was assigned at subscription or resource group scope. Policies can enforce or allow dangerous configurations.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.classic_admin','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"classicAdministrators/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.classic_admin','authorization','azure',
  'critical','Azure: Classic Administrator Added','A classic co-administrator was added to the Azure subscription, granting owner-level access.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.management_group','management','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"Microsoft.Management/managementGroups"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.management_group','management','azure',
  'critical','Azure: Management Group Modification','An Azure Management Group was modified. Changes at management group level affect all child subscriptions.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.privilege_escalation.lock_delete','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"locks/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.privilege_escalation.lock_delete','authorization','azure',
  'critical','Azure: Resource Lock Deleted','An Azure resource lock was deleted, removing protection from accidental or unauthorized resource deletion.',
  'threat_detection','privilege_escalation','azure_activity',
  'azure_activity_privilege_escalation','privilege_escalation',
  'log','{"ciem_engine"}','ciem_engine',
  '["privilege-escalation"]','["T1078","T1484","T1098"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.reconnaissance.keyvault_secret_failed','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"contains","field":"operation","value":"vaults/secrets"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.reconnaissance.keyvault_secret_failed','keyvault','azure',
  'medium','Azure Key Vault: Failed Secret Access','Unauthorized attempt to read a Key Vault secret was denied. May indicate credential harvesting.',
  'threat_detection','reconnaissance','azure_activity',
  'azure_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.reconnaissance.keyvault_key_failed','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"contains","field":"operation","value":"vaults/keys"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.reconnaissance.keyvault_key_failed','keyvault','azure',
  'medium','Azure Key Vault: Failed Key Access','Unauthorized attempt to read a Key Vault cryptographic key was denied.',
  'threat_detection','reconnaissance','azure_activity',
  'azure_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.reconnaissance.keyvault_cert_failed','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"contains","field":"operation","value":"vaults/certificates"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.reconnaissance.keyvault_cert_failed','keyvault','azure',
  'medium','Azure Key Vault: Failed Certificate Access','Unauthorized attempt to read a Key Vault certificate was denied.',
  'threat_detection','reconnaissance','azure_activity',
  'azure_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.reconnaissance.storage_list_keys','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"listKeys/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.reconnaissance.storage_list_keys','storage','azure',
  'medium','Azure Storage: Account Keys Listed','Storage account keys were listed. This operation retrieves secrets that grant full storage access.',
  'threat_detection','reconnaissance','azure_activity',
  'azure_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.reconnaissance.authorization_failed','authorization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"authorization"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.reconnaissance.authorization_failed','authorization','azure',
  'medium','Azure Authorization: Access Check Failed','Multiple authorization check failures detected, indicating potential access probing.',
  'threat_detection','reconnaissance','azure_activity',
  'azure_activity_reconnaissance','reconnaissance',
  'log','{"ciem_engine"}','ciem_engine',
  '["reconnaissance","discovery"]','["T1595","T1526","T1087"]',45,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authentication.compute_failed','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"compute"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authentication.compute_failed','compute','azure',
  'high','Azure Compute: Authentication Failure','An Azure Compute operation failed due to authentication/authorization error.',
  'threat_detection','authentication','azure_activity',
  'azure_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authentication.keyvault_failed','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"contains","field":"operation","value":"accessPolicies"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authentication.keyvault_failed','keyvault','azure',
  'high','Azure Key Vault: Access Policy Authentication Failure','Key Vault access policy operation failed, possible unauthorized access attempt.',
  'threat_detection','authentication','azure_activity',
  'azure_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.authentication.network_failed','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"outcome","value":"failure"},{"op":"equals","field":"service","value":"network"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.authentication.network_failed','network','azure',
  'high','Azure Network: Authentication Failure','An Azure Network operation failed due to authentication/authorization error.',
  'threat_detection','authentication','azure_activity',
  'azure_activity_authentication','authentication',
  'log','{"ciem_engine"}','ciem_engine',
  '["initial-access","credential-access"]','["T1078","T1110"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.exfiltration.storage_sas_list','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"listServiceSas/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.exfiltration.storage_sas_list','storage','azure',
  'critical','Azure Storage: SAS Token Generated','A Storage Account SAS token was listed/created. SAS tokens can be used for unauthorized data exfiltration.',
  'threat_detection','exfiltration','azure_activity',
  'azure_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.exfiltration.disk_export_access','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"exportDiskAccess/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.exfiltration.disk_export_access','compute','azure',
  'critical','Azure Compute: Disk Export Access Granted','A managed disk export access was granted, enabling data extraction from a VM disk.',
  'threat_detection','exfiltration','azure_activity',
  'azure_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.exfiltration.cert_backup','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"certificates/backup/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.exfiltration.cert_backup','keyvault','azure',
  'critical','Azure Key Vault: Certificate Backup Created','A Key Vault certificate backup was created. Backups contain exportable private key material.',
  'threat_detection','exfiltration','azure_activity',
  'azure_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('threat.azure.exfiltration.db_export','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"contains","field":"operation","value":"exportRequest/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'threat.azure.exfiltration.db_export','sql','azure',
  'critical','Azure SQL: Database Export Initiated','An Azure SQL database export operation was initiated. Large-scale data export may indicate exfiltration.',
  'threat_detection','exfiltration','azure_activity',
  'azure_activity_exfiltration','exfiltration',
  'log','{"ciem_engine"}','ciem_engine',
  '["exfiltration"]','["T1048","T1537"]',90,'auto','azure'
) ON CONFLICT DO NOTHING;

COMMIT;
