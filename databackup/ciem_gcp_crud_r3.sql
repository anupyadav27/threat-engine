-- GCP CRUD round 3
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebase.03e7a13d','firebase.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebase.googleapis.com"},{"op":"contains","field":"operation","value":"AddFirebase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebase.03e7a13d','firebase.googleapis.com','gcp',
  'high','GCP Firebase Projects: Add Firebase to GCP Project','Detected AddFirebase on Firebase Projects via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'AddFirebase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebase.83e0bba4','firebase.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebase.googleapis.com"},{"op":"contains","field":"operation","value":"RemoveAnalytics"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebase.83e0bba4','firebase.googleapis.com','gcp',
  'high','GCP Firebase Projects: Remove Firebase Analytics','Detected RemoveAnalytics on Firebase Projects via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'RemoveAnalytics','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebasedatabase.6c13df93','firebasedatabase.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebasedatabase.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDatabaseInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebasedatabase.6c13df93','firebasedatabase.googleapis.com','gcp',
  'high','GCP Firebase RTDB: Create Firebase Realtime Database','Detected CreateDatabaseInstance on Firebase RTDB via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDatabaseInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebasedatabase.6b018a7e','firebasedatabase.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebasedatabase.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteDatabaseInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebasedatabase.6b018a7e','firebasedatabase.googleapis.com','gcp',
  'high','GCP Firebase RTDB: Delete Firebase Realtime Database','Detected DeleteDatabaseInstance on Firebase RTDB via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteDatabaseInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebasehosting.ebf468fa','firebasehosting.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebasehosting.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSite"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebasehosting.ebf468fa','firebasehosting.googleapis.com','gcp',
  'high','GCP Firebase Hosting: Create Firebase Hosting Site','Detected CreateSite on Firebase Hosting via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSite','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebasehosting.47bcd035','firebasehosting.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebasehosting.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteSite"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebasehosting.47bcd035','firebasehosting.googleapis.com','gcp',
  'high','GCP Firebase Hosting: Delete Firebase Hosting Site','Detected DeleteSite on Firebase Hosting via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteSite','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firebasestorage.af0cd408','firebasestorage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firebasestorage.googleapis.com"},{"op":"contains","field":"operation","value":"AddFirebase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firebasestorage.af0cd408','firebasestorage.googleapis.com','gcp',
  'high','GCP Firebase Storage: Link Firebase Storage Bucket','Detected AddFirebase on Firebase Storage via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'AddFirebase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.certificatemanager.60b09c14','certificatemanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"certificatemanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCertificateMap"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.certificatemanager.60b09c14','certificatemanager.googleapis.com','gcp',
  'high','GCP Certificate Maps: Create Certificate Map','Detected CreateCertificateMap on Certificate Maps via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCertificateMap','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.certificatemanager.9ec723d4','certificatemanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"certificatemanager.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCertificateMap"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.certificatemanager.9ec723d4','certificatemanager.googleapis.com','gcp',
  'high','GCP Certificate Maps: Delete Certificate Map','Detected DeleteCertificateMap on Certificate Maps via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCertificateMap','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.certificatemanager.6e0289fb','certificatemanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"certificatemanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.certificatemanager.6e0289fb','certificatemanager.googleapis.com','gcp',
  'high','GCP Certificates: Create Certificate Manager Certificate','Detected CreateCertificate on Certificates via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCertificate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.certificatemanager.d1763835','certificatemanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"certificatemanager.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.certificatemanager.d1763835','certificatemanager.googleapis.com','gcp',
  'high','GCP Certificates: Delete Certificate Manager Certificate','Detected DeleteCertificate on Certificates via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCertificate','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.domains.240815ea','domains.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"domains.googleapis.com"},{"op":"contains","field":"operation","value":"RegisterDomain"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.domains.240815ea','domains.googleapis.com','gcp',
  'high','GCP Cloud Domains: Register Cloud Domain','Detected RegisterDomain on Cloud Domains via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'RegisterDomain','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.domains.c681b46c','domains.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"domains.googleapis.com"},{"op":"contains","field":"operation","value":"TransferDomain"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.domains.c681b46c','domains.googleapis.com','gcp',
  'medium','GCP Cloud Domains: Transfer Cloud Domain','Detected TransferDomain on Cloud Domains via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'TransferDomain','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.domains.f6d29c40','domains.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"domains.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteRegistration"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.domains.f6d29c40','domains.googleapis.com','gcp',
  'high','GCP Cloud Domains: Delete Domain Registration','Detected DeleteRegistration on Cloud Domains via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteRegistration','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workflows.d6c36aaa','workflows.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workflows.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkflow"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workflows.d6c36aaa','workflows.googleapis.com','gcp',
  'high','GCP Cloud Workflows: Create Cloud Workflow','Detected CreateWorkflow on Cloud Workflows via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkflow','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workflows.752afc0d','workflows.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workflows.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteWorkflow"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workflows.752afc0d','workflows.googleapis.com','gcp',
  'high','GCP Cloud Workflows: Delete Cloud Workflow','Detected DeleteWorkflow on Cloud Workflows via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteWorkflow','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workflows.71a75ce2','workflows.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workflows.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateWorkflow"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workflows.71a75ce2','workflows.googleapis.com','gcp',
  'medium','GCP Cloud Workflows: Update Cloud Workflow','Detected UpdateWorkflow on Cloud Workflows via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateWorkflow','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workflowexecutions.10f7a2a8','workflowexecutions.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workflowexecutions.googleapis.com"},{"op":"contains","field":"operation","value":"CreateExecution"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workflowexecutions.10f7a2a8','workflowexecutions.googleapis.com','gcp',
  'high','GCP Workflow Executions: Execute Cloud Workflow','Detected CreateExecution on Workflow Executions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateExecution','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workflowexecutions.e71683ac','workflowexecutions.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workflowexecutions.googleapis.com"},{"op":"contains","field":"operation","value":"CancelExecution"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workflowexecutions.e71683ac','workflowexecutions.googleapis.com','gcp',
  'high','GCP Workflow Executions: Cancel Cloud Workflow Execution','Detected CancelExecution on Workflow Executions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'CancelExecution','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.vpcaccess.4cfd3a32','vpcaccess.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"vpcaccess.googleapis.com"},{"op":"contains","field":"operation","value":"CreateConnector"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.vpcaccess.4cfd3a32','vpcaccess.googleapis.com','gcp',
  'high','GCP VPC Access Connectors: Create Serverless VPC Connector','Detected CreateConnector on VPC Access Connectors via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateConnector','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.vpcaccess.a4fd6a21','vpcaccess.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"vpcaccess.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteConnector"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.vpcaccess.a4fd6a21','vpcaccess.googleapis.com','gcp',
  'high','GCP VPC Access Connectors: Delete Serverless VPC Connector','Detected DeleteConnector on VPC Access Connectors via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteConnector','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.baremetalsolution.d93d427d','baremetalsolution.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"baremetalsolution.googleapis.com"},{"op":"contains","field":"operation","value":"ResetInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.baremetalsolution.d93d427d','baremetalsolution.googleapis.com','gcp',
  'medium','GCP Bare Metal Servers: Reset Bare Metal Server','Detected ResetInstance on Bare Metal Servers via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'ResetInstance','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.baremetalsolution.87bcb512','baremetalsolution.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"baremetalsolution.googleapis.com"},{"op":"contains","field":"operation","value":"ResizeVolume"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.baremetalsolution.87bcb512','baremetalsolution.googleapis.com','gcp',
  'medium','GCP Bare Metal Volumes: Resize Bare Metal Volume','Detected ResizeVolume on Bare Metal Volumes via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'ResizeVolume','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.documentai.1fcc2cfc','documentai.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"documentai.googleapis.com"},{"op":"contains","field":"operation","value":"CreateProcessor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.documentai.1fcc2cfc','documentai.googleapis.com','gcp',
  'high','GCP Document AI Processors: Create Document AI Processor','Detected CreateProcessor on Document AI Processors via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateProcessor','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.documentai.d1d57a43','documentai.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"documentai.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteProcessor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.documentai.d1d57a43','documentai.googleapis.com','gcp',
  'high','GCP Document AI Processors: Delete Document AI Processor','Detected DeleteProcessor on Document AI Processors via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteProcessor','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.documentai.e8bce6b4','documentai.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"documentai.googleapis.com"},{"op":"contains","field":"operation","value":"EnableProcessor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.documentai.e8bce6b4','documentai.googleapis.com','gcp',
  'high','GCP Document AI Processors: Enable Document AI Processor','Detected EnableProcessor on Document AI Processors via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'EnableProcessor','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.documentai.6303fd77','documentai.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"documentai.googleapis.com"},{"op":"contains","field":"operation","value":"DisableProcessor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.documentai.6303fd77','documentai.googleapis.com','gcp',
  'high','GCP Document AI Processors: Disable Document AI Processor','Detected DisableProcessor on Document AI Processors via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DisableProcessor','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.eventarc.3f8f00d6','eventarc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"eventarc.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTrigger"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.eventarc.3f8f00d6','eventarc.googleapis.com','gcp',
  'high','GCP Eventarc Triggers: Create Eventarc Trigger','Detected CreateTrigger on Eventarc Triggers via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTrigger','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.eventarc.390620eb','eventarc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"eventarc.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteTrigger"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.eventarc.390620eb','eventarc.googleapis.com','gcp',
  'high','GCP Eventarc Triggers: Delete Eventarc Trigger','Detected DeleteTrigger on Eventarc Triggers via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteTrigger','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.eventarc.7661f1ee','eventarc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"eventarc.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateTrigger"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.eventarc.7661f1ee','eventarc.googleapis.com','gcp',
  'medium','GCP Eventarc Triggers: Update Eventarc Trigger','Detected UpdateTrigger on Eventarc Triggers via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateTrigger','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.gkehub.53c4ec94','gkehub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"gkehub.googleapis.com"},{"op":"contains","field":"operation","value":"CreateMembership"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.gkehub.53c4ec94','gkehub.googleapis.com','gcp',
  'high','GCP GKE Fleet Memberships: Register Cluster to GKE Fleet','Detected CreateMembership on GKE Fleet Memberships via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateMembership','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.gkehub.a6336054','gkehub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"gkehub.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteMembership"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.gkehub.a6336054','gkehub.googleapis.com','gcp',
  'high','GCP GKE Fleet Memberships: Remove Cluster from GKE Fleet','Detected DeleteMembership on GKE Fleet Memberships via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteMembership','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.gkehub.7c3c7d0a','gkehub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"gkehub.googleapis.com"},{"op":"contains","field":"operation","value":"CreateFeature"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.gkehub.7c3c7d0a','gkehub.googleapis.com','gcp',
  'high','GCP Fleet Features: Enable GKE Fleet Feature','Detected CreateFeature on Fleet Features via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateFeature','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.gkehub.d716cd97','gkehub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"gkehub.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteFeature"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.gkehub.d716cd97','gkehub.googleapis.com','gcp',
  'high','GCP Fleet Features: Disable GKE Fleet Feature','Detected DeleteFeature on Fleet Features via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteFeature','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.binaryauthorization.5a6d565b','binaryauthorization.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"binaryauthorization.googleapis.com"},{"op":"contains","field":"operation","value":"UpdatePolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.binaryauthorization.5a6d565b','binaryauthorization.googleapis.com','gcp',
  'medium','GCP Binauthz Policy: Update Binary Authorization Policy','Detected UpdatePolicy on Binauthz Policy via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdatePolicy','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.binaryauthorization.1b6306f7','binaryauthorization.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"binaryauthorization.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAttestor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.binaryauthorization.1b6306f7','binaryauthorization.googleapis.com','gcp',
  'high','GCP Binauthz Attestors: Create Binary Authorization Attestor','Detected CreateAttestor on Binauthz Attestors via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAttestor','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.binaryauthorization.d84d582d','binaryauthorization.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"binaryauthorization.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteAttestor"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.binaryauthorization.d84d582d','binaryauthorization.googleapis.com','gcp',
  'high','GCP Binauthz Attestors: Delete Binary Authorization Attestor','Detected DeleteAttestor on Binauthz Attestors via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteAttestor','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.osconfig.96fdfffa','osconfig.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"osconfig.googleapis.com"},{"op":"contains","field":"operation","value":"CreatePatchDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.osconfig.96fdfffa','osconfig.googleapis.com','gcp',
  'high','GCP Patch Deployments: Create OS Patch Deployment','Detected CreatePatchDeployment on Patch Deployments via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreatePatchDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.osconfig.d207efd2','osconfig.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"osconfig.googleapis.com"},{"op":"contains","field":"operation","value":"DeletePatchDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.osconfig.d207efd2','osconfig.googleapis.com','gcp',
  'high','GCP Patch Deployments: Delete OS Patch Deployment','Detected DeletePatchDeployment on Patch Deployments via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'DeletePatchDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.osconfig.52568d45','osconfig.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"osconfig.googleapis.com"},{"op":"contains","field":"operation","value":"CreateOSPolicyAssignment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.osconfig.52568d45','osconfig.googleapis.com','gcp',
  'high','GCP OS Policy Assignments: Create OS Policy Assignment','Detected CreateOSPolicyAssignment on OS Policy Assignments via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateOSPolicyAssignment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.assuredworkloads.5fc47468','assuredworkloads.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"assuredworkloads.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkload"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.assuredworkloads.5fc47468','assuredworkloads.googleapis.com','gcp',
  'high','GCP Assured Workloads: Create Assured Workload','Detected CreateWorkload on Assured Workloads via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkload','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.assuredworkloads.933a27fe','assuredworkloads.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"assuredworkloads.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteWorkload"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.assuredworkloads.933a27fe','assuredworkloads.googleapis.com','gcp',
  'high','GCP Assured Workloads: Delete Assured Workload','Detected DeleteWorkload on Assured Workloads via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteWorkload','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.assuredworkloads.507dff4a','assuredworkloads.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"assuredworkloads.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateWorkload"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.assuredworkloads.507dff4a','assuredworkloads.googleapis.com','gcp',
  'medium','GCP Assured Workloads: Update Assured Workload','Detected UpdateWorkload on Assured Workloads via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateWorkload','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networksecurity.1f309f00','networksecurity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networksecurity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAuthorizationPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networksecurity.1f309f00','networksecurity.googleapis.com','gcp',
  'high','GCP AuthZ Policies: Create Network Authorization Policy','Detected CreateAuthorizationPolicy on AuthZ Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAuthorizationPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networksecurity.871acbd4','networksecurity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networksecurity.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteAuthorizationPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networksecurity.871acbd4','networksecurity.googleapis.com','gcp',
  'high','GCP AuthZ Policies: Delete Network Authorization Policy','Detected DeleteAuthorizationPolicy on AuthZ Policies via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteAuthorizationPolicy','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networksecurity.8a474557','networksecurity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networksecurity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTlsInspectionPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networksecurity.8a474557','networksecurity.googleapis.com','gcp',
  'high','GCP TLS Inspection: Create TLS Inspection Policy','Detected CreateTlsInspectionPolicy on TLS Inspection via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTlsInspectionPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networksecurity.5c6664b8','networksecurity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networksecurity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServerTlsPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networksecurity.5c6664b8','networksecurity.googleapis.com','gcp',
  'high','GCP ServerTLS Policies: Create Server TLS Policy','Detected CreateServerTlsPolicy on ServerTLS Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateServerTlsPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.4bc7fa11','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"addRule"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.4bc7fa11','compute.googleapis.com','gcp',
  'high','GCP Security Policies Rules: Add Cloud Armor Security Policy Rule','Detected addRule on Security Policies Rules via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'addRule','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.2323ae49','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"patchRule"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.2323ae49','compute.googleapis.com','gcp',
  'medium','GCP Security Policies Rules: Update Cloud Armor Security Policy Rule','Detected patchRule on Security Policies Rules via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'patchRule','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.69af2025','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"removeRule"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.69af2025','compute.googleapis.com','gcp',
  'high','GCP Security Policies Rules: Remove Cloud Armor Security Policy Rule','Detected removeRule on Security Policies Rules via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'removeRule','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.6dbe2595','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.6dbe2595','alloydb.googleapis.com','gcp',
  'high','GCP AlloyDB Backups: Delete AlloyDB Backup','Detected DeleteBackup on AlloyDB Backups via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteBackup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.0076e3ab','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"CreateUser"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.0076e3ab','alloydb.googleapis.com','gcp',
  'high','GCP AlloyDB Users: Create AlloyDB Database User','Detected CreateUser on AlloyDB Users via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateUser','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.3397d7f8','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteUser"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.3397d7f8','alloydb.googleapis.com','gcp',
  'high','GCP AlloyDB Users: Delete AlloyDB Database User','Detected DeleteUser on AlloyDB Users via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteUser','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.accesscontextmanager.4001845a','accesscontextmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"accesscontextmanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAccessPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.accesscontextmanager.4001845a','accesscontextmanager.googleapis.com','gcp',
  'high','GCP Access Policies: Create Access Context Manager Policy','Detected CreateAccessPolicy on Access Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAccessPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.accesscontextmanager.db0cab1b','accesscontextmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"accesscontextmanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAccessLevel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.accesscontextmanager.db0cab1b','accesscontextmanager.googleapis.com','gcp',
  'high','GCP Access Levels: Create VPC Service Control Access Level','Detected CreateAccessLevel on Access Levels via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAccessLevel','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.accesscontextmanager.21485821','accesscontextmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"accesscontextmanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServicePerimeter"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.accesscontextmanager.21485821','accesscontextmanager.googleapis.com','gcp',
  'high','GCP Service Perimeters: Create VPC Service Control Perimeter','Detected CreateServicePerimeter on Service Perimeters via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateServicePerimeter','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.accesscontextmanager.24b1d547','accesscontextmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"accesscontextmanager.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteServicePerimeter"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.accesscontextmanager.24b1d547','accesscontextmanager.googleapis.com','gcp',
  'high','GCP Service Perimeters: Delete VPC Service Control Perimeter','Detected DeleteServicePerimeter on Service Perimeters via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteServicePerimeter','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.accesscontextmanager.89bd279d','accesscontextmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"accesscontextmanager.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateServicePerimeter"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.accesscontextmanager.89bd279d','accesscontextmanager.googleapis.com','gcp',
  'medium','GCP Service Perimeters: Update VPC Service Control Perimeter','Detected UpdateServicePerimeter on Service Perimeters via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateServicePerimeter','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsublite.f15474c8','pubsublite.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsublite.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsublite.f15474c8','pubsublite.googleapis.com','gcp',
  'high','GCP Pub/Sub Lite Topics: Create Pub/Sub Lite Topic','Detected CreateTopic on Pub/Sub Lite Topics via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTopic','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsublite.c7a20b84','pubsublite.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsublite.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsublite.c7a20b84','pubsublite.googleapis.com','gcp',
  'high','GCP Pub/Sub Lite Topics: Delete Pub/Sub Lite Topic','Detected DeleteTopic on Pub/Sub Lite Topics via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteTopic','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsublite.a7274f3d','pubsublite.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsublite.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSubscription"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsublite.a7274f3d','pubsublite.googleapis.com','gcp',
  'high','GCP Pub/Sub Lite Subscriptions: Create Pub/Sub Lite Subscription','Detected CreateSubscription on Pub/Sub Lite Subscriptions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSubscription','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.881e641e','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstanceConfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.881e641e','spanner.googleapis.com','gcp',
  'high','GCP Spanner Instance Configs: Create Spanner Instance Config','Detected CreateInstanceConfig on Spanner Instance Configs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstanceConfig','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.7e0f4ca1','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"BatchCreateSessions"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.7e0f4ca1','spanner.googleapis.com','gcp',
  'high','GCP Spanner Sessions: Batch Create Spanner Sessions','Detected BatchCreateSessions on Spanner Sessions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'BatchCreateSessions','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.looker.ee1a27ff','looker.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"looker.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.looker.ee1a27ff','looker.googleapis.com','gcp',
  'high','GCP Looker Instances: Create Looker Instance','Detected CreateInstance on Looker Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.looker.22141e05','looker.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"looker.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.looker.22141e05','looker.googleapis.com','gcp',
  'high','GCP Looker Instances: Delete Looker Instance','Detected DeleteInstance on Looker Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.looker.b92e149d','looker.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"looker.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.looker.b92e149d','looker.googleapis.com','gcp',
  'medium','GCP Looker Instances: Update Looker Instance','Detected UpdateInstance on Looker Instances via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateInstance','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.d7f78272','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.notifications.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.d7f78272','storage.googleapis.com','gcp',
  'high','GCP GCS Bucket Notifications: Create GCS Bucket Notification','Detected storage.notifications.create on GCS Bucket Notifications via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'storage.notifications.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.c8bc6a2b','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.bucketAccessControls.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.c8bc6a2b','storage.googleapis.com','gcp',
  'high','GCP GCS Bucket ACLs: Create GCS Bucket ACL Entry','Detected storage.bucketAccessControls.create on GCS Bucket ACLs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'storage.bucketAccessControls.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.8c48165b','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.objectAccessControls.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.8c48165b','storage.googleapis.com','gcp',
  'high','GCP GCS Object ACLs: Create GCS Object ACL Entry','Detected storage.objectAccessControls.create on GCS Object ACLs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'storage.objectAccessControls.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute VPN Tunnels: Create VPN Tunnel','Detected insert on Compute VPN Tunnels via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.d8461b4b','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute VPN Tunnels: Delete VPN Tunnel','Detected delete on Compute VPN Tunnels via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Forwarding Rules: Create Forwarding Rule','Detected insert on Compute Forwarding Rules via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.d8461b4b','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Forwarding Rules: Delete Forwarding Rule','Detected delete on Compute Forwarding Rules via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Health Checks: Create Compute Health Check','Detected insert on Compute Health Checks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Target Pools: Create Compute Target Pool','Detected insert on Compute Target Pools via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Managed Instance Groups: Create Managed Instance Group','Detected insert on Compute Managed Instance Groups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.d8461b4b','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Managed Instance Groups: Delete Managed Instance Group','Detected delete on Compute Managed Instance Groups via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

