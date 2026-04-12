-- OCI CRUD expansion rules
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.analytics.dc25000f','com.oraclecloud.analyticsservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.analyticsservice"},{"op":"equals","field":"operation","value":"CreateAnalyticsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.analytics.dc25000f','com.oraclecloud.analyticsservice','oci',
  'high','OCI Analytics Instances: Create Analytics Cloud Instance','Detected CreateAnalyticsInstance on Analytics Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateAnalyticsInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.analytics.278a7889','com.oraclecloud.analyticsservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.analyticsservice"},{"op":"equals","field":"operation","value":"DeleteAnalyticsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.analytics.278a7889','com.oraclecloud.analyticsservice','oci',
  'high','OCI Analytics Instances: Delete Analytics Cloud Instance','Detected DeleteAnalyticsInstance on Analytics Instances via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteAnalyticsInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.analytics.68209af8','com.oraclecloud.analyticsservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.analyticsservice"},{"op":"equals","field":"operation","value":"StartAnalyticsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.analytics.68209af8','com.oraclecloud.analyticsservice','oci',
  'high','OCI Analytics Instances: Start Analytics Cloud Instance','Detected StartAnalyticsInstance on Analytics Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'StartAnalyticsInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.analytics.2f740a4d','com.oraclecloud.analyticsservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.analyticsservice"},{"op":"equals","field":"operation","value":"StopAnalyticsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.analytics.2f740a4d','com.oraclecloud.analyticsservice','oci',
  'high','OCI Analytics Instances: Stop Analytics Cloud Instance','Detected StopAnalyticsInstance on Analytics Instances via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'StopAnalyticsInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bigdata.cc605b15','com.oraclecloud.bigdataservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bigdataservice"},{"op":"equals","field":"operation","value":"CreateBdsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bigdata.cc605b15','com.oraclecloud.bigdataservice','oci',
  'high','OCI Big Data Clusters: Create Big Data Cluster','Detected CreateBdsInstance on Big Data Clusters via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBdsInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bigdata.d6b3c849','com.oraclecloud.bigdataservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bigdataservice"},{"op":"equals","field":"operation","value":"DeleteBdsInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bigdata.d6b3c849','com.oraclecloud.bigdataservice','oci',
  'high','OCI Big Data Clusters: Delete Big Data Cluster','Detected DeleteBdsInstance on Big Data Clusters via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteBdsInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bigdata.be56e0e1','com.oraclecloud.bigdataservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bigdataservice"},{"op":"equals","field":"operation","value":"AddAutoScalingConfiguration"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bigdata.be56e0e1','com.oraclecloud.bigdataservice','oci',
  'high','OCI Big Data Clusters: Add Big Data Auto-Scaling Config','Detected AddAutoScalingConfiguration on Big Data Clusters via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'AddAutoScalingConfiguration','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bigdata.977628f1','com.oraclecloud.bigdataservice','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bigdataservice"},{"op":"equals","field":"operation","value":"AddWorkerNodes"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bigdata.977628f1','com.oraclecloud.bigdataservice','oci',
  'high','OCI Big Data Nodes: Add Big Data Worker Nodes','Detected AddWorkerNodes on Big Data Nodes via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'AddWorkerNodes','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.certificates.f96839ae','com.oraclecloud.certificatesmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.certificatesmanagement"},{"op":"equals","field":"operation","value":"CreateCertificateAuthority"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.certificates.f96839ae','com.oraclecloud.certificatesmanagement','oci',
  'high','OCI Certificate Authorities: Create Certificate Authority','Detected CreateCertificateAuthority on Certificate Authorities via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCertificateAuthority','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.certificates.0bc736fe','com.oraclecloud.certificatesmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.certificatesmanagement"},{"op":"equals","field":"operation","value":"DeleteCertificateAuthority"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.certificates.0bc736fe','com.oraclecloud.certificatesmanagement','oci',
  'high','OCI Certificate Authorities: Delete Certificate Authority','Detected DeleteCertificateAuthority on Certificate Authorities via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteCertificateAuthority','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.certificates.e33b91eb','com.oraclecloud.certificatesmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.certificatesmanagement"},{"op":"equals","field":"operation","value":"CreateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.certificates.e33b91eb','com.oraclecloud.certificatesmanagement','oci',
  'high','OCI Certificates: Create Certificate','Detected CreateCertificate on Certificates via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCertificate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.certificates.3304ea53','com.oraclecloud.certificatesmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.certificatesmanagement"},{"op":"equals","field":"operation","value":"UpdateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.certificates.3304ea53','com.oraclecloud.certificatesmanagement','oci',
  'medium','OCI Certificates: Update Certificate','Detected UpdateCertificate on Certificates via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateCertificate','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.certificates.46368d40','com.oraclecloud.certificatesmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.certificatesmanagement"},{"op":"equals","field":"operation","value":"CreateCaBundle"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.certificates.46368d40','com.oraclecloud.certificatesmanagement','oci',
  'high','OCI CA Bundles: Create CA Bundle','Detected CreateCaBundle on CA Bundles via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCaBundle','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.cloudguard.c3354539','com.oraclecloud.cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.cloudguard"},{"op":"equals","field":"operation","value":"CreateTarget"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.cloudguard.c3354539','com.oraclecloud.cloudguard','oci',
  'high','OCI Cloud Guard Targets: Create Cloud Guard Target','Detected CreateTarget on Cloud Guard Targets via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateTarget','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.cloudguard.4391bdd7','com.oraclecloud.cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.cloudguard"},{"op":"equals","field":"operation","value":"DeleteTarget"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.cloudguard.4391bdd7','com.oraclecloud.cloudguard','oci',
  'high','OCI Cloud Guard Targets: Delete Cloud Guard Target','Detected DeleteTarget on Cloud Guard Targets via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteTarget','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.cloudguard.65040342','com.oraclecloud.cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.cloudguard"},{"op":"equals","field":"operation","value":"CreateDetectorRecipe"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.cloudguard.65040342','com.oraclecloud.cloudguard','oci',
  'high','OCI Cloud Guard Recipes: Create Cloud Guard Detector Recipe','Detected CreateDetectorRecipe on Cloud Guard Recipes via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDetectorRecipe','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.cloudguard.17d68ce6','com.oraclecloud.cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.cloudguard"},{"op":"equals","field":"operation","value":"DeleteDetectorRecipe"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.cloudguard.17d68ce6','com.oraclecloud.cloudguard','oci',
  'high','OCI Cloud Guard Recipes: Delete Cloud Guard Detector Recipe','Detected DeleteDetectorRecipe on Cloud Guard Recipes via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteDetectorRecipe','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.cloudguard.28f3f5c1','com.oraclecloud.cloudguard','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.cloudguard"},{"op":"equals","field":"operation","value":"CreateResponderRecipe"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.cloudguard.28f3f5c1','com.oraclecloud.cloudguard','oci',
  'high','OCI Cloud Guard Responder Recipes: Create Cloud Guard Responder Recipe','Detected CreateResponderRecipe on Cloud Guard Responder Recipes via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateResponderRecipe','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.dataintegration.5fe83c3f','com.oraclecloud.dataintegration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.dataintegration"},{"op":"equals","field":"operation","value":"CreateWorkspace"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.dataintegration.5fe83c3f','com.oraclecloud.dataintegration','oci',
  'high','OCI DI Workspaces: Create Data Integration Workspace','Detected CreateWorkspace on DI Workspaces via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateWorkspace','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.dataintegration.738516ef','com.oraclecloud.dataintegration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.dataintegration"},{"op":"equals","field":"operation","value":"DeleteWorkspace"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.dataintegration.738516ef','com.oraclecloud.dataintegration','oci',
  'high','OCI DI Workspaces: Delete Data Integration Workspace','Detected DeleteWorkspace on DI Workspaces via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteWorkspace','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.dataintegration.87e79e73','com.oraclecloud.dataintegration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.dataintegration"},{"op":"equals","field":"operation","value":"CreateTask"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.dataintegration.87e79e73','com.oraclecloud.dataintegration','oci',
  'high','OCI DI Tasks: Create Data Integration Task','Detected CreateTask on DI Tasks via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateTask','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.8bbd95a6','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"CreateProject"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.8bbd95a6','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Projects: Create Data Science Project','Detected CreateProject on Data Science Projects via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateProject','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.6dc2b305','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"DeleteProject"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.6dc2b305','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Projects: Delete Data Science Project','Detected DeleteProject on Data Science Projects via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteProject','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.c102968e','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"CreateNotebookSession"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.c102968e','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Notebooks: Create Data Science Notebook Session','Detected CreateNotebookSession on Data Science Notebooks via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateNotebookSession','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.bc722d7f','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"DeleteNotebookSession"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.bc722d7f','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Notebooks: Delete Data Science Notebook Session','Detected DeleteNotebookSession on Data Science Notebooks via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteNotebookSession','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.95b376eb','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"CreateModel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.95b376eb','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Models: Create Data Science Model','Detected CreateModel on Data Science Models via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateModel','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datascience.b712cb9e','com.oraclecloud.datascience','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datascience"},{"op":"equals","field":"operation","value":"CreateModelDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datascience.b712cb9e','com.oraclecloud.datascience','oci',
  'high','OCI Data Science Model Deployments: Create Model Deployment','Detected CreateModelDeployment on Data Science Model Deployments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateModelDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.75adccd9','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"CreateTargetDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.75adccd9','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe Targets: Register Data Safe Target Database','Detected CreateTargetDatabase on Data Safe Targets via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateTargetDatabase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.67dd93c1','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"DeleteTargetDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.67dd93c1','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe Targets: Delete Data Safe Target Database','Detected DeleteTargetDatabase on Data Safe Targets via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteTargetDatabase','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.176350c6','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"CreateSecurityAssessment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.176350c6','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe Security Assessment: Create Data Safe Security Assessment','Detected CreateSecurityAssessment on Data Safe Security Assessment via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSecurityAssessment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.8c14030b','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"CreateUserAssessment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.8c14030b','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe User Assessment: Create Data Safe User Assessment','Detected CreateUserAssessment on Data Safe User Assessment via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateUserAssessment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.dc8b87e4','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"CreateMaskingPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.dc8b87e4','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe Masking Policies: Create Data Safe Masking Policy','Detected CreateMaskingPolicy on Data Safe Masking Policies via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateMaskingPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datasafe.1e5b9f56','com.oraclecloud.datasafe','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datasafe"},{"op":"equals","field":"operation","value":"StartAuditTrail"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datasafe.1e5b9f56','com.oraclecloud.datasafe','oci',
  'high','OCI Data Safe Audit Trails: Start Data Safe Audit Trail','Detected StartAuditTrail on Data Safe Audit Trails via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'StartAuditTrail','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.email.5ee131ec','com.oraclecloud.emaildelivery','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.emaildelivery"},{"op":"equals","field":"operation","value":"CreateSender"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.email.5ee131ec','com.oraclecloud.emaildelivery','oci',
  'high','OCI Email Senders: Create Approved Email Sender','Detected CreateSender on Email Senders via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSender','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.email.f821b345','com.oraclecloud.emaildelivery','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.emaildelivery"},{"op":"equals","field":"operation","value":"DeleteSender"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.email.f821b345','com.oraclecloud.emaildelivery','oci',
  'high','OCI Email Senders: Delete Approved Email Sender','Detected DeleteSender on Email Senders via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSender','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.email.aac51e72','com.oraclecloud.emaildelivery','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.emaildelivery"},{"op":"equals","field":"operation","value":"CreateSuppression"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.email.aac51e72','com.oraclecloud.emaildelivery','oci',
  'high','OCI Email Suppressions: Create Email Suppression','Detected CreateSuppression on Email Suppressions via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSuppression','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.63bb2f33','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"CreateFileSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.63bb2f33','com.oraclecloud.filestorage','oci',
  'high','OCI File Systems: Create File Storage System','Detected CreateFileSystem on File Systems via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateFileSystem','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.cea85fa5','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"DeleteFileSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.cea85fa5','com.oraclecloud.filestorage','oci',
  'high','OCI File Systems: Delete File Storage System','Detected DeleteFileSystem on File Systems via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteFileSystem','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.9ead3507','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"CreateMountTarget"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.9ead3507','com.oraclecloud.filestorage','oci',
  'high','OCI Mount Targets: Create NFS Mount Target','Detected CreateMountTarget on Mount Targets via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateMountTarget','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.01291029','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"DeleteMountTarget"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.01291029','com.oraclecloud.filestorage','oci',
  'high','OCI Mount Targets: Delete NFS Mount Target','Detected DeleteMountTarget on Mount Targets via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteMountTarget','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.bc44dfdd','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"CreateExport"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.bc44dfdd','com.oraclecloud.filestorage','oci',
  'high','OCI Exports: Create File Storage Export','Detected CreateExport on Exports via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateExport','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.435e4493','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"CreateSnapshot"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.435e4493','com.oraclecloud.filestorage','oci',
  'high','OCI Snapshots: Create File Storage Snapshot','Detected CreateSnapshot on Snapshots via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSnapshot','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.filestorage.2b4810c1','com.oraclecloud.filestorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.filestorage"},{"op":"equals","field":"operation","value":"DeleteSnapshot"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.filestorage.2b4810c1','com.oraclecloud.filestorage','oci',
  'high','OCI Snapshots: Delete File Storage Snapshot','Detected DeleteSnapshot on Snapshots via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSnapshot','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.goldengate.24a7f31d','com.oraclecloud.goldengate','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.goldengate"},{"op":"equals","field":"operation","value":"CreateDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.goldengate.24a7f31d','com.oraclecloud.goldengate','oci',
  'high','OCI GoldenGate Deployments: Create GoldenGate Deployment','Detected CreateDeployment on GoldenGate Deployments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.goldengate.201567db','com.oraclecloud.goldengate','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.goldengate"},{"op":"equals","field":"operation","value":"DeleteDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.goldengate.201567db','com.oraclecloud.goldengate','oci',
  'high','OCI GoldenGate Deployments: Delete GoldenGate Deployment','Detected DeleteDeployment on GoldenGate Deployments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'DeleteDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.goldengate.b65a31e9','com.oraclecloud.goldengate','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.goldengate"},{"op":"equals","field":"operation","value":"CreateConnection"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.goldengate.b65a31e9','com.oraclecloud.goldengate','oci',
  'high','OCI GoldenGate Connections: Create GoldenGate Connection','Detected CreateConnection on GoldenGate Connections via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateConnection','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.goldengate.0a58099c','com.oraclecloud.goldengate','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.goldengate"},{"op":"equals","field":"operation","value":"DeleteConnection"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.goldengate.0a58099c','com.oraclecloud.goldengate','oci',
  'high','OCI GoldenGate Connections: Delete GoldenGate Connection','Detected DeleteConnection on GoldenGate Connections via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteConnection','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.integration.2a397301','com.oraclecloud.integration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.integration"},{"op":"equals","field":"operation","value":"CreateIntegrationInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.integration.2a397301','com.oraclecloud.integration','oci',
  'high','OCI Integration Instances: Create Integration Cloud Instance','Detected CreateIntegrationInstance on Integration Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateIntegrationInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.integration.72a61f09','com.oraclecloud.integration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.integration"},{"op":"equals","field":"operation","value":"DeleteIntegrationInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.integration.72a61f09','com.oraclecloud.integration','oci',
  'high','OCI Integration Instances: Delete Integration Cloud Instance','Detected DeleteIntegrationInstance on Integration Instances via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteIntegrationInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.integration.23811a09','com.oraclecloud.integration','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.integration"},{"op":"equals","field":"operation","value":"StartIntegrationInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.integration.23811a09','com.oraclecloud.integration','oci',
  'high','OCI Integration Instances: Start Integration Cloud Instance','Detected StartIntegrationInstance on Integration Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'StartIntegrationInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.mysql.4e2642b8','com.oraclecloud.mysqlaas','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.mysqlaas"},{"op":"equals","field":"operation","value":"CreateDbSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.mysql.4e2642b8','com.oraclecloud.mysqlaas','oci',
  'high','OCI MySQL DB Systems: Create MySQL HeatWave DB System','Detected CreateDbSystem on MySQL DB Systems via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDbSystem','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.mysql.0ee10c63','com.oraclecloud.mysqlaas','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.mysqlaas"},{"op":"equals","field":"operation","value":"DeleteDbSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.mysql.0ee10c63','com.oraclecloud.mysqlaas','oci',
  'high','OCI MySQL DB Systems: Delete MySQL HeatWave DB System','Detected DeleteDbSystem on MySQL DB Systems via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteDbSystem','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.mysql.6b1317f6','com.oraclecloud.mysqlaas','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.mysqlaas"},{"op":"equals","field":"operation","value":"UpdateDbSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.mysql.6b1317f6','com.oraclecloud.mysqlaas','oci',
  'medium','OCI MySQL DB Systems: Update MySQL HeatWave DB System','Detected UpdateDbSystem on MySQL DB Systems via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateDbSystem','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.mysql.1e4c5bda','com.oraclecloud.mysqlaas','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.mysqlaas"},{"op":"equals","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.mysql.1e4c5bda','com.oraclecloud.mysqlaas','oci',
  'high','OCI MySQL Backups: Create MySQL HeatWave Backup','Detected CreateBackup on MySQL Backups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.mysql.6deed9fe','com.oraclecloud.mysqlaas','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.mysqlaas"},{"op":"equals","field":"operation","value":"DeleteBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.mysql.6deed9fe','com.oraclecloud.mysqlaas','oci',
  'high','OCI MySQL Backups: Delete MySQL HeatWave Backup','Detected DeleteBackup on MySQL Backups via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteBackup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.nosql.21f66f36','com.oraclecloud.nosql','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.nosql"},{"op":"equals","field":"operation","value":"CreateTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.nosql.21f66f36','com.oraclecloud.nosql','oci',
  'high','OCI NoSQL Tables: Create NoSQL Database Table','Detected CreateTable on NoSQL Tables via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateTable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.nosql.9c7c401d','com.oraclecloud.nosql','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.nosql"},{"op":"equals","field":"operation","value":"DeleteTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.nosql.9c7c401d','com.oraclecloud.nosql','oci',
  'high','OCI NoSQL Tables: Delete NoSQL Database Table','Detected DeleteTable on NoSQL Tables via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteTable','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.nosql.f71b61a0','com.oraclecloud.nosql','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.nosql"},{"op":"equals","field":"operation","value":"UpdateTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.nosql.f71b61a0','com.oraclecloud.nosql','oci',
  'medium','OCI NoSQL Tables: Update NoSQL Database Table','Detected UpdateTable on NoSQL Tables via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateTable','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.nosql.bfbf5de5','com.oraclecloud.nosql','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.nosql"},{"op":"equals","field":"operation","value":"CreateIndex"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.nosql.bfbf5de5','com.oraclecloud.nosql','oci',
  'high','OCI NoSQL Indexes: Create NoSQL Database Index','Detected CreateIndex on NoSQL Indexes via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateIndex','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.nosql.19359c83','com.oraclecloud.nosql','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.nosql"},{"op":"equals","field":"operation","value":"DeleteIndex"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.nosql.19359c83','com.oraclecloud.nosql','oci',
  'high','OCI NoSQL Indexes: Delete NoSQL Database Index','Detected DeleteIndex on NoSQL Indexes via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteIndex','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oda.2fd4f7d0','com.oraclecloud.oda','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.oda"},{"op":"equals","field":"operation","value":"CreateOdaInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oda.2fd4f7d0','com.oraclecloud.oda','oci',
  'high','OCI ODA Instances: Create Digital Assistant Instance','Detected CreateOdaInstance on ODA Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateOdaInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oda.50b2237f','com.oraclecloud.oda','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.oda"},{"op":"equals","field":"operation","value":"DeleteOdaInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oda.50b2237f','com.oraclecloud.oda','oci',
  'high','OCI ODA Instances: Delete Digital Assistant Instance','Detected DeleteOdaInstance on ODA Instances via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteOdaInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oda.85d0dcf2','com.oraclecloud.oda','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.oda"},{"op":"equals","field":"operation","value":"StartOdaInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oda.85d0dcf2','com.oraclecloud.oda','oci',
  'high','OCI ODA Instances: Start Digital Assistant Instance','Detected StartOdaInstance on ODA Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'StartOdaInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.opensearch.2f272715','com.oraclecloud.opensearch','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.opensearch"},{"op":"equals","field":"operation","value":"CreateOpensearchCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.opensearch.2f272715','com.oraclecloud.opensearch','oci',
  'high','OCI OpenSearch Clusters: Create OpenSearch Cluster','Detected CreateOpensearchCluster on OpenSearch Clusters via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateOpensearchCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.opensearch.6361040c','com.oraclecloud.opensearch','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.opensearch"},{"op":"equals","field":"operation","value":"DeleteOpensearchCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.opensearch.6361040c','com.oraclecloud.opensearch','oci',
  'high','OCI OpenSearch Clusters: Delete OpenSearch Cluster','Detected DeleteOpensearchCluster on OpenSearch Clusters via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteOpensearchCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.opensearch.32ff3959','com.oraclecloud.opensearch','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.opensearch"},{"op":"equals","field":"operation","value":"UpdateOpensearchCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.opensearch.32ff3959','com.oraclecloud.opensearch','oci',
  'medium','OCI OpenSearch Clusters: Update OpenSearch Cluster','Detected UpdateOpensearchCluster on OpenSearch Clusters via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateOpensearchCluster','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.osmanagement.9b842fe8','com.oraclecloud.osmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.osmanagement"},{"op":"equals","field":"operation","value":"CreateManagedInstanceGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.osmanagement.9b842fe8','com.oraclecloud.osmanagement','oci',
  'high','OCI OS Management Groups: Create OS Managed Instance Group','Detected CreateManagedInstanceGroup on OS Management Groups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateManagedInstanceGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.osmanagement.96883e9c','com.oraclecloud.osmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.osmanagement"},{"op":"equals","field":"operation","value":"DeleteManagedInstanceGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.osmanagement.96883e9c','com.oraclecloud.osmanagement','oci',
  'high','OCI OS Management Groups: Delete OS Managed Instance Group','Detected DeleteManagedInstanceGroup on OS Management Groups via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteManagedInstanceGroup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.osmanagement.44c1f8ca','com.oraclecloud.osmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.osmanagement"},{"op":"equals","field":"operation","value":"CreateScheduledJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.osmanagement.44c1f8ca','com.oraclecloud.osmanagement','oci',
  'high','OCI Scheduled Jobs: Create OS Management Scheduled Job','Detected CreateScheduledJob on Scheduled Jobs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateScheduledJob','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.osmanagement.db3acc3c','com.oraclecloud.osmanagement','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.osmanagement"},{"op":"equals","field":"operation","value":"DeleteScheduledJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.osmanagement.db3acc3c','com.oraclecloud.osmanagement','oci',
  'high','OCI Scheduled Jobs: Delete OS Management Scheduled Job','Detected DeleteScheduledJob on Scheduled Jobs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteScheduledJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.queue.aad5abfa','com.oraclecloud.queue','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.queue"},{"op":"equals","field":"operation","value":"CreateQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.queue.aad5abfa','com.oraclecloud.queue','oci',
  'high','OCI Queues: Create OCI Queue','Detected CreateQueue on Queues via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateQueue','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.queue.ecffb0ca','com.oraclecloud.queue','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.queue"},{"op":"equals","field":"operation","value":"DeleteQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.queue.ecffb0ca','com.oraclecloud.queue','oci',
  'high','OCI Queues: Delete OCI Queue','Detected DeleteQueue on Queues via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteQueue','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.queue.2a0bf043','com.oraclecloud.queue','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.queue"},{"op":"equals","field":"operation","value":"UpdateQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.queue.2a0bf043','com.oraclecloud.queue','oci',
  'medium','OCI Queues: Update OCI Queue','Detected UpdateQueue on Queues via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateQueue','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.queue.0bd5f837','com.oraclecloud.queue','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.queue"},{"op":"equals","field":"operation","value":"DeleteMessages"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.queue.0bd5f837','com.oraclecloud.queue','oci',
  'high','OCI Queue Messages: Delete Queue Messages','Detected DeleteMessages on Queue Messages via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteMessages','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.queue.ac664461','com.oraclecloud.queue','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.queue"},{"op":"equals","field":"operation","value":"PurgeQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.queue.ac664461','com.oraclecloud.queue','oci',
  'high','OCI Queue Messages: Purge Queue Messages','Detected PurgeQueue on Queue Messages via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'PurgeQueue','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.visualbuilder.b98c9c82','com.oraclecloud.visualbuilder','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.visualbuilder"},{"op":"equals","field":"operation","value":"CreateVbInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.visualbuilder.b98c9c82','com.oraclecloud.visualbuilder','oci',
  'high','OCI VB Instances: Create Visual Builder Instance','Detected CreateVbInstance on VB Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVbInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.visualbuilder.f744bc4b','com.oraclecloud.visualbuilder','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.visualbuilder"},{"op":"equals","field":"operation","value":"DeleteVbInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.visualbuilder.f744bc4b','com.oraclecloud.visualbuilder','oci',
  'high','OCI VB Instances: Delete Visual Builder Instance','Detected DeleteVbInstance on VB Instances via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteVbInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.visualbuilder.2d92871f','com.oraclecloud.visualbuilder','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.visualbuilder"},{"op":"equals","field":"operation","value":"StartVbInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.visualbuilder.2d92871f','com.oraclecloud.visualbuilder','oci',
  'high','OCI VB Instances: Start Visual Builder Instance','Detected StartVbInstance on VB Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'StartVbInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.bd269046','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateVcn"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.bd269046','com.oraclecloud.virtualnetwork','oci',
  'high','OCI VCN: Create VCN','Detected CreateVcn on VCN via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVcn','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.39940785','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteVcn"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.39940785','com.oraclecloud.virtualnetwork','oci',
  'high','OCI VCN: Delete VCN','Detected DeleteVcn on VCN via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteVcn','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.e27a5f7a','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateSubnet"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.e27a5f7a','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Subnets: Create Subnet','Detected CreateSubnet on Subnets via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSubnet','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.abc22d48','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteSubnet"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.abc22d48','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Subnets: Delete Subnet','Detected DeleteSubnet on Subnets via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSubnet','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.5f05ae4c','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateInternetGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.5f05ae4c','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Internet Gateways: Create Internet Gateway','Detected CreateInternetGateway on Internet Gateways via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateInternetGateway','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.7eef54fd','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteInternetGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.7eef54fd','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Internet Gateways: Delete Internet Gateway','Detected DeleteInternetGateway on Internet Gateways via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteInternetGateway','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.cb4239eb','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateNatGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.cb4239eb','com.oraclecloud.virtualnetwork','oci',
  'high','OCI NAT Gateways: Create NAT Gateway','Detected CreateNatGateway on NAT Gateways via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateNatGateway','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.99dcaadc','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteNatGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.99dcaadc','com.oraclecloud.virtualnetwork','oci',
  'high','OCI NAT Gateways: Delete NAT Gateway','Detected DeleteNatGateway on NAT Gateways via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteNatGateway','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.8cb07978','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateServiceGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.8cb07978','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Service Gateways: Create Service Gateway','Detected CreateServiceGateway on Service Gateways via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateServiceGateway','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.273bc6d7','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateLocalPeeringGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.273bc6d7','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Local Peering Gateways: Create Local Peering Gateway','Detected CreateLocalPeeringGateway on Local Peering Gateways via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateLocalPeeringGateway','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.21c50852','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateRemotePeeringConnection"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.21c50852','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Remote Peering: Create Remote Peering Connection','Detected CreateRemotePeeringConnection on Remote Peering via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateRemotePeeringConnection','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.584bcf7d','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateNetworkSecurityGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.584bcf7d','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Network Security Groups: Create Network Security Group','Detected CreateNetworkSecurityGroup on Network Security Groups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateNetworkSecurityGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.7cb95feb','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"UpdateNetworkSecurityGroupSecurityRules"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.7cb95feb','com.oraclecloud.virtualnetwork','oci',
  'medium','OCI NSG Rules: Update NSG Security Rules','Detected UpdateNetworkSecurityGroupSecurityRules on NSG Rules via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateNetworkSecurityGroupSecurityRules','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.16b503c5','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateSecurityList"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.16b503c5','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Security Lists: Create Security List','Detected CreateSecurityList on Security Lists via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSecurityList','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.d88390d1','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteSecurityList"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.d88390d1','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Security Lists: Delete Security List','Detected DeleteSecurityList on Security Lists via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSecurityList','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.1f7483ab','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateRouteTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.1f7483ab','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Route Tables: Create Route Table','Detected CreateRouteTable on Route Tables via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateRouteTable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.8b0d2673','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"DeleteRouteTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.8b0d2673','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Route Tables: Delete Route Table','Detected DeleteRouteTable on Route Tables via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteRouteTable','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.d0e7ec11','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreateDhcpOptions"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.d0e7ec11','com.oraclecloud.virtualnetwork','oci',
  'high','OCI DHCP Options: Create DHCP Options','Detected CreateDhcpOptions on DHCP Options via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDhcpOptions','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.64549150','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreatePrivateIp"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.64549150','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Private IPs: Create Private IP','Detected CreatePrivateIp on Private IPs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreatePrivateIp','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.network.c2c383d0','com.oraclecloud.virtualnetwork','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.virtualnetwork"},{"op":"equals","field":"operation","value":"CreatePublicIpPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.network.c2c383d0','com.oraclecloud.virtualnetwork','oci',
  'high','OCI Public IP Pools: Create Public IP Pool','Detected CreatePublicIpPool on Public IP Pools via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreatePublicIpPool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.blockstorage.be20840c','com.oraclecloud.blockstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.blockstorage"},{"op":"equals","field":"operation","value":"CreateVolume"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.blockstorage.be20840c','com.oraclecloud.blockstorage','oci',
  'high','OCI Block Volumes: Create Block Volume','Detected CreateVolume on Block Volumes via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVolume','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.blockstorage.67a9fa9f','com.oraclecloud.blockstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.blockstorage"},{"op":"equals","field":"operation","value":"DeleteVolume"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.blockstorage.67a9fa9f','com.oraclecloud.blockstorage','oci',
  'high','OCI Block Volumes: Delete Block Volume','Detected DeleteVolume on Block Volumes via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteVolume','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.blockstorage.a01891b2','com.oraclecloud.blockstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.blockstorage"},{"op":"equals","field":"operation","value":"CreateVolumeBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.blockstorage.a01891b2','com.oraclecloud.blockstorage','oci',
  'high','OCI Block Volume Backups: Create Block Volume Backup','Detected CreateVolumeBackup on Block Volume Backups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVolumeBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.blockstorage.5f283298','com.oraclecloud.blockstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.blockstorage"},{"op":"equals","field":"operation","value":"DeleteVolumeBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.blockstorage.5f283298','com.oraclecloud.blockstorage','oci',
  'high','OCI Block Volume Backups: Delete Block Volume Backup','Detected DeleteVolumeBackup on Block Volume Backups via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteVolumeBackup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.blockstorage.6d515370','com.oraclecloud.blockstorage','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.blockstorage"},{"op":"equals","field":"operation","value":"CreateVolumeGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.blockstorage.6d515370','com.oraclecloud.blockstorage','oci',
  'high','OCI Volume Groups: Create Volume Group','Detected CreateVolumeGroup on Volume Groups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVolumeGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.01de9725','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreateCompartment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.01de9725','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Compartments: Create Compartment','Detected CreateCompartment on Compartments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCompartment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.51c4b044','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"DeleteUser"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.51c4b044','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Users: Delete IAM User','Detected DeleteUser on Users via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteUser','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.51645b8c','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreateGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.51645b8c','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Groups: Create IAM Group','Detected CreateGroup on Groups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.f2c788b4','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"DeleteGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.f2c788b4','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Groups: Delete IAM Group','Detected DeleteGroup on Groups via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteGroup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.0e5d6d89','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreatePolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.0e5d6d89','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Policies: Create IAM Policy','Detected CreatePolicy on Policies via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreatePolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.ecba106a','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"DeletePolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.ecba106a','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Policies: Delete IAM Policy','Detected DeletePolicy on Policies via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeletePolicy','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.7e536cf7','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"CreateCustomerSecretKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.7e536cf7','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Customer Secret Keys: Create OCI Customer Secret Key','Detected CreateCustomerSecretKey on Customer Secret Keys via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCustomerSecretKey','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.identity.d6d421c6','com.oraclecloud.identitycontrolplane','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.identitycontrolplane"},{"op":"equals","field":"operation","value":"DeleteCustomerSecretKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.identity.d6d421c6','com.oraclecloud.identitycontrolplane','oci',
  'high','OCI Customer Secret Keys: Delete OCI Customer Secret Key','Detected DeleteCustomerSecretKey on Customer Secret Keys via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteCustomerSecretKey','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.ad665261','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"CreateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.ad665261','com.oraclecloud.containerengine','oci',
  'high','OCI OKE Clusters: Create OKE Kubernetes Cluster','Detected CreateCluster on OKE Clusters via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.8de45d07','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"DeleteCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.8de45d07','com.oraclecloud.containerengine','oci',
  'high','OCI OKE Clusters: Delete OKE Kubernetes Cluster','Detected DeleteCluster on OKE Clusters via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.e797b238','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"CreateNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.e797b238','com.oraclecloud.containerengine','oci',
  'high','OCI OKE Node Pools: Create OKE Node Pool','Detected CreateNodePool on OKE Node Pools via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateNodePool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.84bc1f9c','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"DeleteNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.84bc1f9c','com.oraclecloud.containerengine','oci',
  'high','OCI OKE Node Pools: Delete OKE Node Pool','Detected DeleteNodePool on OKE Node Pools via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteNodePool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.1d7cf39c','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"UpdateNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.1d7cf39c','com.oraclecloud.containerengine','oci',
  'medium','OCI OKE Node Pools: Update OKE Node Pool','Detected UpdateNodePool on OKE Node Pools via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateNodePool','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.oke.12fdd188','com.oraclecloud.containerengine','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.containerengine"},{"op":"equals","field":"operation","value":"CreateVirtualNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.oke.12fdd188','com.oraclecloud.containerengine','oci',
  'high','OCI OKE Virtual Node Pools: Create OKE Virtual Node Pool','Detected CreateVirtualNodePool on OKE Virtual Node Pools via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVirtualNodePool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.6ada5212','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"LaunchDbSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.6ada5212','com.oraclecloud.database','oci',
  'high','OCI DB Systems: Launch Oracle DB System','Detected LaunchDbSystem on DB Systems via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'LaunchDbSystem','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.f928b2f1','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"TerminateDbSystem"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.f928b2f1','com.oraclecloud.database','oci',
  'high','OCI DB Systems: Terminate Oracle DB System','Detected TerminateDbSystem on DB Systems via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'TerminateDbSystem','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.23d19af2','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"CreateAutonomousDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.23d19af2','com.oraclecloud.database','oci',
  'high','OCI Autonomous DBs: Create Autonomous Database','Detected CreateAutonomousDatabase on Autonomous DBs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateAutonomousDatabase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.fceeb495','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"DeleteAutonomousDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.fceeb495','com.oraclecloud.database','oci',
  'high','OCI Autonomous DBs: Delete Autonomous Database','Detected DeleteAutonomousDatabase on Autonomous DBs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteAutonomousDatabase','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.ba88cad7','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"StopAutonomousDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.ba88cad7','com.oraclecloud.database','oci',
  'high','OCI Autonomous DBs: Stop Autonomous Database','Detected StopAutonomousDatabase on Autonomous DBs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'StopAutonomousDatabase','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.40ff5b38','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.40ff5b38','com.oraclecloud.database','oci',
  'high','OCI DB Backups: Create Oracle DB Backup','Detected CreateBackup on DB Backups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.database.cfb41bd2','com.oraclecloud.database','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.database"},{"op":"equals","field":"operation","value":"CreateExternalDatabaseConnector"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.database.cfb41bd2','com.oraclecloud.database','oci',
  'high','OCI External DB Connectors: Create External DB Connector','Detected CreateExternalDatabaseConnector on External DB Connectors via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateExternalDatabaseConnector','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.e0c65553','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"LaunchInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.e0c65553','com.oraclecloud.computeapi','oci',
  'high','OCI Instances: Launch Compute Instance','Detected LaunchInstance on Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'LaunchInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.4d17fca5','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"TerminateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.4d17fca5','com.oraclecloud.computeapi','oci',
  'high','OCI Instances: Terminate Compute Instance','Detected TerminateInstance on Instances via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'TerminateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.662df0df','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"CreateInstanceConfiguration"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.662df0df','com.oraclecloud.computeapi','oci',
  'high','OCI Instance Configs: Create Instance Configuration','Detected CreateInstanceConfiguration on Instance Configs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateInstanceConfiguration','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.00f74ff2','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"CreateInstancePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.00f74ff2','com.oraclecloud.computeapi','oci',
  'high','OCI Instance Pools: Create Instance Pool','Detected CreateInstancePool on Instance Pools via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateInstancePool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.67952c32','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"DeleteInstancePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.67952c32','com.oraclecloud.computeapi','oci',
  'high','OCI Instance Pools: Delete Instance Pool','Detected DeleteInstancePool on Instance Pools via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteInstancePool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.f82e876d','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"CreateImage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.f82e876d','com.oraclecloud.computeapi','oci',
  'high','OCI Custom Images: Create Custom Compute Image','Detected CreateImage on Custom Images via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateImage','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.compute.ff80b6ad','com.oraclecloud.computeapi','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.computeapi"},{"op":"equals","field":"operation","value":"DeleteImage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.compute.ff80b6ad','com.oraclecloud.computeapi','oci',
  'high','OCI Custom Images: Delete Custom Compute Image','Detected DeleteImage on Custom Images via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'DeleteImage','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

