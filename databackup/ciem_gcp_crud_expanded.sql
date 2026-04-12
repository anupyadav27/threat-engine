-- GCP CRUD expansion rules
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.798d5bc3','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.798d5bc3','alloydb.googleapis.com','gcp',
  'high','GCP Alloy DB Clusters: Create Alloy DB Cluster','Detected CreateCluster on Alloy DB Clusters via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.8689605f','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.8689605f','alloydb.googleapis.com','gcp',
  'high','GCP Alloy DB Clusters: Delete Alloy DB Cluster','Detected DeleteCluster on Alloy DB Clusters via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.0be18d36','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.0be18d36','alloydb.googleapis.com','gcp',
  'high','GCP Alloy DB Instances: Create Alloy DB Instance','Detected CreateInstance on Alloy DB Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.5b9b79f8','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.5b9b79f8','alloydb.googleapis.com','gcp',
  'high','GCP Alloy DB Instances: Delete Alloy DB Instance','Detected DeleteInstance on Alloy DB Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.alloydb.4915a4f1','alloydb.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"alloydb.googleapis.com"},{"op":"contains","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.alloydb.4915a4f1','alloydb.googleapis.com','gcp',
  'high','GCP Alloy DB Backups: Create Alloy DB Backup','Detected CreateBackup on Alloy DB Backups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.6953e269','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"CreateOrganization"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.6953e269','apigee.googleapis.com','gcp',
  'high','GCP Apigee Organizations: Create Apigee Organization','Detected CreateOrganization on Apigee Organizations via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateOrganization','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.0e459a9a','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"CreateEnvironment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.0e459a9a','apigee.googleapis.com','gcp',
  'high','GCP Apigee Environments: Create Apigee Environment','Detected CreateEnvironment on Apigee Environments via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateEnvironment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.ac18f94a','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"CreateApiProxy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.ac18f94a','apigee.googleapis.com','gcp',
  'high','GCP Apigee API Proxies: Create Apigee API Proxy','Detected CreateApiProxy on Apigee API Proxies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateApiProxy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.c848d792','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"CreateKeystore"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.c848d792','apigee.googleapis.com','gcp',
  'high','GCP Apigee Key Stores: Create Apigee Keystore','Detected CreateKeystore on Apigee Key Stores via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateKeystore','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.bde642c5','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteKeystore"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.bde642c5','apigee.googleapis.com','gcp',
  'high','GCP Apigee Key Stores: Delete Apigee Keystore','Detected DeleteKeystore on Apigee Key Stores via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteKeystore','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.apigee.ba36ff1d','apigee.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"apigee.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDeveloperApp"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.apigee.ba36ff1d','apigee.googleapis.com','gcp',
  'high','GCP Apigee Developer Apps: Create Apigee Developer App','Detected CreateDeveloperApp on Apigee Developer Apps via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDeveloperApp','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.appengine.f3fb04c1','appengine.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"appengine.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.appengine.f3fb04c1','appengine.googleapis.com','gcp',
  'high','GCP App Engine Services: Delete App Engine Service','Detected DeleteService on App Engine Services via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteService','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.appengine.bca32239','appengine.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"appengine.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.appengine.bca32239','appengine.googleapis.com','gcp',
  'high','GCP App Engine Versions: Delete App Engine Version','Detected DeleteVersion on App Engine Versions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteVersion','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.appengine.aff7e1aa','appengine.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"appengine.googleapis.com"},{"op":"contains","field":"operation","value":"StartInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.appengine.aff7e1aa','appengine.googleapis.com','gcp',
  'high','GCP App Engine Instances: Start App Engine Instance','Detected StartInstance on App Engine Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'StartInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.appengine.2bbbf699','appengine.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"appengine.googleapis.com"},{"op":"contains","field":"operation","value":"BatchUpdateIngressRules"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.appengine.2bbbf699','appengine.googleapis.com','gcp',
  'medium','GCP App Engine Firewall: Update App Engine Firewall Rules','Detected BatchUpdateIngressRules on App Engine Firewall via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'BatchUpdateIngressRules','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.84fcbb7c','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.84fcbb7c','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable Instances: Create Bigtable Instance','Detected CreateInstance on Bigtable Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.68655dad','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.68655dad','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable Instances: Delete Bigtable Instance','Detected DeleteInstance on Bigtable Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.c62ddc58','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.c62ddc58','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable Tables: Create Bigtable Table','Detected CreateTable on Bigtable Tables via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.29c30f6c','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteTable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.29c30f6c','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable Tables: Delete Bigtable Table','Detected DeleteTable on Bigtable Tables via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteTable','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.b9937587','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.b9937587','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable Backups: Create Bigtable Backup','Detected CreateBackup on Bigtable Backups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigtableadmin.b9351f54','bigtableadmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigtableadmin.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAppProfile"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigtableadmin.b9351f54','bigtableadmin.googleapis.com','gcp',
  'high','GCP Bigtable App Profiles: Create Bigtable App Profile','Detected CreateAppProfile on Bigtable App Profiles via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAppProfile','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.composer.58e13edc','composer.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"composer.googleapis.com"},{"op":"contains","field":"operation","value":"CreateEnvironment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.composer.58e13edc','composer.googleapis.com','gcp',
  'high','GCP Composer Environments: Create Cloud Composer Environment','Detected CreateEnvironment on Composer Environments via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateEnvironment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.composer.f6c067fb','composer.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"composer.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteEnvironment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.composer.f6c067fb','composer.googleapis.com','gcp',
  'high','GCP Composer Environments: Delete Cloud Composer Environment','Detected DeleteEnvironment on Composer Environments via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteEnvironment','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.composer.64e4d216','composer.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"composer.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateEnvironment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.composer.64e4d216','composer.googleapis.com','gcp',
  'medium','GCP Composer Environments: Update Cloud Composer Environment','Detected UpdateEnvironment on Composer Environments via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateEnvironment','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataflow.0fd3eafa','dataflow.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataflow.googleapis.com"},{"op":"contains","field":"operation","value":"CreateJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataflow.0fd3eafa','dataflow.googleapis.com','gcp',
  'high','GCP Dataflow Jobs: Create Dataflow Job','Detected CreateJob on Dataflow Jobs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateJob','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataflow.43d1cc24','dataflow.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataflow.googleapis.com"},{"op":"contains","field":"operation","value":"CancelJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataflow.43d1cc24','dataflow.googleapis.com','gcp',
  'high','GCP Dataflow Jobs: Cancel Dataflow Job','Detected CancelJob on Dataflow Jobs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'CancelJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataflow.37dacb4e','dataflow.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataflow.googleapis.com"},{"op":"contains","field":"operation","value":"SnapshotJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataflow.37dacb4e','dataflow.googleapis.com','gcp',
  'medium','GCP Dataflow Jobs: Snapshot Dataflow Job','Detected SnapshotJob on Dataflow Jobs via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'SnapshotJob','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.98295db0','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.98295db0','dataproc.googleapis.com','gcp',
  'high','GCP Dataproc Clusters: Create Dataproc Cluster','Detected CreateCluster on Dataproc Clusters via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.377ec6fc','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.377ec6fc','dataproc.googleapis.com','gcp',
  'high','GCP Dataproc Clusters: Delete Dataproc Cluster','Detected DeleteCluster on Dataproc Clusters via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.f7931a66','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.f7931a66','dataproc.googleapis.com','gcp',
  'medium','GCP Dataproc Clusters: Update Dataproc Cluster','Detected UpdateCluster on Dataproc Clusters via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateCluster','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.44f074c3','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"SubmitJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.44f074c3','dataproc.googleapis.com','gcp',
  'medium','GCP Dataproc Jobs: Submit Dataproc Job','Detected SubmitJob on Dataproc Jobs via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'SubmitJob','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.433a6dbf','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"CancelJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.433a6dbf','dataproc.googleapis.com','gcp',
  'high','GCP Dataproc Jobs: Cancel Dataproc Job','Detected CancelJob on Dataproc Jobs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'CancelJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dataproc.9c660e8b','dataproc.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dataproc.googleapis.com"},{"op":"contains","field":"operation","value":"InstantiateWorkflowTemplate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dataproc.9c660e8b','dataproc.googleapis.com','gcp',
  'medium','GCP Dataproc Workflows: Run Dataproc Workflow Template','Detected InstantiateWorkflowTemplate on Dataproc Workflows via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'InstantiateWorkflowTemplate','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.filestore.87d2b845','file.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"file.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.filestore.87d2b845','file.googleapis.com','gcp',
  'high','GCP Filestore Instances: Create Filestore Instance','Detected CreateInstance on Filestore Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.filestore.e83ff0e0','file.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"file.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.filestore.e83ff0e0','file.googleapis.com','gcp',
  'high','GCP Filestore Instances: Delete Filestore Instance','Detected DeleteInstance on Filestore Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.filestore.fc9acf7a','file.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"file.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.filestore.fc9acf7a','file.googleapis.com','gcp',
  'medium','GCP Filestore Instances: Update Filestore Instance','Detected UpdateInstance on Filestore Instances via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateInstance','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.filestore.3aa2ac7f','file.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"file.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSnapshot"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.filestore.3aa2ac7f','file.googleapis.com','gcp',
  'high','GCP Filestore Snapshots: Create Filestore Snapshot','Detected CreateSnapshot on Filestore Snapshots via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSnapshot','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.filestore.5a3bc2ed','file.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"file.googleapis.com"},{"op":"contains","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.filestore.5a3bc2ed','file.googleapis.com','gcp',
  'high','GCP Filestore Backups: Create Filestore Backup','Detected CreateBackup on Filestore Backups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firestore.8e2628e7','firestore.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firestore.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firestore.8e2628e7','firestore.googleapis.com','gcp',
  'high','GCP Firestore Databases: Create Firestore Database','Detected CreateDatabase on Firestore Databases via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDatabase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firestore.e1f8f034','firestore.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firestore.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firestore.e1f8f034','firestore.googleapis.com','gcp',
  'high','GCP Firestore Databases: Delete Firestore Database','Detected DeleteDatabase on Firestore Databases via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteDatabase','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firestore.51cf05b8','firestore.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firestore.googleapis.com"},{"op":"contains","field":"operation","value":"CreateIndex"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firestore.51cf05b8','firestore.googleapis.com','gcp',
  'high','GCP Firestore Indexes: Create Firestore Index','Detected CreateIndex on Firestore Indexes via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateIndex','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firestore.b92065f0','firestore.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firestore.googleapis.com"},{"op":"contains","field":"operation","value":"ExportDocuments"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firestore.b92065f0','firestore.googleapis.com','gcp',
  'medium','GCP Firestore Export: Export Firestore Documents','Detected ExportDocuments on Firestore Export via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'ExportDocuments','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.firestore.64f1a6d6','firestore.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"firestore.googleapis.com"},{"op":"contains","field":"operation","value":"ImportDocuments"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.firestore.64f1a6d6','firestore.googleapis.com','gcp',
  'medium','GCP Firestore Import: Import Firestore Documents','Detected ImportDocuments on Firestore Import via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'ImportDocuments','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudiot.63141df9','cloudiot.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudiot.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDeviceRegistry"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudiot.63141df9','cloudiot.googleapis.com','gcp',
  'high','GCP IoT Registries: Create IoT Device Registry','Detected CreateDeviceRegistry on IoT Registries via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDeviceRegistry','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudiot.836a0875','cloudiot.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudiot.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteDeviceRegistry"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudiot.836a0875','cloudiot.googleapis.com','gcp',
  'high','GCP IoT Registries: Delete IoT Device Registry','Detected DeleteDeviceRegistry on IoT Registries via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteDeviceRegistry','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudiot.f52db7ed','cloudiot.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudiot.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDevice"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudiot.f52db7ed','cloudiot.googleapis.com','gcp',
  'high','GCP IoT Devices: Create IoT Device','Detected CreateDevice on IoT Devices via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDevice','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudiot.8269513d','cloudiot.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudiot.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteDevice"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudiot.8269513d','cloudiot.googleapis.com','gcp',
  'high','GCP IoT Devices: Delete IoT Device','Detected DeleteDevice on IoT Devices via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteDevice','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudiot.55b0226d','cloudiot.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudiot.googleapis.com"},{"op":"contains","field":"operation","value":"ModifyCloudToDeviceConfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudiot.55b0226d','cloudiot.googleapis.com','gcp',
  'medium','GCP IoT Configs: Modify IoT Device Config','Detected ModifyCloudToDeviceConfig on IoT Configs via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'ModifyCloudToDeviceConfig','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudtasks.5b7e4874','cloudtasks.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudtasks.googleapis.com"},{"op":"contains","field":"operation","value":"CreateQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudtasks.5b7e4874','cloudtasks.googleapis.com','gcp',
  'high','GCP Task Queues: Create Cloud Tasks Queue','Detected CreateQueue on Task Queues via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateQueue','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudtasks.c745f7d8','cloudtasks.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudtasks.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudtasks.c745f7d8','cloudtasks.googleapis.com','gcp',
  'high','GCP Task Queues: Delete Cloud Tasks Queue','Detected DeleteQueue on Task Queues via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteQueue','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudtasks.956f2f97','cloudtasks.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudtasks.googleapis.com"},{"op":"contains","field":"operation","value":"PauseQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudtasks.956f2f97','cloudtasks.googleapis.com','gcp',
  'medium','GCP Task Queues: Pause Cloud Tasks Queue','Detected PauseQueue on Task Queues via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'PauseQueue','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudtasks.f7c7fe06','cloudtasks.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudtasks.googleapis.com"},{"op":"contains","field":"operation","value":"PurgeQueue"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudtasks.f7c7fe06','cloudtasks.googleapis.com','gcp',
  'high','GCP Task Queues: Purge Cloud Tasks Queue','Detected PurgeQueue on Task Queues via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'PurgeQueue','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudtasks.3d89e889','cloudtasks.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudtasks.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTask"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudtasks.3d89e889','cloudtasks.googleapis.com','gcp',
  'high','GCP Tasks: Create Cloud Task','Detected CreateTask on Tasks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTask','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudscheduler.49dc8c70','cloudscheduler.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudscheduler.googleapis.com"},{"op":"contains","field":"operation","value":"CreateJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudscheduler.49dc8c70','cloudscheduler.googleapis.com','gcp',
  'high','GCP Scheduler Jobs: Create Cloud Scheduler Job','Detected CreateJob on Scheduler Jobs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateJob','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudscheduler.ba452a55','cloudscheduler.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudscheduler.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudscheduler.ba452a55','cloudscheduler.googleapis.com','gcp',
  'high','GCP Scheduler Jobs: Delete Cloud Scheduler Job','Detected DeleteJob on Scheduler Jobs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudscheduler.3aedf012','cloudscheduler.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudscheduler.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudscheduler.3aedf012','cloudscheduler.googleapis.com','gcp',
  'medium','GCP Scheduler Jobs: Update Cloud Scheduler Job','Detected UpdateJob on Scheduler Jobs via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateJob','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudscheduler.52e80d6e','cloudscheduler.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudscheduler.googleapis.com"},{"op":"contains","field":"operation","value":"PauseJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudscheduler.52e80d6e','cloudscheduler.googleapis.com','gcp',
  'medium','GCP Scheduler Jobs: Pause Cloud Scheduler Job','Detected PauseJob on Scheduler Jobs via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'PauseJob','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.redis.533cbc85','redis.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"redis.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.redis.533cbc85','redis.googleapis.com','gcp',
  'high','GCP Memorystore Redis: Create Memorystore Redis Instance','Detected CreateInstance on Memorystore Redis via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.redis.0af3e390','redis.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"redis.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.redis.0af3e390','redis.googleapis.com','gcp',
  'high','GCP Memorystore Redis: Delete Memorystore Redis Instance','Detected DeleteInstance on Memorystore Redis via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.redis.1d68b5ca','redis.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"redis.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.redis.1d68b5ca','redis.googleapis.com','gcp',
  'medium','GCP Memorystore Redis: Update Memorystore Redis Instance','Detected UpdateInstance on Memorystore Redis via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateInstance','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.redis.f93b4cc2','redis.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"redis.googleapis.com"},{"op":"contains","field":"operation","value":"FailoverInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.redis.f93b4cc2','redis.googleapis.com','gcp',
  'medium','GCP Memorystore Redis: Failover Memorystore Redis Instance','Detected FailoverInstance on Memorystore Redis via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'FailoverInstance','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.memcache.0ffbdfe2','memcache.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"memcache.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.memcache.0ffbdfe2','memcache.googleapis.com','gcp',
  'high','GCP Memorystore Memcached: Create Memorystore Memcached Instance','Detected CreateInstance on Memorystore Memcached via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.memcache.981f7998','memcache.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"memcache.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.memcache.981f7998','memcache.googleapis.com','gcp',
  'high','GCP Memorystore Memcached: Delete Memorystore Memcached Instance','Detected DeleteInstance on Memorystore Memcached via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iap.64a049ab','iap.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iap.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTunnelDestGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iap.64a049ab','iap.googleapis.com','gcp',
  'high','GCP IAP Tunnel: Create IAP Tunnel Destination Group','Detected CreateTunnelDestGroup on IAP Tunnel via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTunnelDestGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iap.ea436944','iap.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iap.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteTunnelDestGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iap.ea436944','iap.googleapis.com','gcp',
  'high','GCP IAP Tunnel: Delete IAP Tunnel Destination Group','Detected DeleteTunnelDestGroup on IAP Tunnel via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteTunnelDestGroup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iap.8cf6c89d','iap.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iap.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateIapSettings"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iap.8cf6c89d','iap.googleapis.com','gcp',
  'medium','GCP IAP Settings: Update IAP Settings','Detected UpdateIapSettings on IAP Settings via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateIapSettings','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networkconnectivity.52b1812a','networkconnectivity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networkconnectivity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateHub"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networkconnectivity.52b1812a','networkconnectivity.googleapis.com','gcp',
  'high','GCP Network Hubs: Create Network Connectivity Hub','Detected CreateHub on Network Hubs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateHub','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networkconnectivity.143187d7','networkconnectivity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networkconnectivity.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteHub"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networkconnectivity.143187d7','networkconnectivity.googleapis.com','gcp',
  'high','GCP Network Hubs: Delete Network Connectivity Hub','Detected DeleteHub on Network Hubs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteHub','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networkconnectivity.46885ee0','networkconnectivity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networkconnectivity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSpoke"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networkconnectivity.46885ee0','networkconnectivity.googleapis.com','gcp',
  'high','GCP Network Spokes: Create Network Connectivity Spoke','Detected CreateSpoke on Network Spokes via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSpoke','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networkconnectivity.d24e887f','networkconnectivity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networkconnectivity.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteSpoke"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networkconnectivity.d24e887f','networkconnectivity.googleapis.com','gcp',
  'high','GCP Network Spokes: Delete Network Connectivity Spoke','Detected DeleteSpoke on Network Spokes via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteSpoke','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.networkconnectivity.2d9908d9','networkconnectivity.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"networkconnectivity.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServiceConnectionPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.networkconnectivity.2d9908d9','networkconnectivity.googleapis.com','gcp',
  'high','GCP Service Connection Policies: Create Service Connection Policy','Detected CreateServiceConnectionPolicy on Service Connection Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateServiceConnectionPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.71c59faf','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCaPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.71c59faf','privateca.googleapis.com','gcp',
  'high','GCP CA Pool: Create Certificate Authority Pool','Detected CreateCaPool on CA Pool via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCaPool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.4d0974c0','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCaPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.4d0974c0','privateca.googleapis.com','gcp',
  'high','GCP CA Pool: Delete Certificate Authority Pool','Detected DeleteCaPool on CA Pool via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCaPool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.248e5304','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCertificateAuthority"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.248e5304','privateca.googleapis.com','gcp',
  'high','GCP Certificate Authority: Create Certificate Authority','Detected CreateCertificateAuthority on Certificate Authority via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCertificateAuthority','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.0b663965','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCertificateAuthority"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.0b663965','privateca.googleapis.com','gcp',
  'high','GCP Certificate Authority: Delete Certificate Authority','Detected DeleteCertificateAuthority on Certificate Authority via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCertificateAuthority','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.861aaf12','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.861aaf12','privateca.googleapis.com','gcp',
  'high','GCP Certificates: Issue Certificate from Private CA','Detected CreateCertificate on Certificates via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCertificate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.privateca.6f0b43e0','privateca.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"privateca.googleapis.com"},{"op":"contains","field":"operation","value":"RevokeCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.privateca.6f0b43e0','privateca.googleapis.com','gcp',
  'high','GCP Certificates: Revoke Certificate from Private CA','Detected RevokeCertificate on Certificates via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'RevokeCertificate','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.serviceusage.6aab7b2d','serviceusage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"serviceusage.googleapis.com"},{"op":"contains","field":"operation","value":"EnableService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.serviceusage.6aab7b2d','serviceusage.googleapis.com','gcp',
  'high','GCP APIs: Enable GCP API/Service','Detected EnableService on APIs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'EnableService','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.serviceusage.92cd3e75','serviceusage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"serviceusage.googleapis.com"},{"op":"contains","field":"operation","value":"DisableService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.serviceusage.92cd3e75','serviceusage.googleapis.com','gcp',
  'high','GCP APIs: Disable GCP API/Service','Detected DisableService on APIs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DisableService','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.serviceusage.e7ef1c94','serviceusage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"serviceusage.googleapis.com"},{"op":"contains","field":"operation","value":"BatchEnableServices"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.serviceusage.e7ef1c94','serviceusage.googleapis.com','gcp',
  'high','GCP APIs: Batch Enable GCP APIs','Detected BatchEnableServices on APIs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'BatchEnableServices','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.deb8237c','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDataset"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.deb8237c','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Datasets: Create Vertex AI Dataset','Detected CreateDataset on Vertex AI Datasets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDataset','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.fc426d4b','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteDataset"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.fc426d4b','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Datasets: Delete Vertex AI Dataset','Detected DeleteDataset on Vertex AI Datasets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteDataset','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.17815b5c','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTrainingPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.17815b5c','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Training: Create Vertex AI Training Pipeline','Detected CreateTrainingPipeline on Vertex AI Training via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTrainingPipeline','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.eb0ee2b7','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"UploadModel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.eb0ee2b7','aiplatform.googleapis.com','gcp',
  'medium','GCP Vertex AI Models: Upload Vertex AI Model','Detected UploadModel on Vertex AI Models via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UploadModel','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.02d51f4b','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteModel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.02d51f4b','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Models: Delete Vertex AI Model','Detected DeleteModel on Vertex AI Models via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteModel','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.fd4e920b','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"CreateEndpoint"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.fd4e920b','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Endpoints: Create Vertex AI Endpoint','Detected CreateEndpoint on Vertex AI Endpoints via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateEndpoint','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.5d7b9668','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteEndpoint"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.5d7b9668','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Endpoints: Delete Vertex AI Endpoint','Detected DeleteEndpoint on Vertex AI Endpoints via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteEndpoint','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.505997d5','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"DeployModel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.505997d5','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Endpoints: Deploy Model to Vertex AI Endpoint','Detected DeployModel on Vertex AI Endpoints via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'DeployModel','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.aiplatform.edfec68a','aiplatform.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"aiplatform.googleapis.com"},{"op":"contains","field":"operation","value":"CreateNotebookInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.aiplatform.edfec68a','aiplatform.googleapis.com','gcp',
  'high','GCP Vertex AI Notebooks: Create Vertex AI Notebook','Detected CreateNotebookInstance on Vertex AI Notebooks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateNotebookInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workstations.a0e5eaa1','workstations.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workstations.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkstationCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workstations.a0e5eaa1','workstations.googleapis.com','gcp',
  'high','GCP Workstation Clusters: Create Cloud Workstation Cluster','Detected CreateWorkstationCluster on Workstation Clusters via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkstationCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workstations.fb640d08','workstations.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workstations.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteWorkstationCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workstations.fb640d08','workstations.googleapis.com','gcp',
  'high','GCP Workstation Clusters: Delete Cloud Workstation Cluster','Detected DeleteWorkstationCluster on Workstation Clusters via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteWorkstationCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workstations.84d95a80','workstations.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workstations.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkstationConfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workstations.84d95a80','workstations.googleapis.com','gcp',
  'high','GCP Workstation Configs: Create Workstation Configuration','Detected CreateWorkstationConfig on Workstation Configs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkstationConfig','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workstations.cad2ed6b','workstations.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workstations.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkstation"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workstations.cad2ed6b','workstations.googleapis.com','gcp',
  'high','GCP Workstations: Create Workstation','Detected CreateWorkstation on Workstations via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkstation','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.workstations.5ef2a64a','workstations.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"workstations.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteWorkstation"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.workstations.5ef2a64a','workstations.googleapis.com','gcp',
  'high','GCP Workstations: Delete Workstation','Detected DeleteWorkstation on Workstations via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteWorkstation','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.artifactregistry.04427a9a','artifactregistry.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"artifactregistry.googleapis.com"},{"op":"contains","field":"operation","value":"CreateRepository"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.artifactregistry.04427a9a','artifactregistry.googleapis.com','gcp',
  'high','GCP AR Repos: Create Artifact Registry Repository','Detected CreateRepository on AR Repos via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateRepository','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.artifactregistry.9f906625','artifactregistry.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"artifactregistry.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteRepository"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.artifactregistry.9f906625','artifactregistry.googleapis.com','gcp',
  'high','GCP AR Repos: Delete Artifact Registry Repository','Detected DeleteRepository on AR Repos via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteRepository','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.artifactregistry.23d995c9','artifactregistry.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"artifactregistry.googleapis.com"},{"op":"contains","field":"operation","value":"DeletePackage"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.artifactregistry.23d995c9','artifactregistry.googleapis.com','gcp',
  'high','GCP AR Packages: Delete Package from Artifact Registry','Detected DeletePackage on AR Packages via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeletePackage','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.artifactregistry.bcb1dceb','artifactregistry.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"artifactregistry.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTag"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.artifactregistry.bcb1dceb','artifactregistry.googleapis.com','gcp',
  'high','GCP AR Tags: Create Artifact Registry Tag','Detected CreateTag on AR Tags via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTag','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.fd49fb28','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.fd49fb28','container.googleapis.com','gcp',
  'high','GCP GKE Clusters: Create GKE Cluster','Detected CreateCluster on GKE Clusters via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.e0483626','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.e0483626','container.googleapis.com','gcp',
  'high','GCP GKE Clusters: Delete GKE Cluster','Detected DeleteCluster on GKE Clusters via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.4da13028','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.4da13028','container.googleapis.com','gcp',
  'medium','GCP GKE Clusters: Update GKE Cluster','Detected UpdateCluster on GKE Clusters via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateCluster','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.efd37ebc','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"CreateNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.efd37ebc','container.googleapis.com','gcp',
  'high','GCP GKE Node Pools: Create GKE Node Pool','Detected CreateNodePool on GKE Node Pools via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateNodePool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.9c121020','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteNodePool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.9c121020','container.googleapis.com','gcp',
  'high','GCP GKE Node Pools: Delete GKE Node Pool','Detected DeleteNodePool on GKE Node Pools via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteNodePool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.4d247d4e','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"SetNodePoolSize"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.4d247d4e','container.googleapis.com','gcp',
  'medium','GCP GKE Node Pools: Scale GKE Node Pool','Detected SetNodePoolSize on GKE Node Pools via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'SetNodePoolSize','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.container.5df05384','container.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"container.googleapis.com"},{"op":"contains","field":"operation","value":"CreateRoleBinding"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.container.5df05384','container.googleapis.com','gcp',
  'high','GCP GKE RBAC: Create GKE RBAC Role Binding','Detected CreateRoleBinding on GKE RBAC via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateRoleBinding','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Instances: Create Compute Instance','Detected insert on Compute Instances via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Instances: Delete Compute Instance','Detected delete on Compute Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Disks: Create Compute Disk','Detected insert on Compute Disks via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Disks: Delete Compute Disk','Detected delete on Compute Disks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Firewall: Create VPC Firewall Rule','Detected insert on Compute Firewall via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Firewall: Delete VPC Firewall Rule','Detected delete on Compute Firewall via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Images: Create Compute Image','Detected insert on Compute Images via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Images: Delete Compute Image','Detected delete on Compute Images via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.d8461b4b','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Networks: Delete VPC Network','Detected delete on Compute Networks via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Subnetworks: Create VPC Subnetwork','Detected insert on Compute Subnetworks via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Subnetworks: Delete VPC Subnetwork','Detected delete on Compute Subnetworks via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Target Proxies: Create Load Balancer Target Proxy','Detected insert on Compute Target Proxies via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Backend Services: Create Compute Backend Service','Detected insert on Compute Backend Services via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Backend Services: Delete Compute Backend Service','Detected delete on Compute Backend Services via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"compute.googleapis.com"},{"op":"contains","field":"operation","value":"insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute URL Maps: Create Compute URL Map','Detected insert on Compute URL Maps via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute SSL Certs: Create Compute SSL Certificate','Detected insert on Compute SSL Certs via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.a6c9fd66','compute.googleapis.com','gcp',
  'high','GCP Compute Security Policies: Create Cloud Armor Security Policy','Detected insert on Compute Security Policies via GCP Audit Logs.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.compute.d8461b4b','compute.googleapis.com','gcp',
  'high','GCP Compute Security Policies: Delete Cloud Armor Security Policy','Detected delete on Compute Security Policies via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.2fc868eb','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesInsert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.2fc868eb','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Instances: Create Cloud SQL Instance','Detected SqlInstancesInsert on Cloud SQL Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'SqlInstancesInsert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.385909be','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesDelete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.385909be','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Instances: Delete Cloud SQL Instance','Detected SqlInstancesDelete on Cloud SQL Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'SqlInstancesDelete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.1912ee84','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesRestart"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.1912ee84','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Instances: Restart Cloud SQL Instance','Detected SqlInstancesRestart on Cloud SQL Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'SqlInstancesRestart','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.0a609e01','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesImport"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.0a609e01','sqladmin.googleapis.com','gcp',
  'medium','GCP Cloud SQL Instances: Import Data to Cloud SQL','Detected SqlInstancesImport on Cloud SQL Instances via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'SqlInstancesImport','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.d91a9e89','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlBackupRunsInsert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.d91a9e89','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Backups: Create Cloud SQL Backup','Detected SqlBackupRunsInsert on Cloud SQL Backups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'SqlBackupRunsInsert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.a4a1fc5f','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlBackupRunsDelete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.a4a1fc5f','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Backups: Delete Cloud SQL Backup','Detected SqlBackupRunsDelete on Cloud SQL Backups via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'SqlBackupRunsDelete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.sqladmin.24591d86','sqladmin.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"sqladmin.googleapis.com"},{"op":"contains","field":"operation","value":"SqlInstancesAddServerCa"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.sqladmin.24591d86','sqladmin.googleapis.com','gcp',
  'high','GCP Cloud SQL Replicas: Add Cloud SQL Server CA','Detected SqlInstancesAddServerCa on Cloud SQL Replicas via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'SqlInstancesAddServerCa','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.4406e245','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"CreateInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.4406e245','spanner.googleapis.com','gcp',
  'high','GCP Spanner Instances: Create Spanner Instance','Detected CreateInstance on Spanner Instances via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateInstance','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.68ff62d0','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteInstance"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.68ff62d0','spanner.googleapis.com','gcp',
  'high','GCP Spanner Instances: Delete Spanner Instance','Detected DeleteInstance on Spanner Instances via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteInstance','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.b19f9841','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"CreateDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.b19f9841','spanner.googleapis.com','gcp',
  'high','GCP Spanner Databases: Create Spanner Database','Detected CreateDatabase on Spanner Databases via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateDatabase','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.b09bd4be','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"DropDatabase"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.b09bd4be','spanner.googleapis.com','gcp',
  'high','GCP Spanner Databases: Drop Spanner Database','Detected DropDatabase on Spanner Databases via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DropDatabase','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.f9991a51','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"CreateBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.f9991a51','spanner.googleapis.com','gcp',
  'high','GCP Spanner Backups: Create Spanner Backup','Detected CreateBackup on Spanner Backups via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateBackup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.spanner.740332cf','spanner.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"spanner.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteBackup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.spanner.740332cf','spanner.googleapis.com','gcp',
  'high','GCP Spanner Backups: Delete Spanner Backup','Detected DeleteBackup on Spanner Backups via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteBackup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigquery.27aaaf99','bigquery.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"datasetservice.insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigquery.27aaaf99','bigquery.googleapis.com','gcp',
  'high','GCP BigQuery Datasets: Create BigQuery Dataset','Detected datasetservice.insert on BigQuery Datasets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'datasetservice.insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigquery.501ae898','bigquery.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"datasetservice.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigquery.501ae898','bigquery.googleapis.com','gcp',
  'high','GCP BigQuery Datasets: Delete BigQuery Dataset','Detected datasetservice.delete on BigQuery Datasets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'datasetservice.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigquery.015b2e35','bigquery.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"tableservice.insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigquery.015b2e35','bigquery.googleapis.com','gcp',
  'high','GCP BigQuery Tables: Create BigQuery Table','Detected tableservice.insert on BigQuery Tables via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'tableservice.insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigquery.22cf80cb','bigquery.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"tableservice.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigquery.22cf80cb','bigquery.googleapis.com','gcp',
  'high','GCP BigQuery Tables: Delete BigQuery Table','Detected tableservice.delete on BigQuery Tables via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'tableservice.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.bigquery.44d08f02','bigquery.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"bigquery.googleapis.com"},{"op":"contains","field":"operation","value":"transfers.insert"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.bigquery.44d08f02','bigquery.googleapis.com','gcp',
  'high','GCP BigQuery Transfers: Create BigQuery Data Transfer','Detected transfers.insert on BigQuery Transfers via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'transfers.insert','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudkms.d4fd04de','cloudkms.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"CreateKeyRing"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudkms.d4fd04de','cloudkms.googleapis.com','gcp',
  'high','GCP KMS Key Rings: Create KMS Key Ring','Detected CreateKeyRing on KMS Key Rings via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateKeyRing','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudkms.664a21bf','cloudkms.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCryptoKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudkms.664a21bf','cloudkms.googleapis.com','gcp',
  'high','GCP KMS Keys: Create KMS Crypto Key','Detected CreateCryptoKey on KMS Keys via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCryptoKey','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudkms.a8f49aa5','cloudkms.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateCryptoKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudkms.a8f49aa5','cloudkms.googleapis.com','gcp',
  'medium','GCP KMS Keys: Update KMS Crypto Key','Detected UpdateCryptoKey on KMS Keys via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateCryptoKey','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudkms.ae295372','cloudkms.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"CreateCryptoKeyVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudkms.ae295372','cloudkms.googleapis.com','gcp',
  'high','GCP KMS Key Versions: Create KMS Key Version','Detected CreateCryptoKeyVersion on KMS Key Versions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateCryptoKeyVersion','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudkms.02ebcca7','cloudkms.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudkms.googleapis.com"},{"op":"contains","field":"operation","value":"DestroyCryptoKeyVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudkms.02ebcca7','cloudkms.googleapis.com','gcp',
  'high','GCP KMS Key Versions: Destroy KMS Key Version','Detected DestroyCryptoKeyVersion on KMS Key Versions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DestroyCryptoKeyVersion','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.d7b75bb7','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.buckets.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.d7b75bb7','storage.googleapis.com','gcp',
  'high','GCP GCS Buckets: Create GCS Bucket','Detected storage.buckets.create on GCS Buckets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'storage.buckets.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.203bccce','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.buckets.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.203bccce','storage.googleapis.com','gcp',
  'high','GCP GCS Buckets: Delete GCS Bucket','Detected storage.buckets.delete on GCS Buckets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'storage.buckets.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.97311e84','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.buckets.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.97311e84','storage.googleapis.com','gcp',
  'medium','GCP GCS Buckets: Update GCS Bucket Configuration','Detected storage.buckets.update on GCS Buckets via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'storage.buckets.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.storage.e3a9b7df','storage.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"storage.googleapis.com"},{"op":"contains","field":"operation","value":"storage.objects.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.storage.e3a9b7df','storage.googleapis.com','gcp',
  'high','GCP GCS Objects: Delete GCS Object','Detected storage.objects.delete on GCS Objects via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'storage.objects.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsub.65c590cc','pubsub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsub.googleapis.com"},{"op":"contains","field":"operation","value":"google.pubsub.v1.Publisher.CreateTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsub.65c590cc','pubsub.googleapis.com','gcp',
  'high','GCP Pub/Sub Topics: Create Pub/Sub Topic','Detected google.pubsub.v1.Publisher.CreateTopic on Pub/Sub Topics via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.pubsub.v1.Publisher.CreateTopic','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsub.78dfba78','pubsub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsub.googleapis.com"},{"op":"contains","field":"operation","value":"google.pubsub.v1.Publisher.DeleteTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsub.78dfba78','pubsub.googleapis.com','gcp',
  'high','GCP Pub/Sub Topics: Delete Pub/Sub Topic','Detected google.pubsub.v1.Publisher.DeleteTopic on Pub/Sub Topics via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.pubsub.v1.Publisher.DeleteTopic','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsub.239a17b3','pubsub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsub.googleapis.com"},{"op":"contains","field":"operation","value":"google.pubsub.v1.Subscriber.CreateSubscription"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsub.239a17b3','pubsub.googleapis.com','gcp',
  'high','GCP Pub/Sub Subscriptions: Create Pub/Sub Subscription','Detected google.pubsub.v1.Subscriber.CreateSubscription on Pub/Sub Subscriptions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.pubsub.v1.Subscriber.CreateSubscription','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.pubsub.f5a30605','pubsub.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"pubsub.googleapis.com"},{"op":"contains","field":"operation","value":"google.pubsub.v1.Subscriber.DeleteSubscription"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.pubsub.f5a30605','pubsub.googleapis.com','gcp',
  'high','GCP Pub/Sub Subscriptions: Delete Pub/Sub Subscription','Detected google.pubsub.v1.Subscriber.DeleteSubscription on Pub/Sub Subscriptions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'google.pubsub.v1.Subscriber.DeleteSubscription','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.secretmanager.76c595d3','secretmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSecret"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.secretmanager.76c595d3','secretmanager.googleapis.com','gcp',
  'high','GCP Secrets: Create Secret','Detected CreateSecret on Secrets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSecret','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.secretmanager.f939e6ac','secretmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteSecret"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.secretmanager.f939e6ac','secretmanager.googleapis.com','gcp',
  'high','GCP Secrets: Delete Secret','Detected DeleteSecret on Secrets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteSecret','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.secretmanager.1f8632b0','secretmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"AddSecretVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.secretmanager.1f8632b0','secretmanager.googleapis.com','gcp',
  'high','GCP Secret Versions: Add Secret Version','Detected AddSecretVersion on Secret Versions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'AddSecretVersion','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.secretmanager.2cf310be','secretmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"DestroySecretVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.secretmanager.2cf310be','secretmanager.googleapis.com','gcp',
  'high','GCP Secret Versions: Destroy Secret Version','Detected DestroySecretVersion on Secret Versions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DestroySecretVersion','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.secretmanager.6758363d','secretmanager.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"secretmanager.googleapis.com"},{"op":"contains","field":"operation","value":"DisableSecretVersion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.secretmanager.6758363d','secretmanager.googleapis.com','gcp',
  'high','GCP Secret Versions: Disable Secret Version','Detected DisableSecretVersion on Secret Versions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DisableSecretVersion','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudfunctions.fc083e66','cloudfunctions.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudfunctions.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.functions.v1.CloudFunctionsService.DeleteFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudfunctions.fc083e66','cloudfunctions.googleapis.com','gcp',
  'high','GCP Cloud Functions: Delete Cloud Function','Detected google.cloud.functions.v1.CloudFunctionsService.DeleteFunction on Cloud Functions via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'google.cloud.functions.v1.CloudFunctionsService.DeleteFunction','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudfunctions.dc8f8c1d','cloudfunctions.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudfunctions.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.functions.v1.CloudFunctionsService.UpdateFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudfunctions.dc8f8c1d','cloudfunctions.googleapis.com','gcp',
  'medium','GCP Cloud Functions: Update Cloud Function','Detected google.cloud.functions.v1.CloudFunctionsService.UpdateFunction on Cloud Functions via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'google.cloud.functions.v1.CloudFunctionsService.UpdateFunction','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudfunctions.f3e22d8d','cloudfunctions.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudfunctions.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.functions.v2.FunctionService.CreateFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudfunctions.f3e22d8d','cloudfunctions.googleapis.com','gcp',
  'high','GCP Cloud Functions: Create Cloud Function v2','Detected google.cloud.functions.v2.FunctionService.CreateFunction on Cloud Functions via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.cloud.functions.v2.FunctionService.CreateFunction','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.run.cea00a03','run.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"run.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.run.v1.Services.DeleteService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.run.cea00a03','run.googleapis.com','gcp',
  'high','GCP Cloud Run Services: Delete Cloud Run Service','Detected google.cloud.run.v1.Services.DeleteService on Cloud Run Services via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'google.cloud.run.v1.Services.DeleteService','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.run.0291f011','run.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"run.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.run.v1.Services.ReplaceService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.run.0291f011','run.googleapis.com','gcp',
  'medium','GCP Cloud Run Services: Update Cloud Run Service','Detected google.cloud.run.v1.Services.ReplaceService on Cloud Run Services via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'google.cloud.run.v1.Services.ReplaceService','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.run.d7546207','run.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"run.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.run.v1.Jobs.CreateJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.run.d7546207','run.googleapis.com','gcp',
  'high','GCP Cloud Run Jobs: Create Cloud Run Job','Detected google.cloud.run.v1.Jobs.CreateJob on Cloud Run Jobs via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.cloud.run.v1.Jobs.CreateJob','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.run.1c277f71','run.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"run.googleapis.com"},{"op":"contains","field":"operation","value":"google.cloud.run.v1.Jobs.DeleteJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.run.1c277f71','run.googleapis.com','gcp',
  'high','GCP Cloud Run Jobs: Delete Cloud Run Job','Detected google.cloud.run.v1.Jobs.DeleteJob on Cloud Run Jobs via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'google.cloud.run.v1.Jobs.DeleteJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.logging.5ca1a243','logging.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"CreateSink"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.logging.5ca1a243','logging.googleapis.com','gcp',
  'high','GCP Log Sinks: Create Log Sink','Detected CreateSink on Log Sinks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateSink','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.logging.773a3cda','logging.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateSink"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.logging.773a3cda','logging.googleapis.com','gcp',
  'medium','GCP Log Sinks: Update Log Sink','Detected UpdateSink on Log Sinks via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateSink','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.logging.7e8a86b0','logging.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"CreateBucket"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.logging.7e8a86b0','logging.googleapis.com','gcp',
  'high','GCP Log Buckets: Create Log Bucket','Detected CreateBucket on Log Buckets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateBucket','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.logging.b4328c9f','logging.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteBucket"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.logging.b4328c9f','logging.googleapis.com','gcp',
  'high','GCP Log Buckets: Delete Log Bucket','Detected DeleteBucket on Log Buckets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteBucket','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.logging.8eab60c8','logging.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"logging.googleapis.com"},{"op":"contains","field":"operation","value":"CreateView"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.logging.8eab60c8','logging.googleapis.com','gcp',
  'high','GCP Log Views: Create Log View','Detected CreateView on Log Views via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateView','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.monitoring.73fed4fa','monitoring.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"CreateAlertPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.monitoring.73fed4fa','monitoring.googleapis.com','gcp',
  'high','GCP Monitoring Alert Policies: Create Monitoring Alert Policy','Detected CreateAlertPolicy on Monitoring Alert Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateAlertPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.monitoring.5735eb21','monitoring.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"UpdateAlertPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.monitoring.5735eb21','monitoring.googleapis.com','gcp',
  'medium','GCP Monitoring Alert Policies: Update Monitoring Alert Policy','Detected UpdateAlertPolicy on Monitoring Alert Policies via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'UpdateAlertPolicy','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.monitoring.8db1c261','monitoring.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"CreateNotificationChannel"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.monitoring.8db1c261','monitoring.googleapis.com','gcp',
  'high','GCP Notification Channels: Create Monitoring Notification Channel','Detected CreateNotificationChannel on Notification Channels via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateNotificationChannel','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.monitoring.51f22886','monitoring.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"CreateUptimeCheckConfig"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.monitoring.51f22886','monitoring.googleapis.com','gcp',
  'high','GCP Uptime Checks: Create Uptime Check','Detected CreateUptimeCheckConfig on Uptime Checks via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateUptimeCheckConfig','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.monitoring.1f06ad98','monitoring.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"monitoring.googleapis.com"},{"op":"contains","field":"operation","value":"CreateService"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.monitoring.1f06ad98','monitoring.googleapis.com','gcp',
  'high','GCP Service Monitoring: Create Monitored Service','Detected CreateService on Service Monitoring via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateService','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudbuild.dc6eaf19','cloudbuild.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudbuild.googleapis.com"},{"op":"contains","field":"operation","value":"google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudbuild.dc6eaf19','cloudbuild.googleapis.com','gcp',
  'medium','GCP Build Triggers: Update Cloud Build Trigger','Detected google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger on Build Triggers via GCP Audit Logs.',
  'persistence','modify','gcp_audit',
  'google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudbuild.0fdb013f','cloudbuild.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudbuild.googleapis.com"},{"op":"contains","field":"operation","value":"google.devtools.cloudbuild.v1.CloudBuild.DeleteBuildTrigger"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudbuild.0fdb013f','cloudbuild.googleapis.com','gcp',
  'high','GCP Build Triggers: Delete Cloud Build Trigger','Detected google.devtools.cloudbuild.v1.CloudBuild.DeleteBuildTrigger on Build Triggers via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'google.devtools.cloudbuild.v1.CloudBuild.DeleteBuildTrigger','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.cloudbuild.4361ae67','cloudbuild.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"cloudbuild.googleapis.com"},{"op":"contains","field":"operation","value":"google.devtools.cloudbuild.v1.CloudBuild.CreateWorkerPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.cloudbuild.4361ae67','cloudbuild.googleapis.com','gcp',
  'high','GCP Worker Pools: Create Cloud Build Worker Pool','Detected google.devtools.cloudbuild.v1.CloudBuild.CreateWorkerPool on Worker Pools via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'google.devtools.cloudbuild.v1.CloudBuild.CreateWorkerPool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.9cfbe995','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServiceAccountKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.9cfbe995','iam.googleapis.com','gcp',
  'high','GCP Service Account Keys: Create Service Account Key','Detected CreateServiceAccountKey on Service Account Keys via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateServiceAccountKey','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.3a3bb776','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteServiceAccountKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.3a3bb776','iam.googleapis.com','gcp',
  'high','GCP Service Account Keys: Delete Service Account Key','Detected DeleteServiceAccountKey on Service Account Keys via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteServiceAccountKey','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.61f232e0','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateServiceAccount"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.61f232e0','iam.googleapis.com','gcp',
  'high','GCP Service Accounts: Create Service Account','Detected CreateServiceAccount on Service Accounts via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateServiceAccount','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.52ff73e4','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteServiceAccount"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.52ff73e4','iam.googleapis.com','gcp',
  'high','GCP Service Accounts: Delete Service Account','Detected DeleteServiceAccount on Service Accounts via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteServiceAccount','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.7c951c2a','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkloadIdentityPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.7c951c2a','iam.googleapis.com','gcp',
  'high','GCP Workload Identity Pools: Create Workload Identity Pool','Detected CreateWorkloadIdentityPool on Workload Identity Pools via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkloadIdentityPool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.2c540d2f','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"DeleteWorkloadIdentityPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.2c540d2f','iam.googleapis.com','gcp',
  'high','GCP Workload Identity Pools: Delete Workload Identity Pool','Detected DeleteWorkloadIdentityPool on Workload Identity Pools via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'DeleteWorkloadIdentityPool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.iam.2ecbd36b','iam.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"iam.googleapis.com"},{"op":"contains","field":"operation","value":"CreateWorkloadIdentityPoolProvider"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.iam.2ecbd36b','iam.googleapis.com','gcp',
  'high','GCP WI Pool Providers: Create Workload Identity Provider','Detected CreateWorkloadIdentityPoolProvider on WI Pool Providers via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateWorkloadIdentityPoolProvider','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dns.bd6b1571','dns.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dns.googleapis.com"},{"op":"contains","field":"operation","value":"dns.managedZones.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dns.bd6b1571','dns.googleapis.com','gcp',
  'high','GCP DNS Zones: Create DNS Managed Zone','Detected dns.managedZones.create on DNS Zones via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'dns.managedZones.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dns.70591332','dns.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dns.googleapis.com"},{"op":"contains","field":"operation","value":"dns.resourceRecordSets.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dns.70591332','dns.googleapis.com','gcp',
  'high','GCP DNS Record Sets: Create DNS Record Set','Detected dns.resourceRecordSets.create on DNS Record Sets via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'dns.resourceRecordSets.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dns.84b6835c','dns.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dns.googleapis.com"},{"op":"contains","field":"operation","value":"dns.resourceRecordSets.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dns.84b6835c','dns.googleapis.com','gcp',
  'high','GCP DNS Record Sets: Delete DNS Record Set','Detected dns.resourceRecordSets.delete on DNS Record Sets via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'dns.resourceRecordSets.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dns.df6ed6be','dns.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dns.googleapis.com"},{"op":"contains","field":"operation","value":"dns.policies.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dns.df6ed6be','dns.googleapis.com','gcp',
  'high','GCP DNS Policies: Create DNS Policy','Detected dns.policies.create on DNS Policies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'dns.policies.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.dns.ab7020a6','dns.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"dns.googleapis.com"},{"op":"contains","field":"operation","value":"dns.policies.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.dns.ab7020a6','dns.googleapis.com','gcp',
  'high','GCP DNS Policies: Delete DNS Policy','Detected dns.policies.delete on DNS Policies via GCP Audit Logs.',
  'impact','delete','gcp_audit',
  'dns.policies.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.datacatalog.d9e99843','datacatalog.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"datacatalog.googleapis.com"},{"op":"contains","field":"operation","value":"CreateEntry"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.datacatalog.d9e99843','datacatalog.googleapis.com','gcp',
  'high','GCP Data Catalog Entries: Create Data Catalog Entry','Detected CreateEntry on Data Catalog Entries via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateEntry','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.datacatalog.879076b1','datacatalog.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"datacatalog.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTag"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.datacatalog.879076b1','datacatalog.googleapis.com','gcp',
  'high','GCP Data Catalog Tags: Create Data Catalog Tag','Detected CreateTag on Data Catalog Tags via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTag','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.datacatalog.cad0871b','datacatalog.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"datacatalog.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTagTemplate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.datacatalog.cad0871b','datacatalog.googleapis.com','gcp',
  'high','GCP Data Catalog Tag Templates: Create Data Catalog Tag Template','Detected CreateTagTemplate on Data Catalog Tag Templates via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTagTemplate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.gcp.datacatalog.1ad729bf','datacatalog.googleapis.com','gcp','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"gcp_audit"},{"op":"equals","field":"service","value":"datacatalog.googleapis.com"},{"op":"contains","field":"operation","value":"CreateTaxonomy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.gcp.datacatalog.1ad729bf','datacatalog.googleapis.com','gcp',
  'high','GCP Data Catalog Taxonomies: Create Data Catalog Taxonomy','Detected CreateTaxonomy on Data Catalog Taxonomies via GCP Audit Logs.',
  'persistence','create','gcp_audit',
  'CreateTaxonomy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','gcp'
) ON CONFLICT DO NOTHING;

