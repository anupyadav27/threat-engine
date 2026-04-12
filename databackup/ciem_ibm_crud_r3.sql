-- IBM CRUD round 3
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.8b15f878','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.8b15f878','power_iaas','ibm',
  'high','IBM Power VS Instances: Create Power Virtual Server Instance','Detected instance.create on Power VS Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.ca946e05','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".instance.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.ca946e05','power_iaas','ibm',
  'medium','IBM Power VS Instances: Update Power Virtual Server Instance','Detected instance.update on Power VS Instances via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'instance.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.8ab1c50c','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".instance.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.8ab1c50c','power_iaas','ibm',
  'high','IBM Power VS Instances: Delete Power Virtual Server Instance','Detected instance.delete on Power VS Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.6b6100a8','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".instance.start"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.6b6100a8','power_iaas','ibm',
  'high','IBM Power VS Instances: Start Power Virtual Server Instance','Detected instance.start on Power VS Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.start','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.1884925b','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".instance.stop"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.1884925b','power_iaas','ibm',
  'high','IBM Power VS Instances: Stop Power Virtual Server Instance','Detected instance.stop on Power VS Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.stop','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.a2808e0d','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".volume.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.a2808e0d','power_iaas','ibm',
  'high','IBM Power VS Volumes: Create Power VS Volume','Detected volume.create on Power VS Volumes via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'volume.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.58e2e6df','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".volume.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.58e2e6df','power_iaas','ibm',
  'high','IBM Power VS Volumes: Delete Power VS Volume','Detected volume.delete on Power VS Volumes via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'volume.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.2471e2a9','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".network.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.2471e2a9','power_iaas','ibm',
  'high','IBM Power VS Networks: Create Power VS Network','Detected network.create on Power VS Networks via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'network.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.ccb95611','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".ssh-key.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.ccb95611','power_iaas','ibm',
  'high','IBM Power VS SSH Keys: Create Power VS SSH Key','Detected ssh-key.create on Power VS SSH Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'ssh-key.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.power_iaas.fe93e10c','power_iaas','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"power_iaas"},{"op":"contains","field":"operation","value":".image.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.power_iaas.fe93e10c','power_iaas','ibm',
  'high','IBM Power VS Images: Create Power VS Custom Image','Detected image.create on Power VS Images via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'image.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.vmwaresolutions.eb727e77','vmwaresolutions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"vmwaresolutions"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.vmwaresolutions.eb727e77','vmwaresolutions','ibm',
  'high','IBM VMware Instances: Create VMware Solutions Instance','Detected instance.create on VMware Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.vmwaresolutions.64d678d7','vmwaresolutions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"vmwaresolutions"},{"op":"contains","field":"operation","value":".instance.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.vmwaresolutions.64d678d7','vmwaresolutions','ibm',
  'medium','IBM VMware Instances: Update VMware Solutions Instance','Detected instance.update on VMware Instances via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'instance.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.vmwaresolutions.5388046a','vmwaresolutions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"vmwaresolutions"},{"op":"contains","field":"operation","value":".instance.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.vmwaresolutions.5388046a','vmwaresolutions','ibm',
  'high','IBM VMware Instances: Delete VMware Solutions Instance','Detected instance.delete on VMware Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.vmwaresolutions.4d1f4fce','vmwaresolutions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"vmwaresolutions"},{"op":"contains","field":"operation","value":".cluster.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.vmwaresolutions.4d1f4fce','vmwaresolutions','ibm',
  'high','IBM VMware Clusters: Create VMware Cluster','Detected cluster.create on VMware Clusters via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'cluster.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.vmwaresolutions.be344361','vmwaresolutions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"vmwaresolutions"},{"op":"contains","field":"operation","value":".cluster.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.vmwaresolutions.be344361','vmwaresolutions','ibm',
  'high','IBM VMware Clusters: Delete VMware Cluster','Detected cluster.delete on VMware Clusters via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'cluster.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_assistant.ff2e9c32','watson_assistant','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_assistant"},{"op":"contains","field":"operation","value":".environment.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_assistant.ff2e9c32','watson_assistant','ibm',
  'high','IBM WA Environments: Create Watson Assistant Environment','Detected environment.create on WA Environments via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'environment.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_assistant.8982a593','watson_assistant','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_assistant"},{"op":"contains","field":"operation","value":".environment.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_assistant.8982a593','watson_assistant','ibm',
  'high','IBM WA Environments: Delete Watson Assistant Environment','Detected environment.delete on WA Environments via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'environment.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_assistant.1b9a7585','watson_assistant','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_assistant"},{"op":"contains","field":"operation","value":".skill.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_assistant.1b9a7585','watson_assistant','ibm',
  'high','IBM WA Skills: Create Watson Assistant Skill','Detected skill.create on WA Skills via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'skill.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_discovery.b3fae584','watson_discovery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_discovery"},{"op":"contains","field":"operation","value":".project.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_discovery.b3fae584','watson_discovery','ibm',
  'high','IBM WD Projects: Create Watson Discovery Project','Detected project.create on WD Projects via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'project.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_discovery.e81faa7f','watson_discovery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_discovery"},{"op":"contains","field":"operation","value":".project.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_discovery.e81faa7f','watson_discovery','ibm',
  'high','IBM WD Projects: Delete Watson Discovery Project','Detected project.delete on WD Projects via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'project.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watson_discovery.54145122','watson_discovery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watson_discovery"},{"op":"contains","field":"operation","value":".collection.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watson_discovery.54145122','watson_discovery','ibm',
  'high','IBM WD Collections: Create Watson Discovery Collection','Detected collection.create on WD Collections via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'collection.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.natural_language_understanding.d5c822ea','natural_language_understanding','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"natural_language_understanding"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.natural_language_understanding.d5c822ea','natural_language_understanding','ibm',
  'high','IBM NLU Instances: Create NLU Instance','Detected instance.create on NLU Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watsonx_ai.74fd1a0e','watsonx_ai','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watsonx_ai"},{"op":"contains","field":"operation","value":".space.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watsonx_ai.74fd1a0e','watsonx_ai','ibm',
  'high','IBM Watsonx Spaces: Create Watsonx.ai Space','Detected space.create on Watsonx Spaces via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'space.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watsonx_ai.6c95b124','watsonx_ai','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watsonx_ai"},{"op":"contains","field":"operation","value":".space.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watsonx_ai.6c95b124','watsonx_ai','ibm',
  'high','IBM Watsonx Spaces: Delete Watsonx.ai Space','Detected space.delete on Watsonx Spaces via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'space.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watsonx_ai.f787ff7a','watsonx_ai','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watsonx_ai"},{"op":"contains","field":"operation","value":".deployment.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watsonx_ai.f787ff7a','watsonx_ai','ibm',
  'high','IBM Watsonx Deployments: Create Watsonx Model Deployment','Detected deployment.create on Watsonx Deployments via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watsonx_ai.0e457f3d','watsonx_ai','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watsonx_ai"},{"op":"contains","field":"operation","value":".deployment.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watsonx_ai.0e457f3d','watsonx_ai','ibm',
  'high','IBM Watsonx Deployments: Delete Watsonx Model Deployment','Detected deployment.delete on Watsonx Deployments via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.watsonx_data.3ea031b0','watsonx_data','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"watsonx_data"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.watsonx_data.3ea031b0','watsonx_data','ibm',
  'high','IBM Watsonx Data Instances: Create Watsonx.data Instance','Detected instance.create on Watsonx Data Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.d86aa91a','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".zone.add"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.d86aa91a','containers_kubernetes','ibm',
  'high','IBM IKS Zones: Add Zone to Worker Pool','Detected zone.add on IKS Zones via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'zone.add','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.c5d6b104','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".zone.remove"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.c5d6b104','containers_kubernetes','ibm',
  'high','IBM IKS Zones: Remove Zone from Worker Pool','Detected zone.remove on IKS Zones via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'zone.remove','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.973c95fd','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".policy.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.973c95fd','containers_kubernetes','ibm',
  'medium','IBM IKS Policies: Set IKS Security Policy','Detected policy.set on IKS Policies via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'policy.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.c1ee98dd','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".addon.enable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.c1ee98dd','containers_kubernetes','ibm',
  'high','IBM IKS Addons: Enable IKS Cluster Addon','Detected addon.enable on IKS Addons via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'addon.enable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.2db89f20','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".addon.disable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.2db89f20','containers_kubernetes','ibm',
  'high','IBM IKS Addons: Disable IKS Cluster Addon','Detected addon.disable on IKS Addons via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'addon.disable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.06ab2c07','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".apikey.reset"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.06ab2c07','containers_kubernetes','ibm',
  'medium','IBM IKS API Keys: Reset IKS API Key','Detected apikey.reset on IKS API Keys via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'apikey.reset','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.23ab5dc9','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".image.restore"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.23ab5dc9','container_registry','ibm',
  'medium','IBM Registry Images: Restore Container Image','Detected image.restore on Registry Images via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'image.restore','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.2a973243','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".quota.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.2a973243','container_registry','ibm',
  'medium','IBM Registry Quotas: Set Registry Quota','Detected quota.set on Registry Quotas via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'quota.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.8d71d12d','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".token.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.8d71d12d','container_registry','ibm',
  'high','IBM Registry Tokens: Create Registry Token','Detected token.create on Registry Tokens via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'token.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.9be9a900','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".token.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.9be9a900','container_registry','ibm',
  'high','IBM Registry Tokens: Delete Registry Token','Detected token.delete on Registry Tokens via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'token.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.d1205d33','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpn-gateway.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.d1205d33','is','ibm',
  'high','IBM VPC VPN Gateways: Create VPN Gateway','Detected vpn-gateway.create on VPC VPN Gateways via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'vpn-gateway.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.6b81e149','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpn-gateway.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.6b81e149','is','ibm',
  'high','IBM VPC VPN Gateways: Delete VPN Gateway','Detected vpn-gateway.delete on VPC VPN Gateways via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'vpn-gateway.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.4efc272a','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpn-connection.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.4efc272a','is','ibm',
  'high','IBM VPC VPN Connections: Create VPN Connection','Detected vpn-connection.create on VPC VPN Connections via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'vpn-connection.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.dadbb1e8','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpn-connection.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.dadbb1e8','is','ibm',
  'high','IBM VPC VPN Connections: Delete VPN Connection','Detected vpn-connection.delete on VPC VPN Connections via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'vpn-connection.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.45fe38d3','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".endpoint-gateway.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.45fe38d3','is','ibm',
  'high','IBM VPC Endpoint Gateways: Create VPC Endpoint Gateway','Detected endpoint-gateway.create on VPC Endpoint Gateways via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'endpoint-gateway.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.f74434eb','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".endpoint-gateway.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.f74434eb','is','ibm',
  'high','IBM VPC Endpoint Gateways: Delete VPC Endpoint Gateway','Detected endpoint-gateway.delete on VPC Endpoint Gateways via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'endpoint-gateway.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.825b295d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".flow-log-collector.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.825b295d','is','ibm',
  'high','IBM VPC Flow Logs: Create Flow Log Collector','Detected flow-log-collector.create on VPC Flow Logs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'flow-log-collector.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.aacc046f','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".flow-log-collector.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.aacc046f','is','ibm',
  'high','IBM VPC Flow Logs: Delete Flow Log Collector','Detected flow-log-collector.delete on VPC Flow Logs via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'flow-log-collector.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.cda0c713','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".share.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.cda0c713','is','ibm',
  'high','IBM VPC File Shares: Create File Share','Detected share.create on VPC File Shares via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'share.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.7ed2e746','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".share.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.7ed2e746','is','ibm',
  'high','IBM VPC File Shares: Delete File Share','Detected share.delete on VPC File Shares via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'share.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.2307ee57','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".placement-group.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.2307ee57','is','ibm',
  'high','IBM VPC Placement Groups: Create Instance Placement Group','Detected placement-group.create on VPC Placement Groups via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'placement-group.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.7a567e3a','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".bare-metal-server.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.7a567e3a','is','ibm',
  'high','IBM VPC Bare Metal Servers: Create Bare Metal Server','Detected bare-metal-server.create on VPC Bare Metal Servers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'bare-metal-server.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.018b9c3d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".bare-metal-server.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.018b9c3d','is','ibm',
  'high','IBM VPC Bare Metal Servers: Delete Bare Metal Server','Detected bare-metal-server.delete on VPC Bare Metal Servers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'bare-metal-server.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.7dc1d148','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".prefix-filter.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.7dc1d148','transit_gateway','ibm',
  'high','IBM TGW Prefix Filters: Create TGW Prefix Filter','Detected prefix-filter.create on TGW Prefix Filters via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'prefix-filter.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.273d03f2','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".prefix-filter.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.273d03f2','transit_gateway','ibm',
  'high','IBM TGW Prefix Filters: Delete TGW Prefix Filter','Detected prefix-filter.delete on TGW Prefix Filters via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'prefix-filter.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.f224d6aa','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".route-report.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.f224d6aa','transit_gateway','ibm',
  'high','IBM TGW Route Reports: Create TGW Route Report','Detected route-report.create on TGW Route Reports via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'route-report.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.ef8119dc','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".custom-resolver.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.ef8119dc','dns_svcs','ibm',
  'high','IBM DNS Custom Resolvers: Create Custom DNS Resolver','Detected custom-resolver.create on DNS Custom Resolvers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'custom-resolver.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.b1088b05','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".custom-resolver.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.b1088b05','dns_svcs','ibm',
  'high','IBM DNS Custom Resolvers: Delete Custom DNS Resolver','Detected custom-resolver.delete on DNS Custom Resolvers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'custom-resolver.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.45d86fb2','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".custom-resolver.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.45d86fb2','dns_svcs','ibm',
  'medium','IBM DNS Custom Resolvers: Update Custom DNS Resolver','Detected custom-resolver.update on DNS Custom Resolvers via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'custom-resolver.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.a38579d6','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".security-group-rule.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.a38579d6','is','ibm',
  'high','IBM VPC SG Rules: Create Security Group Rule','Detected security-group-rule.create on VPC SG Rules via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'security-group-rule.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.c3eb73c4','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".security-group-rule.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.c3eb73c4','is','ibm',
  'high','IBM VPC SG Rules: Delete Security Group Rule','Detected security-group-rule.delete on VPC SG Rules via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'security-group-rule.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.22b66b68','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".destination.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.22b66b68','event_notifications','ibm',
  'high','IBM EN Destinations: Create EN Destination','Detected destination.create on EN Destinations via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'destination.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.0328d2b4','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".destination.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.0328d2b4','event_notifications','ibm',
  'high','IBM EN Destinations: Delete EN Destination','Detected destination.delete on EN Destinations via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'destination.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.e369c28f','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".source.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.e369c28f','event_notifications','ibm',
  'high','IBM EN Sources: Create EN Source','Detected source.create on EN Sources via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'source.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.028b80d0','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".user.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.028b80d0','appid','ibm',
  'high','IBM App ID Users: Create App ID Cloud Directory User','Detected user.create on App ID Users via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'user.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.b0ea099f','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".user.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.b0ea099f','appid','ibm',
  'high','IBM App ID Users: Delete App ID Cloud Directory User','Detected user.delete on App ID Users via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'user.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.08f490ad','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".role.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.08f490ad','appid','ibm',
  'high','IBM App ID Roles: Create App ID Role','Detected role.create on App ID Roles via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'role.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.d189b6d1','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".role.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.d189b6d1','appid','ibm',
  'high','IBM App ID Roles: Delete App ID Role','Detected role.delete on App ID Roles via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'role.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.ca2596a3','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".blueprint.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.ca2596a3','schematics','ibm',
  'high','IBM Schematics Blueprints: Create Schematics Blueprint','Detected blueprint.create on Schematics Blueprints via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'blueprint.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.f7d5299f','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".blueprint.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.f7d5299f','schematics','ibm',
  'high','IBM Schematics Blueprints: Delete Schematics Blueprint','Detected blueprint.delete on Schematics Blueprints via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'blueprint.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.f16351a9','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".blueprint.apply"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.f16351a9','schematics','ibm',
  'medium','IBM Schematics Blueprints: Apply Schematics Blueprint','Detected blueprint.apply on Schematics Blueprints via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'blueprint.apply','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.074ae5e9','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-notification.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.074ae5e9','cloud_object_storage','ibm',
  'high','IBM COS Notifications: Create COS Bucket Notification','Detected bucket-notification.create on COS Notifications via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'bucket-notification.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.5b416d2e','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-key.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.5b416d2e','cloud_object_storage','ibm',
  'medium','IBM COS Encryption: Set COS Bucket Encryption Key','Detected bucket-key.set on COS Encryption via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket-key.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.574d1113','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-website.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.574d1113','cloud_object_storage','ibm',
  'medium','IBM COS Static Web: Set COS Bucket Static Website','Detected bucket-website.set on COS Static Web via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket-website.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.c47af4c8','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret-version.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.c47af4c8','secrets_manager','ibm',
  'high','IBM SM Secret Versions: Create Secret Version','Detected secret-version.create on SM Secret Versions via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secret-version.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.dc717d85','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".engine.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.dc717d85','secrets_manager','ibm',
  'medium','IBM SM Engine Config: Set Secrets Manager Engine Config','Detected engine.set on SM Engine Config via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'engine.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.1db91387','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".dashboard.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.1db91387','sysdig_monitor','ibm',
  'high','IBM Monitoring Dashboards: Create Monitoring Dashboard','Detected dashboard.create on Monitoring Dashboards via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'dashboard.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.b0977cd8','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".dashboard.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.b0977cd8','sysdig_monitor','ibm',
  'high','IBM Monitoring Dashboards: Delete Monitoring Dashboard','Detected dashboard.delete on Monitoring Dashboards via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'dashboard.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.1a1b1259','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".scope.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.1a1b1259','sysdig_monitor','ibm',
  'high','IBM Monitoring Scopes: Create Monitoring Scope','Detected scope.create on Monitoring Scopes via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'scope.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.6736eb53','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".scope.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.6736eb53','sysdig_monitor','ibm',
  'high','IBM Monitoring Scopes: Delete Monitoring Scope','Detected scope.delete on Monitoring Scopes via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'scope.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.5f8bddf4','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".tekton-pipeline-trigger.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.5f8bddf4','continuous_delivery','ibm',
  'high','IBM Tekton Triggers: Create Tekton Pipeline Trigger','Detected tekton-pipeline-trigger.create on Tekton Triggers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'tekton-pipeline-trigger.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.1c480380','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".tekton-pipeline-trigger.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.1c480380','continuous_delivery','ibm',
  'high','IBM Tekton Triggers: Delete Tekton Pipeline Trigger','Detected tekton-pipeline-trigger.delete on Tekton Triggers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'tekton-pipeline-trigger.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.toolchain.894aeaab','toolchain','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"toolchain"},{"op":"contains","field":"operation","value":".integration.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.toolchain.894aeaab','toolchain','ibm',
  'high','IBM Toolchain Integrations: Create Toolchain Integration','Detected integration.create on Toolchain Integrations via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'integration.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.toolchain.3aa0fa4c','toolchain','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"toolchain"},{"op":"contains","field":"operation","value":".integration.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.toolchain.3aa0fa4c','toolchain','ibm',
  'high','IBM Toolchain Integrations: Delete Toolchain Integration','Detected integration.delete on Toolchain Integrations via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'integration.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.b10f79cf','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".view.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.b10f79cf','logdna','ibm',
  'high','IBM Log Analysis Views: Create Log Analysis View','Detected view.create on Log Analysis Views via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'view.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.d36f32af','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".view.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.d36f32af','logdna','ibm',
  'high','IBM Log Analysis Views: Delete Log Analysis View','Detected view.delete on Log Analysis Views via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'view.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.452f4264','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".alert.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.452f4264','logdna','ibm',
  'high','IBM Log Analysis Alerts: Create Log Analysis Alert','Detected alert.create on Log Analysis Alerts via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'alert.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.3d1da36a','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".alert.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.3d1da36a','logdna','ibm',
  'high','IBM Log Analysis Alerts: Delete Log Analysis Alert','Detected alert.delete on Log Analysis Alerts via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'alert.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.4be73d56','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".settings.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.4be73d56','atracker','ibm',
  'medium','IBM ATracker Settings: Update Activity Tracker Settings','Detected settings.update on ATracker Settings via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'settings.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.context_based_restrictions.84bcd565','context_based_restrictions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"context_based_restrictions"},{"op":"contains","field":"operation","value":".account-settings.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.context_based_restrictions.84bcd565','context_based_restrictions','ibm',
  'medium','IBM CBR Account Settings: Update Account CBR Settings','Detected account-settings.update on CBR Account Settings via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'account-settings.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.f0f5c369','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".package.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.f0f5c369','functions','ibm',
  'high','IBM Functions Packages: Create Functions Package','Detected package.create on Functions Packages via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'package.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.dc34a0b0','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".package.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.dc34a0b0','functions','ibm',
  'high','IBM Functions Packages: Delete Functions Package','Detected package.delete on Functions Packages via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'package.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.5e58e636','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".trigger.fire"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.5e58e636','functions','ibm',
  'medium','IBM Functions Trigger Fires: Fire Function Trigger','Detected trigger.fire on Functions Trigger Fires via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'trigger.fire','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

