-- IBM CRUD expansion rules
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.user_management.3c161973','user_management','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"user_management"},{"op":"contains","field":"operation","value":".user.invite"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.user_management.3c161973','user_management','ibm',
  'medium','IBM Account Users: Invite User to Account','Detected user.invite operation on Account Users via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'user.invite','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.user_management.1bd666d1','user_management','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"user_management"},{"op":"contains","field":"operation","value":".user.remove"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.user_management.1bd666d1','user_management','ibm',
  'high','IBM Account Users: Remove User from Account','Detected user.remove operation on Account Users via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'user.remove','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.user_management.30169c1a','user_management','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"user_management"},{"op":"contains","field":"operation","value":".user.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.user_management.30169c1a','user_management','ibm',
  'medium','IBM Account Users: Update User Settings','Detected user.update operation on Account Users via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'user.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.a688de0b','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".account.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.a688de0b','iam_identity','ibm',
  'medium','IBM Account Settings: Update Account Settings','Detected account.update operation on Account Settings via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'account.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.f4dc1f6b','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.f4dc1f6b','iam_groups','ibm',
  'high','IBM Access Groups: Create Access Group','Detected access-group.create operation on Access Groups via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'access-group.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.81b0389d','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.81b0389d','iam_groups','ibm',
  'high','IBM Access Groups: Delete Access Group','Detected access-group.delete operation on Access Groups via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'access-group.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.9a7b26e4','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.9a7b26e4','iam_groups','ibm',
  'medium','IBM Access Groups: Update Access Group','Detected access-group.update operation on Access Groups via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'access-group.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.72e5d4bf','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group-members.add"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.72e5d4bf','iam_groups','ibm',
  'high','IBM Access Group Members: Add Member to Access Group','Detected access-group-members.add operation on Access Group Members via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'access-group-members.add','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.b8220b47','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group-members.remove"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.b8220b47','iam_groups','ibm',
  'high','IBM Access Group Members: Remove Member from Access Group','Detected access-group-members.remove operation on Access Group Members via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'access-group-members.remove','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.13e2cdda','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group-policy.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.13e2cdda','iam_groups','ibm',
  'high','IBM Access Group Policies: Create Access Group Policy','Detected access-group-policy.create operation on Access Group Policies via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'access-group-policy.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_groups.219b1d4d','iam_groups','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_groups"},{"op":"contains","field":"operation","value":".access-group-policy.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_groups.219b1d4d','iam_groups','ibm',
  'high','IBM Access Group Policies: Delete Access Group Policy','Detected access-group-policy.delete operation on Access Group Policies via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'access-group-policy.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam.96eb8858','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":".policy.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam.96eb8858','iam','ibm',
  'high','IBM IAM Policies: Create IAM Policy','Detected policy.create operation on IAM Policies via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'policy.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam.6024ea02','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":".policy.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam.6024ea02','iam','ibm',
  'medium','IBM IAM Policies: Update IAM Policy','Detected policy.update operation on IAM Policies via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'policy.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam.33ef790c','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":".policy.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam.33ef790c','iam','ibm',
  'high','IBM IAM Policies: Delete IAM Policy','Detected policy.delete operation on IAM Policies via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'policy.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam.8ded628c','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":".authorization.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam.8ded628c','iam','ibm',
  'medium','IBM Service Authorizations: Update Service Authorization','Detected authorization.update operation on Service Authorizations via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'authorization.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam.e9488493','iam','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam"},{"op":"contains","field":"operation","value":".authorization.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam.e9488493','iam','ibm',
  'high','IBM Service Authorizations: Delete Service Authorization','Detected authorization.delete operation on Service Authorizations via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'authorization.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.5b27a15a','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".apikey.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.5b27a15a','iam_identity','ibm',
  'high','IBM API Keys: Create API Key','Detected apikey.create operation on API Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'apikey.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.4bba884c','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".apikey.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.4bba884c','iam_identity','ibm',
  'high','IBM API Keys: Delete API Key','Detected apikey.delete operation on API Keys via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'apikey.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.b51c9f6f','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".apikey.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.b51c9f6f','iam_identity','ibm',
  'medium','IBM API Keys: Update API Key','Detected apikey.update operation on API Keys via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'apikey.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.499068f7','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".serviceid.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.499068f7','iam_identity','ibm',
  'high','IBM Service IDs: Create Service ID','Detected serviceid.create operation on Service IDs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'serviceid.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.ab72530e','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".serviceid.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.ab72530e','iam_identity','ibm',
  'high','IBM Service IDs: Delete Service ID','Detected serviceid.delete operation on Service IDs via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'serviceid.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.1aeea124','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".serviceid.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.1aeea124','iam_identity','ibm',
  'medium','IBM Service IDs: Update Service ID','Detected serviceid.update operation on Service IDs via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'serviceid.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.853f6ec6','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".profile.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.853f6ec6','iam_identity','ibm',
  'high','IBM Trusted Profiles: Create Trusted Profile','Detected profile.create operation on Trusted Profiles via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'profile.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.40c0b710','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".profile.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.40c0b710','iam_identity','ibm',
  'high','IBM Trusted Profiles: Delete Trusted Profile','Detected profile.delete operation on Trusted Profiles via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'profile.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.iam_identity.17ee4e6f','iam_identity','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"iam_identity"},{"op":"contains","field":"operation","value":".profile.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.iam_identity.17ee4e6f','iam_identity','ibm',
  'medium','IBM Trusted Profiles: Update Trusted Profile','Detected profile.update operation on Trusted Profiles via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'profile.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.context_based_restrictions.3461ac38','context_based_restrictions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"context_based_restrictions"},{"op":"contains","field":"operation","value":".rule.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.context_based_restrictions.3461ac38','context_based_restrictions','ibm',
  'high','IBM CBR Rules: Create CBR Rule','Detected rule.create operation on CBR Rules via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'rule.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.context_based_restrictions.0631ebb2','context_based_restrictions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"context_based_restrictions"},{"op":"contains","field":"operation","value":".rule.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.context_based_restrictions.0631ebb2','context_based_restrictions','ibm',
  'medium','IBM CBR Rules: Update CBR Rule','Detected rule.update operation on CBR Rules via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'rule.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.context_based_restrictions.bdaccf4a','context_based_restrictions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"context_based_restrictions"},{"op":"contains","field":"operation","value":".zone.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.context_based_restrictions.bdaccf4a','context_based_restrictions','ibm',
  'high','IBM CBR Zones: Create CBR Zone','Detected zone.create operation on CBR Zones via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'zone.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.context_based_restrictions.700b9062','context_based_restrictions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"context_based_restrictions"},{"op":"contains","field":"operation","value":".zone.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.context_based_restrictions.700b9062','context_based_restrictions','ibm',
  'medium','IBM CBR Zones: Update CBR Zone','Detected zone.update operation on CBR Zones via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'zone.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.3d3dd983','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.3d3dd983','resource_controller','ibm',
  'high','IBM Service Instances: Create Service Instance','Detected instance.create operation on Service Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.7faa5410','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".instance.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.7faa5410','resource_controller','ibm',
  'medium','IBM Service Instances: Update Service Instance','Detected instance.update operation on Service Instances via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'instance.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.6fab7afe','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".instance.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.6fab7afe','resource_controller','ibm',
  'high','IBM Service Instances: Delete Service Instance','Detected instance.delete operation on Service Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.38bded8b','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".binding.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.38bded8b','resource_controller','ibm',
  'high','IBM Service Bindings: Create Service Binding','Detected binding.create operation on Service Bindings via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'binding.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.dfd1995c','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".binding.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.dfd1995c','resource_controller','ibm',
  'high','IBM Service Bindings: Delete Service Binding','Detected binding.delete operation on Service Bindings via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'binding.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.d2412873','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".key.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.d2412873','resource_controller','ibm',
  'high','IBM Service Credentials: Create Service Credential','Detected key.create operation on Service Credentials via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'key.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.0470bd75','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".key.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.0470bd75','resource_controller','ibm',
  'high','IBM Service Credentials: Delete Service Credential','Detected key.delete operation on Service Credentials via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'key.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.resource_controller.684c7430','resource_controller','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"resource_controller"},{"op":"contains","field":"operation","value":".key.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.resource_controller.684c7430','resource_controller','ibm',
  'medium','IBM Service Credentials: Update Service Credential','Detected key.update operation on Service Credentials via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'key.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.a88bc918','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.a88bc918','cloud_object_storage','ibm',
  'high','IBM COS Buckets: Create COS Bucket','Detected bucket.create operation on COS Buckets via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'bucket.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.45d497b1','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.45d497b1','cloud_object_storage','ibm',
  'high','IBM COS Buckets: Delete COS Bucket','Detected bucket.delete operation on COS Buckets via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'bucket.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.9026bc95','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.9026bc95','cloud_object_storage','ibm',
  'medium','IBM COS Buckets: Update COS Bucket','Detected bucket.update operation on COS Buckets via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.ef66b68b','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".object.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.ef66b68b','cloud_object_storage','ibm',
  'high','IBM COS Objects: Delete Object from COS Bucket','Detected object.delete operation on COS Objects via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'object.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.52e717a5','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-cors.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.52e717a5','cloud_object_storage','ibm',
  'medium','IBM COS Bucket CORS: Set COS Bucket CORS Policy','Detected bucket-cors.set operation on COS Bucket CORS via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket-cors.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.395c5548','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-versioning.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.395c5548','cloud_object_storage','ibm',
  'medium','IBM COS Bucket Versioning: Set COS Bucket Versioning','Detected bucket-versioning.set operation on COS Bucket Versioning via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket-versioning.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloud_object_storage.693092a9','cloud_object_storage','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloud_object_storage"},{"op":"contains","field":"operation","value":".bucket-retention.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloud_object_storage.693092a9','cloud_object_storage','ibm',
  'medium','IBM COS Bucket Retention: Set COS Bucket Retention Policy','Detected bucket-retention.set operation on COS Bucket Retention via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'bucket-retention.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.490776f6','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".secrets.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.490776f6','kms','ibm',
  'high','IBM Key Protect Keys: Create Encryption Key','Detected secrets.create operation on Key Protect Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secrets.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.e5791751','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".secrets.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.e5791751','kms','ibm',
  'high','IBM Key Protect Keys: Delete Encryption Key','Detected secrets.delete operation on Key Protect Keys via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'secrets.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.79f3ad90','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".secrets.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.79f3ad90','kms','ibm',
  'medium','IBM Key Protect Keys: Update Key Metadata','Detected secrets.update operation on Key Protect Keys via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'secrets.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.c761bcf8','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".secrets.enable"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.c761bcf8','kms','ibm',
  'high','IBM Key Protect Keys: Enable Encryption Key','Detected secrets.enable operation on Key Protect Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secrets.enable','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.c938292a','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".secrets.purge"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.c938292a','kms','ibm',
  'high','IBM Key Protect Keys: Purge Encryption Key','Detected secrets.purge operation on Key Protect Keys via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'secrets.purge','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.065bc839','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".keyrings.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.065bc839','kms','ibm',
  'high','IBM Key Protect Key Rings: Create Key Ring','Detected keyrings.create operation on Key Protect Key Rings via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'keyrings.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.2c34bd34','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".keyrings.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.2c34bd34','kms','ibm',
  'high','IBM Key Protect Key Rings: Delete Key Ring','Detected keyrings.delete operation on Key Protect Key Rings via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'keyrings.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.63daf432','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".registrations.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.63daf432','kms','ibm',
  'high','IBM Key Protect Registrations: Create Key Registration','Detected registrations.create operation on Key Protect Registrations via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'registrations.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.kms.f445ce84','kms','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"kms"},{"op":"contains","field":"operation","value":".registrations.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.kms.f445ce84','kms','ibm',
  'high','IBM Key Protect Registrations: Delete Key Registration','Detected registrations.delete operation on Key Protect Registrations via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'registrations.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.hs_crypto.3eab71fd','hs_crypto','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"hs_crypto"},{"op":"contains","field":"operation","value":".keys.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.hs_crypto.3eab71fd','hs_crypto','ibm',
  'high','IBM Hyper Protect Keys: Create Key in HPCS','Detected keys.create operation on Hyper Protect Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'keys.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.hs_crypto.11b96334','hs_crypto','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"hs_crypto"},{"op":"contains","field":"operation","value":".keys.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.hs_crypto.11b96334','hs_crypto','ibm',
  'high','IBM Hyper Protect Keys: Delete Key in HPCS','Detected keys.delete operation on Hyper Protect Keys via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'keys.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.hs_crypto.62a47d6f','hs_crypto','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"hs_crypto"},{"op":"contains","field":"operation","value":".keys.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.hs_crypto.62a47d6f','hs_crypto','ibm',
  'medium','IBM Hyper Protect Keys: Update Key in HPCS','Detected keys.update operation on Hyper Protect Keys via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'keys.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.hs_crypto.00358b1e','hs_crypto','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"hs_crypto"},{"op":"contains","field":"operation","value":".instances.initialize"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.hs_crypto.00358b1e','hs_crypto','ibm',
  'medium','IBM HPCS Instances: Initialize HPCS Instance','Detected instances.initialize operation on HPCS Instances via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'instances.initialize','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.009e2143','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.009e2143','secrets_manager','ibm',
  'high','IBM Secrets Manager Secrets: Create Secret','Detected secret.create operation on Secrets Manager Secrets via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secret.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.411907f7','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.411907f7','secrets_manager','ibm',
  'medium','IBM Secrets Manager Secrets: Update Secret Metadata','Detected secret.update operation on Secrets Manager Secrets via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'secret.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.b3a8987e','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.b3a8987e','secrets_manager','ibm',
  'high','IBM Secrets Manager Secrets: Delete Secret','Detected secret.delete operation on Secrets Manager Secrets via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'secret.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.e8193abb','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret-group.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.e8193abb','secrets_manager','ibm',
  'high','IBM Secrets Manager Groups: Create Secret Group','Detected secret-group.create operation on Secrets Manager Groups via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secret-group.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.34e3a552','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".secret-group.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.34e3a552','secrets_manager','ibm',
  'high','IBM Secrets Manager Groups: Delete Secret Group','Detected secret-group.delete operation on Secrets Manager Groups via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'secret-group.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.a9a0f967','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".configuration.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.a9a0f967','secrets_manager','ibm',
  'high','IBM Secrets Manager Config: Create Secrets Config','Detected configuration.create operation on Secrets Manager Config via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'configuration.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.secrets_manager.b367ca98','secrets_manager','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"secrets_manager"},{"op":"contains","field":"operation","value":".configuration.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.secrets_manager.b367ca98','secrets_manager','ibm',
  'high','IBM Secrets Manager Config: Delete Secrets Config','Detected configuration.delete operation on Secrets Manager Config via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'configuration.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.d59c39a5','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.d59c39a5','is','ibm',
  'high','IBM VPC Instances: Create VPC Instance','Detected instance.create operation on VPC Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.43eb00d3','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".instance.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.43eb00d3','is','ibm',
  'medium','IBM VPC Instances: Update VPC Instance','Detected instance.update operation on VPC Instances via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'instance.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.73896ff7','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".instance.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.73896ff7','is','ibm',
  'high','IBM VPC Instances: Delete VPC Instance','Detected instance.delete operation on VPC Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.f1e88793','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".subnet.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.f1e88793','is','ibm',
  'high','IBM VPC Subnets: Create VPC Subnet','Detected subnet.create operation on VPC Subnets via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'subnet.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.4d9c4699','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".subnet.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.4d9c4699','is','ibm',
  'medium','IBM VPC Subnets: Update VPC Subnet','Detected subnet.update operation on VPC Subnets via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'subnet.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.2c7be03d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".subnet.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.2c7be03d','is','ibm',
  'high','IBM VPC Subnets: Delete VPC Subnet','Detected subnet.delete operation on VPC Subnets via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'subnet.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.87d78419','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpc.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.87d78419','is','ibm',
  'high','IBM VPCs: Create VPC','Detected vpc.create operation on VPCs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'vpc.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.45a07970','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpc.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.45a07970','is','ibm',
  'medium','IBM VPCs: Update VPC','Detected vpc.update operation on VPCs via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'vpc.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.fe3573c5','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpc.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.fe3573c5','is','ibm',
  'high','IBM VPCs: Delete VPC','Detected vpc.delete operation on VPCs via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'vpc.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.c8580d47','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".security-group.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.c8580d47','is','ibm',
  'high','IBM VPC Security Groups: Create Security Group','Detected security-group.create operation on VPC Security Groups via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'security-group.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.5d3c3611','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".security-group.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.5d3c3611','is','ibm',
  'medium','IBM VPC Security Groups: Update Security Group','Detected security-group.update operation on VPC Security Groups via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'security-group.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.239b1993','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".security-group.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.239b1993','is','ibm',
  'high','IBM VPC Security Groups: Delete Security Group','Detected security-group.delete operation on VPC Security Groups via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'security-group.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.2af80105','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".network-acl.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.2af80105','is','ibm',
  'high','IBM VPC Network ACLs: Create Network ACL','Detected network-acl.create operation on VPC Network ACLs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'network-acl.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.a20cf821','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".network-acl.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.a20cf821','is','ibm',
  'medium','IBM VPC Network ACLs: Update Network ACL','Detected network-acl.update operation on VPC Network ACLs via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'network-acl.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.ffaf0dce','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".network-acl.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.ffaf0dce','is','ibm',
  'high','IBM VPC Network ACLs: Delete Network ACL','Detected network-acl.delete operation on VPC Network ACLs via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'network-acl.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.a09b3db0','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".public-gateway.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.a09b3db0','is','ibm',
  'high','IBM VPC Public Gateways: Create Public Gateway','Detected public-gateway.create operation on VPC Public Gateways via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'public-gateway.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.88a4c55d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".public-gateway.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.88a4c55d','is','ibm',
  'high','IBM VPC Public Gateways: Delete Public Gateway','Detected public-gateway.delete operation on VPC Public Gateways via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'public-gateway.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.0fa5db01','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".volume.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.0fa5db01','is','ibm',
  'high','IBM VPC Block Volumes: Create VPC Block Volume','Detected volume.create operation on VPC Block Volumes via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'volume.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.d0b63b83','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".volume.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.d0b63b83','is','ibm',
  'medium','IBM VPC Block Volumes: Update VPC Block Volume','Detected volume.update operation on VPC Block Volumes via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'volume.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.62f78dec','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".volume.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.62f78dec','is','ibm',
  'high','IBM VPC Block Volumes: Delete VPC Block Volume','Detected volume.delete operation on VPC Block Volumes via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'volume.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.63ca49d9','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".load-balancer.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.63ca49d9','is','ibm',
  'high','IBM VPC Load Balancers: Create VPC Load Balancer','Detected load-balancer.create operation on VPC Load Balancers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'load-balancer.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.06bace91','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".load-balancer.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.06bace91','is','ibm',
  'medium','IBM VPC Load Balancers: Update VPC Load Balancer','Detected load-balancer.update operation on VPC Load Balancers via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'load-balancer.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.72fdf79d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".load-balancer.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.72fdf79d','is','ibm',
  'high','IBM VPC Load Balancers: Delete VPC Load Balancer','Detected load-balancer.delete operation on VPC Load Balancers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'load-balancer.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.d1205d33','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".vpn-gateway.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.d1205d33','is','ibm',
  'high','IBM VPC VPN Gateways: Create VPN Gateway','Detected vpn-gateway.create operation on VPC VPN Gateways via IBM Activity Tracker.',
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
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.6b81e149','is','ibm',
  'high','IBM VPC VPN Gateways: Delete VPN Gateway','Detected vpn-gateway.delete operation on VPC VPN Gateways via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'vpn-gateway.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.d64e23ea','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".dedicated-host.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.d64e23ea','is','ibm',
  'high','IBM VPC Dedicated Hosts: Create Dedicated Host','Detected dedicated-host.create operation on VPC Dedicated Hosts via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'dedicated-host.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.32e0ad7d','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".dedicated-host.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.32e0ad7d','is','ibm',
  'high','IBM VPC Dedicated Hosts: Delete Dedicated Host','Detected dedicated-host.delete operation on VPC Dedicated Hosts via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'dedicated-host.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.8771b700','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".image.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.8771b700','is','ibm',
  'high','IBM VPC Custom Images: Create Custom Image','Detected image.create operation on VPC Custom Images via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'image.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.b7931e85','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".image.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.b7931e85','is','ibm',
  'high','IBM VPC Custom Images: Delete Custom Image','Detected image.delete operation on VPC Custom Images via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'image.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.is.ed7437ba','is','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"is"},{"op":"contains","field":"operation","value":".instance-template.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.is.ed7437ba','is','ibm',
  'high','IBM VPC Instance Templates: Create Instance Template','Detected instance-template.create operation on VPC Instance Templates via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance-template.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.47e6496f','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".cluster.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.47e6496f','containers_kubernetes','ibm',
  'high','IBM IKS Clusters: Create Kubernetes Cluster','Detected cluster.create operation on IKS Clusters via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'cluster.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.9aff721c','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".cluster.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.9aff721c','containers_kubernetes','ibm',
  'medium','IBM IKS Clusters: Update Kubernetes Cluster','Detected cluster.update operation on IKS Clusters via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'cluster.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.6ad0f441','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".cluster.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.6ad0f441','containers_kubernetes','ibm',
  'high','IBM IKS Clusters: Delete Kubernetes Cluster','Detected cluster.delete operation on IKS Clusters via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'cluster.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.ef51bb40','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".worker.add"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.ef51bb40','containers_kubernetes','ibm',
  'high','IBM IKS Workers: Add Worker Node','Detected worker.add operation on IKS Workers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'worker.add','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.eaadf59f','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".worker.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.eaadf59f','containers_kubernetes','ibm',
  'high','IBM IKS Workers: Delete Worker Node','Detected worker.delete operation on IKS Workers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'worker.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.661fe9cf','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".worker-pool.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.661fe9cf','containers_kubernetes','ibm',
  'high','IBM IKS Worker Pools: Create Worker Pool','Detected worker-pool.create operation on IKS Worker Pools via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'worker-pool.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.1a67071f','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".worker-pool.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.1a67071f','containers_kubernetes','ibm',
  'high','IBM IKS Worker Pools: Delete Worker Pool','Detected worker-pool.delete operation on IKS Worker Pools via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'worker-pool.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.c2b983f0','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".nlb.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.c2b983f0','containers_kubernetes','ibm',
  'high','IBM IKS NLBs: Create NLB for IKS','Detected nlb.create operation on IKS NLBs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'nlb.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.14cf86ba','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".alb.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.14cf86ba','containers_kubernetes','ibm',
  'high','IBM IKS ALBs: Create ALB for IKS','Detected alb.create operation on IKS ALBs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'alb.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.containers_kubernetes.fef58f96','containers_kubernetes','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"containers_kubernetes"},{"op":"contains","field":"operation","value":".ingress.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.containers_kubernetes.fef58f96','containers_kubernetes','ibm',
  'medium','IBM IKS Ingress: Update Ingress for IKS','Detected ingress.update operation on IKS Ingress via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'ingress.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.11cc1705','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".namespace.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.11cc1705','container_registry','ibm',
  'high','IBM Registry Namespaces: Create Container Registry Namespace','Detected namespace.create operation on Registry Namespaces via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'namespace.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.9c970800','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".namespace.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.9c970800','container_registry','ibm',
  'high','IBM Registry Namespaces: Delete Container Registry Namespace','Detected namespace.delete operation on Registry Namespaces via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'namespace.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.f0ae7d61','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".image.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.f0ae7d61','container_registry','ibm',
  'high','IBM Registry Images: Delete Container Image','Detected image.delete operation on Registry Images via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'image.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.cd30f50c','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".retention-policy.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.cd30f50c','container_registry','ibm',
  'medium','IBM Registry Retention: Set Image Retention Policy','Detected retention-policy.set operation on Registry Retention via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'retention-policy.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.container_registry.6361ef4e','container_registry','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"container_registry"},{"op":"contains","field":"operation","value":".auth.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.container_registry.6361ef4e','container_registry','ibm',
  'medium','IBM Registry Auth: Update Registry Authentication Settings','Detected auth.set operation on Registry Auth via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'auth.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.5335dfbf','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".application.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.5335dfbf','codeengine','ibm',
  'high','IBM Code Engine Apps: Create Code Engine Application','Detected application.create operation on Code Engine Apps via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'application.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.abcd187a','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".application.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.abcd187a','codeengine','ibm',
  'medium','IBM Code Engine Apps: Update Code Engine Application','Detected application.update operation on Code Engine Apps via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'application.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.8b44527a','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".application.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.8b44527a','codeengine','ibm',
  'high','IBM Code Engine Apps: Delete Code Engine Application','Detected application.delete operation on Code Engine Apps via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'application.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.13f72c7d','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".job.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.13f72c7d','codeengine','ibm',
  'high','IBM Code Engine Jobs: Create Code Engine Job','Detected job.create operation on Code Engine Jobs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'job.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.618dcdfb','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".job.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.618dcdfb','codeengine','ibm',
  'high','IBM Code Engine Jobs: Delete Code Engine Job','Detected job.delete operation on Code Engine Jobs via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'job.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.b6c10510','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".project.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.b6c10510','codeengine','ibm',
  'high','IBM Code Engine Projects: Create Code Engine Project','Detected project.create operation on Code Engine Projects via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'project.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.29426a40','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".project.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.29426a40','codeengine','ibm',
  'high','IBM Code Engine Projects: Delete Code Engine Project','Detected project.delete operation on Code Engine Projects via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'project.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.c2154df1','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".configmap.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.c2154df1','codeengine','ibm',
  'high','IBM Code Engine ConfigMaps: Create Code Engine ConfigMap','Detected configmap.create operation on Code Engine ConfigMaps via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'configmap.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.1138c374','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".secret.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.1138c374','codeengine','ibm',
  'high','IBM Code Engine Secrets: Create Code Engine Secret','Detected secret.create operation on Code Engine Secrets via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'secret.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.codeengine.a8a43073','codeengine','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"codeengine"},{"op":"contains","field":"operation","value":".secret.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.codeengine.a8a43073','codeengine','ibm',
  'high','IBM Code Engine Secrets: Delete Code Engine Secret','Detected secret.delete operation on Code Engine Secrets via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'secret.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_postgresql.eb258474','databases_for_postgresql','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_postgresql"},{"op":"contains","field":"operation","value":".deployment.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_postgresql.eb258474','databases_for_postgresql','ibm',
  'high','IBM PostgreSQL Instances: Create Databases for PostgreSQL Instance','Detected deployment.create operation on PostgreSQL Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_postgresql.a00b7495','databases_for_postgresql','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_postgresql"},{"op":"contains","field":"operation","value":".deployment.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_postgresql.a00b7495','databases_for_postgresql','ibm',
  'high','IBM PostgreSQL Instances: Delete Databases for PostgreSQL Instance','Detected deployment.delete operation on PostgreSQL Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_postgresql.e9c321f6','databases_for_postgresql','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_postgresql"},{"op":"contains","field":"operation","value":".user.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_postgresql.e9c321f6','databases_for_postgresql','ibm',
  'high','IBM PostgreSQL Users: Create PostgreSQL User','Detected user.create operation on PostgreSQL Users via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'user.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_postgresql.4a0f2f58','databases_for_postgresql','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_postgresql"},{"op":"contains","field":"operation","value":".user.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_postgresql.4a0f2f58','databases_for_postgresql','ibm',
  'high','IBM PostgreSQL Users: Delete PostgreSQL User','Detected user.delete operation on PostgreSQL Users via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'user.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_postgresql.8bccacef','databases_for_postgresql','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_postgresql"},{"op":"contains","field":"operation","value":".whitelist.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_postgresql.8bccacef','databases_for_postgresql','ibm',
  'medium','IBM PostgreSQL Allowlist: Update PostgreSQL Allowlist','Detected whitelist.update operation on PostgreSQL Allowlist via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'whitelist.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_mongodb.d01c2e5b','databases_for_mongodb','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_mongodb"},{"op":"contains","field":"operation","value":".deployment.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_mongodb.d01c2e5b','databases_for_mongodb','ibm',
  'high','IBM MongoDB Instances: Create Databases for MongoDB Instance','Detected deployment.create operation on MongoDB Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_mongodb.d58db59a','databases_for_mongodb','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_mongodb"},{"op":"contains","field":"operation","value":".deployment.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_mongodb.d58db59a','databases_for_mongodb','ibm',
  'high','IBM MongoDB Instances: Delete Databases for MongoDB Instance','Detected deployment.delete operation on MongoDB Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_redis.4aff68b8','databases_for_redis','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_redis"},{"op":"contains","field":"operation","value":".deployment.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_redis.4aff68b8','databases_for_redis','ibm',
  'high','IBM Redis Instances: Create Databases for Redis Instance','Detected deployment.create operation on Redis Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.databases_for_redis.78c355f7','databases_for_redis','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"databases_for_redis"},{"op":"contains","field":"operation","value":".deployment.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.databases_for_redis.78c355f7','databases_for_redis','ibm',
  'high','IBM Redis Instances: Delete Databases for Redis Instance','Detected deployment.delete operation on Redis Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'deployment.delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloudantnosqldb.9e6385e0','cloudantnosqldb','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloudantnosqldb"},{"op":"contains","field":"operation","value":".cluster.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloudantnosqldb.9e6385e0','cloudantnosqldb','ibm',
  'high','IBM Cloudant Instances: Create Cloudant Database Instance','Detected cluster.create operation on Cloudant Instances via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'cluster.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloudantnosqldb.4a36bf87','cloudantnosqldb','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloudantnosqldb"},{"op":"contains","field":"operation","value":".cluster.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloudantnosqldb.4a36bf87','cloudantnosqldb','ibm',
  'high','IBM Cloudant Instances: Delete Cloudant Database Instance','Detected cluster.delete operation on Cloudant Instances via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'cluster.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.cloudantnosqldb.b1ac0f60','cloudantnosqldb','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"cloudantnosqldb"},{"op":"contains","field":"operation","value":".db.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.cloudantnosqldb.b1ac0f60','cloudantnosqldb','ibm',
  'high','IBM Cloudant Databases: Create Cloudant Database','Detected db.create operation on Cloudant Databases via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'db.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.bcbec720','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".instance.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.bcbec720','event_notifications','ibm',
  'high','IBM Event Notifications: Create Event Notifications Instance','Detected instance.create operation on Event Notifications via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'instance.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.f3ecc352','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".instance.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.f3ecc352','event_notifications','ibm',
  'high','IBM Event Notifications: Delete Event Notifications Instance','Detected instance.delete operation on Event Notifications via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'instance.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.0622dd3f','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".topic.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.0622dd3f','event_notifications','ibm',
  'high','IBM EN Topics: Create Event Notifications Topic','Detected topic.create operation on EN Topics via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'topic.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.6c093304','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".topic.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.6c093304','event_notifications','ibm',
  'high','IBM EN Topics: Delete Event Notifications Topic','Detected topic.delete operation on EN Topics via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'topic.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.bc9063bd','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".subscription.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.bc9063bd','event_notifications','ibm',
  'high','IBM EN Subscriptions: Create Event Notifications Subscription','Detected subscription.create operation on EN Subscriptions via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'subscription.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.event_notifications.6d6d7ae7','event_notifications','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"event_notifications"},{"op":"contains","field":"operation","value":".subscription.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.event_notifications.6d6d7ae7','event_notifications','ibm',
  'high','IBM EN Subscriptions: Delete Event Notifications Subscription','Detected subscription.delete operation on EN Subscriptions via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'subscription.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.79478e99','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".target.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.79478e99','atracker','ibm',
  'high','IBM ATracker Targets: Create Activity Tracker Target','Detected target.create operation on ATracker Targets via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'target.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.d92dc925','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".target.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.d92dc925','atracker','ibm',
  'medium','IBM ATracker Targets: Update Activity Tracker Target','Detected target.update operation on ATracker Targets via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'target.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.d64f9f4d','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".target.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.d64f9f4d','atracker','ibm',
  'high','IBM ATracker Targets: Delete Activity Tracker Target','Detected target.delete operation on ATracker Targets via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'target.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.d65f218f','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".route.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.d65f218f','atracker','ibm',
  'high','IBM ATracker Routes: Create Activity Tracker Route','Detected route.create operation on ATracker Routes via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'route.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.ea4ca323','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".route.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.ea4ca323','atracker','ibm',
  'medium','IBM ATracker Routes: Update Activity Tracker Route','Detected route.update operation on ATracker Routes via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'route.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.atracker.56458eb5','atracker','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"atracker"},{"op":"contains","field":"operation","value":".route.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.atracker.56458eb5','atracker','ibm',
  'high','IBM ATracker Routes: Delete Activity Tracker Route','Detected route.delete operation on ATracker Routes via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'route.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.0f351dae','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".workspace.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.0f351dae','schematics','ibm',
  'high','IBM Schematics Workspaces: Create Schematics Workspace','Detected workspace.create operation on Schematics Workspaces via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'workspace.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.7ab3757e','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".workspace.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.7ab3757e','schematics','ibm',
  'medium','IBM Schematics Workspaces: Update Schematics Workspace','Detected workspace.update operation on Schematics Workspaces via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'workspace.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.358d492e','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".workspace.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.358d492e','schematics','ibm',
  'high','IBM Schematics Workspaces: Delete Schematics Workspace','Detected workspace.delete operation on Schematics Workspaces via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'workspace.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.c4e057c4','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".workspace-action.apply"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.c4e057c4','schematics','ibm',
  'medium','IBM Schematics Actions: Apply Schematics Workspace (Terraform Apply)','Detected workspace-action.apply operation on Schematics Actions via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'workspace-action.apply','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.c9547e48','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".workspace-action.destroy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.c9547e48','schematics','ibm',
  'high','IBM Schematics Actions: Destroy Schematics Workspace (Terraform Destroy)','Detected workspace-action.destroy operation on Schematics Actions via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'workspace-action.destroy','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.a960677b','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".action.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.a960677b','schematics','ibm',
  'high','IBM Schematics Ansible Actions: Create Schematics Action (Ansible)','Detected action.create operation on Schematics Ansible Actions via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'action.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.schematics.a8e8fdb8','schematics','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"schematics"},{"op":"contains","field":"operation","value":".action.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.schematics.a8e8fdb8','schematics','ibm',
  'high','IBM Schematics Ansible Actions: Delete Schematics Action','Detected action.delete operation on Schematics Ansible Actions via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'action.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.a3835c94','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".gateway.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.a3835c94','transit_gateway','ibm',
  'high','IBM Transit Gateways: Create Transit Gateway','Detected gateway.create operation on Transit Gateways via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'gateway.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.3cd6aa93','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".gateway.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.3cd6aa93','transit_gateway','ibm',
  'medium','IBM Transit Gateways: Update Transit Gateway','Detected gateway.update operation on Transit Gateways via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'gateway.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.673506ee','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".gateway.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.673506ee','transit_gateway','ibm',
  'high','IBM Transit Gateways: Delete Transit Gateway','Detected gateway.delete operation on Transit Gateways via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'gateway.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.a4fcfb25','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".connection.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.a4fcfb25','transit_gateway','ibm',
  'high','IBM TGW Connections: Create Transit Gateway Connection','Detected connection.create operation on TGW Connections via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'connection.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.725d681e','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".connection.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.725d681e','transit_gateway','ibm',
  'medium','IBM TGW Connections: Update Transit Gateway Connection','Detected connection.update operation on TGW Connections via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'connection.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.transit_gateway.0248580e','transit_gateway','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"transit_gateway"},{"op":"contains","field":"operation","value":".connection.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.transit_gateway.0248580e','transit_gateway','ibm',
  'high','IBM TGW Connections: Delete Transit Gateway Connection','Detected connection.delete operation on TGW Connections via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'connection.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.toolchain.2396a8df','toolchain','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"toolchain"},{"op":"contains","field":"operation","value":".toolchain.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.toolchain.2396a8df','toolchain','ibm',
  'high','IBM Toolchains: Create Toolchain','Detected toolchain.create operation on Toolchains via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'toolchain.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.toolchain.74ccffb7','toolchain','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"toolchain"},{"op":"contains","field":"operation","value":".toolchain.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.toolchain.74ccffb7','toolchain','ibm',
  'medium','IBM Toolchains: Update Toolchain','Detected toolchain.update operation on Toolchains via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'toolchain.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.toolchain.3546a11c','toolchain','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"toolchain"},{"op":"contains","field":"operation","value":".toolchain.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.toolchain.3546a11c','toolchain','ibm',
  'high','IBM Toolchains: Delete Toolchain','Detected toolchain.delete operation on Toolchains via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'toolchain.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.3ab83339','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".pipeline.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.3ab83339','continuous_delivery','ibm',
  'high','IBM CD Pipelines: Create Continuous Delivery Pipeline','Detected pipeline.create operation on CD Pipelines via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'pipeline.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.97561d20','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".pipeline.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.97561d20','continuous_delivery','ibm',
  'high','IBM CD Pipelines: Delete Continuous Delivery Pipeline','Detected pipeline.delete operation on CD Pipelines via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'pipeline.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.b89c46d0','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".tekton-pipeline.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.b89c46d0','continuous_delivery','ibm',
  'high','IBM Tekton Pipelines: Create Tekton Pipeline','Detected tekton-pipeline.create operation on Tekton Pipelines via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'tekton-pipeline.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.continuous_delivery.b6936542','continuous_delivery','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"continuous_delivery"},{"op":"contains","field":"operation","value":".tekton-pipeline.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.continuous_delivery.b6936542','continuous_delivery','ibm',
  'high','IBM Tekton Pipelines: Delete Tekton Pipeline','Detected tekton-pipeline.delete operation on Tekton Pipelines via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'tekton-pipeline.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.5392dd7a','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".alert.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.5392dd7a','sysdig_monitor','ibm',
  'high','IBM Monitoring Alerts: Create Monitoring Alert','Detected alert.create operation on Monitoring Alerts via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'alert.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.42998ef9','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".alert.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.42998ef9','sysdig_monitor','ibm',
  'medium','IBM Monitoring Alerts: Update Monitoring Alert','Detected alert.update operation on Monitoring Alerts via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'alert.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.15c580c0','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".alert.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.15c580c0','sysdig_monitor','ibm',
  'high','IBM Monitoring Alerts: Delete Monitoring Alert','Detected alert.delete operation on Monitoring Alerts via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'alert.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.6b70bbcc','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".notification.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.6b70bbcc','sysdig_monitor','ibm',
  'high','IBM Monitoring Notifications: Create Monitoring Notification Channel','Detected notification.create operation on Monitoring Notifications via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'notification.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.0a45be7d','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".notification.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.0a45be7d','sysdig_monitor','ibm',
  'high','IBM Monitoring Notifications: Delete Monitoring Notification Channel','Detected notification.delete operation on Monitoring Notifications via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'notification.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.4b6292f6','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".team.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.4b6292f6','sysdig_monitor','ibm',
  'high','IBM Monitoring Teams: Create Monitoring Team','Detected team.create operation on Monitoring Teams via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'team.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.31a3733c','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".team.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.31a3733c','sysdig_monitor','ibm',
  'high','IBM Monitoring Teams: Delete Monitoring Team','Detected team.delete operation on Monitoring Teams via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'team.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.sysdig_monitor.bde19a96','sysdig_monitor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"sysdig_monitor"},{"op":"contains","field":"operation","value":".capture.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.sysdig_monitor.bde19a96','sysdig_monitor','ibm',
  'high','IBM Monitoring Captures: Create Monitoring Capture (Sysdig Capture)','Detected capture.create operation on Monitoring Captures via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'capture.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.8fd99807','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".account.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.8fd99807','logdna','ibm',
  'medium','IBM Log Analysis Settings: Update Log Analysis Account Settings','Detected account.update operation on Log Analysis Settings via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'account.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.14d87e0c','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".archive.config"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.14d87e0c','logdna','ibm',
  'medium','IBM Log Analysis Archive: Configure Log Analysis Archiving','Detected archive.config operation on Log Analysis Archive via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'archive.config','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.4afc1f12','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".key.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.4afc1f12','logdna','ibm',
  'high','IBM Log Analysis Keys: Create Log Analysis Service Key','Detected key.create operation on Log Analysis Keys via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'key.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.ab74104c','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".key.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.ab74104c','logdna','ibm',
  'high','IBM Log Analysis Keys: Delete Log Analysis Service Key','Detected key.delete operation on Log Analysis Keys via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'key.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.8ea60e09','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".exclusion.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.8ea60e09','logdna','ibm',
  'high','IBM Log Analysis Exclusions: Create Log Analysis Exclusion Rule','Detected exclusion.create operation on Log Analysis Exclusions via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'exclusion.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.logdna.87d69429','logdna','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"logdna"},{"op":"contains","field":"operation","value":".exclusion.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.logdna.87d69429','logdna','ibm',
  'high','IBM Log Analysis Exclusions: Delete Log Analysis Exclusion Rule','Detected exclusion.delete operation on Log Analysis Exclusions via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'exclusion.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.ded52cdc','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".location.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.ded52cdc','satellite','ibm',
  'high','IBM Satellite Locations: Create Satellite Location','Detected location.create operation on Satellite Locations via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'location.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.4d56f632','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".location.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.4d56f632','satellite','ibm',
  'medium','IBM Satellite Locations: Update Satellite Location','Detected location.update operation on Satellite Locations via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'location.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.bcb68082','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".location.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.bcb68082','satellite','ibm',
  'high','IBM Satellite Locations: Delete Satellite Location','Detected location.delete operation on Satellite Locations via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'location.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.a046e458','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".cluster.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.a046e458','satellite','ibm',
  'high','IBM Satellite Clusters: Create Satellite Cluster','Detected cluster.create operation on Satellite Clusters via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'cluster.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.d9021a3a','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".cluster.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.d9021a3a','satellite','ibm',
  'high','IBM Satellite Clusters: Delete Satellite Cluster','Detected cluster.delete operation on Satellite Clusters via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'cluster.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.718828cc','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".config.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.718828cc','satellite','ibm',
  'high','IBM Satellite Configs: Create Satellite Config','Detected config.create operation on Satellite Configs via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'config.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.7080ca55','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".link.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.7080ca55','satellite','ibm',
  'high','IBM Satellite Links: Create Satellite Link (Connector)','Detected link.create operation on Satellite Links via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'link.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.satellite.0fbf01cf','satellite','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"satellite"},{"op":"contains","field":"operation","value":".endpoint.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.satellite.0fbf01cf','satellite','ibm',
  'high','IBM Satellite Endpoints: Create Satellite Endpoint','Detected endpoint.create operation on Satellite Endpoints via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'endpoint.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.3312bd23','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".application.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.3312bd23','appid','ibm',
  'high','IBM App ID Applications: Create App ID Application','Detected application.create operation on App ID Applications via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'application.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.e528a535','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".application.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.e528a535','appid','ibm',
  'high','IBM App ID Applications: Delete App ID Application','Detected application.delete operation on App ID Applications via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'application.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.d3ad0e4a','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".application.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.d3ad0e4a','appid','ibm',
  'medium','IBM App ID Applications: Update App ID Application','Detected application.update operation on App ID Applications via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'application.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.f2c648f6','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".cloud-directory.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.f2c648f6','appid','ibm',
  'medium','IBM App ID Cloud Directory: Update App ID Cloud Directory Settings','Detected cloud-directory.set operation on App ID Cloud Directory via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'cloud-directory.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.acaccf35','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".idp.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.acaccf35','appid','ibm',
  'medium','IBM App ID Identity Providers: Configure App ID Identity Provider','Detected idp.set operation on App ID Identity Providers via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'idp.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.appid.51da45dd','appid','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"appid"},{"op":"contains","field":"operation","value":".action-url.set"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.appid.51da45dd','appid','ibm',
  'medium','IBM App ID Redirect URLs: Set App ID Redirect/Action URL','Detected action-url.set operation on App ID Redirect URLs via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'action-url.set','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.813c3c35','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".zone.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.813c3c35','dns_svcs','ibm',
  'high','IBM DNS Zones: Create Private DNS Zone','Detected zone.create operation on DNS Zones via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'zone.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.6e049dbb','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".zone.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.6e049dbb','dns_svcs','ibm',
  'medium','IBM DNS Zones: Update Private DNS Zone','Detected zone.update operation on DNS Zones via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'zone.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.b8100f29','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".zone.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.b8100f29','dns_svcs','ibm',
  'high','IBM DNS Zones: Delete Private DNS Zone','Detected zone.delete operation on DNS Zones via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'zone.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.91b1347c','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".resource-record.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.91b1347c','dns_svcs','ibm',
  'high','IBM DNS Records: Create DNS Resource Record','Detected resource-record.create operation on DNS Records via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'resource-record.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.32fcf932','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".resource-record.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.32fcf932','dns_svcs','ibm',
  'high','IBM DNS Records: Delete DNS Resource Record','Detected resource-record.delete operation on DNS Records via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'resource-record.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.dns_svcs.5456ab95','dns_svcs','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"dns_svcs"},{"op":"contains","field":"operation","value":".forwarding-rule.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.dns_svcs.5456ab95','dns_svcs','ibm',
  'high','IBM DNS Forwarding Rules: Create DNS Forwarding Rule','Detected forwarding-rule.create operation on DNS Forwarding Rules via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'forwarding-rule.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.94475f9d','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".cluster.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.94475f9d','messagehub','ibm',
  'medium','IBM Event Streams Clusters: Update Event Streams Cluster','Detected cluster.update operation on Event Streams Clusters via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'cluster.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.a452613f','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".topic.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.a452613f','messagehub','ibm',
  'high','IBM Event Streams Topics: Create Event Streams Topic','Detected topic.create operation on Event Streams Topics via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'topic.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.1d5b150b','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".topic.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.1d5b150b','messagehub','ibm',
  'high','IBM Event Streams Topics: Delete Event Streams Topic','Detected topic.delete operation on Event Streams Topics via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'topic.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.dd7ab06a','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".service-credentials.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.dd7ab06a','messagehub','ibm',
  'high','IBM ES Credentials: Create Event Streams Service Credentials','Detected service-credentials.create operation on ES Credentials via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'service-credentials.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.9480c1bb','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".service-credentials.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.9480c1bb','messagehub','ibm',
  'high','IBM ES Credentials: Delete Event Streams Service Credentials','Detected service-credentials.delete operation on ES Credentials via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'service-credentials.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.messagehub.36a0dff6','messagehub','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"messagehub"},{"op":"contains","field":"operation","value":".mirroring.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.messagehub.36a0dff6','messagehub','ibm',
  'medium','IBM ES Mirroring: Update Event Streams Mirroring Config','Detected mirroring.update operation on ES Mirroring via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'mirroring.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.security_advisor.33831eff','security_advisor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"security_advisor"},{"op":"contains","field":"operation","value":".note.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.security_advisor.33831eff','security_advisor','ibm',
  'high','IBM Security Findings: Create Security Finding Note','Detected note.create operation on Security Findings via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'note.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.security_advisor.873d92a1','security_advisor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"security_advisor"},{"op":"contains","field":"operation","value":".note.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.security_advisor.873d92a1','security_advisor','ibm',
  'medium','IBM Security Findings: Update Security Finding Note','Detected note.update operation on Security Findings via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'note.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.security_advisor.60c1844e','security_advisor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"security_advisor"},{"op":"contains","field":"operation","value":".note.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.security_advisor.60c1844e','security_advisor','ibm',
  'high','IBM Security Findings: Delete Security Finding Note','Detected note.delete operation on Security Findings via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'note.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.security_advisor.bf395582','security_advisor','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"security_advisor"},{"op":"contains","field":"operation","value":".occurrence.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.security_advisor.bf395582','security_advisor','ibm',
  'high','IBM Security Occurrences: Create Security Occurrence','Detected occurrence.create operation on Security Occurrences via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'occurrence.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.7d1b3759','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".namespace.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.7d1b3759','functions','ibm',
  'high','IBM Functions Namespaces: Create Functions Namespace','Detected namespace.create operation on Functions Namespaces via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'namespace.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.7a75e2cd','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".namespace.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.7a75e2cd','functions','ibm',
  'high','IBM Functions Namespaces: Delete Functions Namespace','Detected namespace.delete operation on Functions Namespaces via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'namespace.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.d13bed31','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".action.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.d13bed31','functions','ibm',
  'high','IBM Functions Actions: Create Function Action','Detected action.create operation on Functions Actions via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'action.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.67fce6c9','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".action.update"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.67fce6c9','functions','ibm',
  'medium','IBM Functions Actions: Update Function Action','Detected action.update operation on Functions Actions via IBM Activity Tracker.',
  'persistence','modify','ibm_activity',
  'action.update','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.486ae471','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".action.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.486ae471','functions','ibm',
  'high','IBM Functions Actions: Delete Function Action','Detected action.delete operation on Functions Actions via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'action.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.63051d9e','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".trigger.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.63051d9e','functions','ibm',
  'high','IBM Functions Triggers: Create Function Trigger','Detected trigger.create operation on Functions Triggers via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'trigger.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.4dc739ec','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".trigger.delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.4dc739ec','functions','ibm',
  'high','IBM Functions Triggers: Delete Function Trigger','Detected trigger.delete operation on Functions Triggers via IBM Activity Tracker.',
  'impact','delete','ibm_activity',
  'trigger.delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','ibm'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.ibm.functions.87a745b4','functions','ibm','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"ibm_activity"},{"op":"equals","field":"service","value":"functions"},{"op":"contains","field":"operation","value":".rule.create"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.ibm.functions.87a745b4','functions','ibm',
  'high','IBM Functions Rules: Create Function Rule','Detected rule.create operation on Functions Rules via IBM Activity Tracker.',
  'persistence','create','ibm_activity',
  'rule.create','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','ibm'
) ON CONFLICT DO NOTHING;

