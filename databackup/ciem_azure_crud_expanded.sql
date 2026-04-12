-- Azure CRUD expansion rules
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.254805','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.254805','dns','azure',
  'high','Azure DNS Zones: Create/Update DNS Zone','Detected Microsoft.Network/dnsZones/write on DNS Zones via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/dnsZones/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.74d126','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.74d126','dns','azure',
  'high','Azure DNS Zones: Delete DNS Zone','Detected Microsoft.Network/dnsZones/delete on DNS Zones via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/dnsZones/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.2dd85f','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/A/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.2dd85f','dns','azure',
  'high','Azure DNS Record Sets: Create/Update A Record','Detected Microsoft.Network/dnsZones/A/write on DNS Record Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/dnsZones/A/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.c4be7f','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/A/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.c4be7f','dns','azure',
  'high','Azure DNS Record Sets: Delete A Record','Detected Microsoft.Network/dnsZones/A/delete on DNS Record Sets via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/dnsZones/A/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.810a34','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/CNAME/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.810a34','dns','azure',
  'high','Azure DNS Record Sets: Create/Update CNAME Record','Detected Microsoft.Network/dnsZones/CNAME/write on DNS Record Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/dnsZones/CNAME/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.2cb51e','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/MX/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.2cb51e','dns','azure',
  'high','Azure DNS Record Sets: Create/Update MX Record','Detected Microsoft.Network/dnsZones/MX/write on DNS Record Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/dnsZones/MX/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dns.ba03f1','dns','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/dnsZones/TXT/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dns.ba03f1','dns','azure',
  'high','Azure DNS Record Sets: Create/Update TXT Record','Detected Microsoft.Network/dnsZones/TXT/write on DNS Record Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/dnsZones/TXT/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerinstance.1d4f63','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerinstance.1d4f63','containerinstance','azure',
  'high','Azure Container Groups: Create/Update Container Group','Detected Microsoft.ContainerInstance/containerGroups/write on Container Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerInstance/containerGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerinstance.b1789f','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerinstance.b1789f','containerinstance','azure',
  'high','Azure Container Groups: Delete Container Group','Detected Microsoft.ContainerInstance/containerGroups/delete on Container Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ContainerInstance/containerGroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerinstance.89efd7','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/start/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerinstance.89efd7','containerinstance','azure',
  'high','Azure Container Groups: Start Container Group','Detected Microsoft.ContainerInstance/containerGroups/start/action on Container Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerInstance/containerGroups/start/action','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerinstance.f57c35','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/stop/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerinstance.f57c35','containerinstance','azure',
  'high','Azure Container Groups: Stop Container Group','Detected Microsoft.ContainerInstance/containerGroups/stop/action on Container Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ContainerInstance/containerGroups/stop/action','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerinstance.13bfdd','containerinstance','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerInstance/containerGroups/restart/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerinstance.13bfdd','containerinstance','azure',
  'high','Azure Container Groups: Restart Container Group','Detected Microsoft.ContainerInstance/containerGroups/restart/action on Container Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerInstance/containerGroups/restart/action','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.4fdcab','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/serverfarms/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.4fdcab','web','azure',
  'high','Azure App Service Plans: Create/Update App Service Plan','Detected Microsoft.Web/serverfarms/write on App Service Plans via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/serverfarms/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.fbabf8','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/serverfarms/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.fbabf8','web','azure',
  'high','Azure App Service Plans: Delete App Service Plan','Detected Microsoft.Web/serverfarms/delete on App Service Plans via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Web/serverfarms/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.619354','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/sites/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.619354','web','azure',
  'high','Azure Web Apps: Create/Update Web App','Detected Microsoft.Web/sites/write on Web Apps via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/sites/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.98a45d','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/sites/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.98a45d','web','azure',
  'high','Azure Web Apps: Delete Web App','Detected Microsoft.Web/sites/delete on Web Apps via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Web/sites/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.8a0fe3','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/sites/slots/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.8a0fe3','web','azure',
  'high','Azure Web App Slots: Create/Update Deployment Slot','Detected Microsoft.Web/sites/slots/write on Web App Slots via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/sites/slots/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.084b11','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/sites/slots/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.084b11','web','azure',
  'high','Azure Web App Slots: Delete Deployment Slot','Detected Microsoft.Web/sites/slots/delete on Web App Slots via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/sites/slots/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.f00b4c','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/sites/config/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.f00b4c','web','azure',
  'high','Azure Web App Configs: Update App Configuration','Detected Microsoft.Web/sites/config/write on Web App Configs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/sites/config/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.d140ee','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/certificates/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.d140ee','web','azure',
  'high','Azure Web App Certificates: Create/Update SSL Certificate','Detected Microsoft.Web/certificates/write on Web App Certificates via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/certificates/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.91eda1','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/certificates/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.91eda1','web','azure',
  'high','Azure Web App Certificates: Delete SSL Certificate','Detected Microsoft.Web/certificates/delete on Web App Certificates via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Web/certificates/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.5adf0d','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/staticSites/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.5adf0d','web','azure',
  'high','Azure Static Sites: Create/Update Static Web App','Detected Microsoft.Web/staticSites/write on Static Sites via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Web/staticSites/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.web.ebb6c5','web','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Web/staticSites/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.web.ebb6c5','web','azure',
  'high','Azure Static Sites: Delete Static Web App','Detected Microsoft.Web/staticSites/delete on Static Sites via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Web/staticSites/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.84f428','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.84f428','streamanalytics','azure',
  'high','Azure Stream Analytics Jobs: Create/Update Stream Analytics Job','Detected Microsoft.StreamAnalytics/streamingjobs/write on Stream Analytics Jobs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.fff104','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.fff104','streamanalytics','azure',
  'high','Azure Stream Analytics Jobs: Delete Stream Analytics Job','Detected Microsoft.StreamAnalytics/streamingjobs/delete on Stream Analytics Jobs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.895bdb','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/start/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.895bdb','streamanalytics','azure',
  'high','Azure Stream Analytics Jobs: Start Stream Analytics Job','Detected Microsoft.StreamAnalytics/streamingjobs/start/action on Stream Analytics Jobs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/start/action','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.405660','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/stop/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.405660','streamanalytics','azure',
  'high','Azure Stream Analytics Jobs: Stop Stream Analytics Job','Detected Microsoft.StreamAnalytics/streamingjobs/stop/action on Stream Analytics Jobs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/stop/action','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.601ce0','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/inputs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.601ce0','streamanalytics','azure',
  'high','Azure Stream Analytics Inputs: Create/Update Stream Analytics Input','Detected Microsoft.StreamAnalytics/streamingjobs/inputs/write on Stream Analytics Inputs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/inputs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.streamanalytics.16e5d6','streamanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.StreamAnalytics/streamingjobs/outputs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.streamanalytics.16e5d6','streamanalytics','azure',
  'high','Azure Stream Analytics Outputs: Create/Update Stream Analytics Output','Detected Microsoft.StreamAnalytics/streamingjobs/outputs/write on Stream Analytics Outputs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.StreamAnalytics/streamingjobs/outputs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.2adc33','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.2adc33','kusto','azure',
  'high','Azure Kusto Clusters: Create/Update Kusto Cluster','Detected Microsoft.Kusto/clusters/write on Kusto Clusters via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Kusto/clusters/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.5e1017','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.5e1017','kusto','azure',
  'high','Azure Kusto Clusters: Delete Kusto Cluster','Detected Microsoft.Kusto/clusters/delete on Kusto Clusters via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Kusto/clusters/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.6d3386','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/start/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.6d3386','kusto','azure',
  'high','Azure Kusto Clusters: Start Kusto Cluster','Detected Microsoft.Kusto/clusters/start/action on Kusto Clusters via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Kusto/clusters/start/action','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.5edf7c','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/stop/action"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.5edf7c','kusto','azure',
  'high','Azure Kusto Clusters: Stop Kusto Cluster','Detected Microsoft.Kusto/clusters/stop/action on Kusto Clusters via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Kusto/clusters/stop/action','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.c549e0','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/databases/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.c549e0','kusto','azure',
  'high','Azure Kusto Databases: Create/Update Kusto Database','Detected Microsoft.Kusto/clusters/databases/write on Kusto Databases via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Kusto/clusters/databases/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.d79500','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/databases/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.d79500','kusto','azure',
  'high','Azure Kusto Databases: Delete Kusto Database','Detected Microsoft.Kusto/clusters/databases/delete on Kusto Databases via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Kusto/clusters/databases/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kusto.569378','kusto','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kusto/clusters/databases/dataConnections/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kusto.569378','kusto','azure',
  'high','Azure Kusto Data Connections: Create/Update Data Connection','Detected Microsoft.Kusto/clusters/databases/dataConnections/write on Kusto Data Connections via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Kusto/clusters/databases/dataConnections/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.signalr.c97c8e','signalr','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SignalRService/signalR/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.signalr.c97c8e','signalr','azure',
  'high','Azure SignalR: Create/Update SignalR Service','Detected Microsoft.SignalRService/signalR/write on SignalR via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SignalRService/signalR/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.signalr.1a8263','signalr','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SignalRService/signalR/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.signalr.1a8263','signalr','azure',
  'high','Azure SignalR: Delete SignalR Service','Detected Microsoft.SignalRService/signalR/delete on SignalR via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.SignalRService/signalR/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.signalr.562bcb','signalr','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SignalRService/webPubSub/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.signalr.562bcb','signalr','azure',
  'high','Azure Web PubSub: Create/Update Web PubSub Service','Detected Microsoft.SignalRService/webPubSub/write on Web PubSub via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SignalRService/webPubSub/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.signalr.788337','signalr','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SignalRService/webPubSub/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.signalr.788337','signalr','azure',
  'high','Azure Web PubSub: Delete Web PubSub Service','Detected Microsoft.SignalRService/webPubSub/delete on Web PubSub via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.SignalRService/webPubSub/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.relay.1e7397','relay','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Relay/namespaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.relay.1e7397','relay','azure',
  'high','Azure Relay Namespaces: Create/Update Relay Namespace','Detected Microsoft.Relay/namespaces/write on Relay Namespaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Relay/namespaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.relay.10dc95','relay','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Relay/namespaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.relay.10dc95','relay','azure',
  'high','Azure Relay Namespaces: Delete Relay Namespace','Detected Microsoft.Relay/namespaces/delete on Relay Namespaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Relay/namespaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.relay.2b1dd1','relay','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Relay/namespaces/hybridConnections/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.relay.2b1dd1','relay','azure',
  'high','Azure Hybrid Connections: Create/Update Hybrid Connection','Detected Microsoft.Relay/namespaces/hybridConnections/write on Hybrid Connections via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Relay/namespaces/hybridConnections/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.relay.d88682','relay','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Relay/namespaces/wcfRelays/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.relay.d88682','relay','azure',
  'high','Azure WCF Relays: Create/Update WCF Relay','Detected Microsoft.Relay/namespaces/wcfRelays/write on WCF Relays via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Relay/namespaces/wcfRelays/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.maps.468fc3','maps','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Maps/accounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.maps.468fc3','maps','azure',
  'high','Azure Maps Accounts: Create/Update Maps Account','Detected Microsoft.Maps/accounts/write on Maps Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Maps/accounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.maps.ad7f03','maps','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Maps/accounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.maps.ad7f03','maps','azure',
  'high','Azure Maps Accounts: Delete Maps Account','Detected Microsoft.Maps/accounts/delete on Maps Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Maps/accounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.notificationhubs.cdfbf4','notificationhubs','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NotificationHubs/namespaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.notificationhubs.cdfbf4','notificationhubs','azure',
  'high','Azure Notification Hub Namespaces: Create/Update Notification Hub Namespace','Detected Microsoft.NotificationHubs/namespaces/write on Notification Hub Namespaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NotificationHubs/namespaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.notificationhubs.a0c296','notificationhubs','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NotificationHubs/namespaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.notificationhubs.a0c296','notificationhubs','azure',
  'high','Azure Notification Hub Namespaces: Delete Notification Hub Namespace','Detected Microsoft.NotificationHubs/namespaces/delete on Notification Hub Namespaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NotificationHubs/namespaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.notificationhubs.1954f3','notificationhubs','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NotificationHubs/namespaces/notificationHubs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.notificationhubs.1954f3','notificationhubs','azure',
  'high','Azure Notification Hubs: Create/Update Notification Hub','Detected Microsoft.NotificationHubs/namespaces/notificationHubs/write on Notification Hubs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NotificationHubs/namespaces/notificationHubs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.notificationhubs.a886d9','notificationhubs','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NotificationHubs/namespaces/notificationHubs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.notificationhubs.a886d9','notificationhubs','azure',
  'high','Azure Notification Hubs: Delete Notification Hub','Detected Microsoft.NotificationHubs/namespaces/notificationHubs/delete on Notification Hubs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NotificationHubs/namespaces/notificationHubs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.436e29','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.436e29','netapp','azure',
  'high','Azure NetApp Accounts: Create/Update NetApp Account','Detected Microsoft.NetApp/netAppAccounts/write on NetApp Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NetApp/netAppAccounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.e6f882','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.e6f882','netapp','azure',
  'high','Azure NetApp Accounts: Delete NetApp Account','Detected Microsoft.NetApp/netAppAccounts/delete on NetApp Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NetApp/netAppAccounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.5c7719','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.5c7719','netapp','azure',
  'high','Azure Capacity Pools: Create/Update Capacity Pool','Detected Microsoft.NetApp/netAppAccounts/capacityPools/write on Capacity Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.d697cd','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.d697cd','netapp','azure',
  'high','Azure Capacity Pools: Delete Capacity Pool','Detected Microsoft.NetApp/netAppAccounts/capacityPools/delete on Capacity Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.d532d4','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/volumes/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.d532d4','netapp','azure',
  'high','Azure Volumes: Create/Update NetApp Volume','Detected Microsoft.NetApp/netAppAccounts/capacityPools/volumes/write on Volumes via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.c937da','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/volumes/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.c937da','netapp','azure',
  'high','Azure Volumes: Delete NetApp Volume','Detected Microsoft.NetApp/netAppAccounts/capacityPools/volumes/delete on Volumes via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.10a4e2','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.10a4e2','netapp','azure',
  'high','Azure Snapshots: Create/Update NetApp Snapshot','Detected Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/write on Snapshots via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.netapp.29a182','netapp','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.netapp.29a182','netapp','azure',
  'high','Azure Snapshots: Delete NetApp Snapshot','Detected Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/delete on Snapshots via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.1f5e61','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/hostpools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.1f5e61','desktopvirtualization','azure',
  'high','Azure AVD Host Pools: Create/Update AVD Host Pool','Detected Microsoft.DesktopVirtualization/hostpools/write on AVD Host Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DesktopVirtualization/hostpools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.51f9ea','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/hostpools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.51f9ea','desktopvirtualization','azure',
  'high','Azure AVD Host Pools: Delete AVD Host Pool','Detected Microsoft.DesktopVirtualization/hostpools/delete on AVD Host Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DesktopVirtualization/hostpools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.304900','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/applicationgroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.304900','desktopvirtualization','azure',
  'high','Azure AVD Application Groups: Create/Update AVD Application Group','Detected Microsoft.DesktopVirtualization/applicationgroups/write on AVD Application Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DesktopVirtualization/applicationgroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.902781','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/applicationgroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.902781','desktopvirtualization','azure',
  'high','Azure AVD Application Groups: Delete AVD Application Group','Detected Microsoft.DesktopVirtualization/applicationgroups/delete on AVD Application Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DesktopVirtualization/applicationgroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.d7abf4','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/workspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.d7abf4','desktopvirtualization','azure',
  'high','Azure AVD Workspaces: Create/Update AVD Workspace','Detected Microsoft.DesktopVirtualization/workspaces/write on AVD Workspaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DesktopVirtualization/workspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.b02566','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/hostpools/sessionhosts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.b02566','desktopvirtualization','azure',
  'high','Azure AVD Session Hosts: Create/Update AVD Session Host','Detected Microsoft.DesktopVirtualization/hostpools/sessionhosts/write on AVD Session Hosts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DesktopVirtualization/hostpools/sessionhosts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.desktopvirtualization.59d28c','desktopvirtualization','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DesktopVirtualization/hostpools/sessionhosts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.desktopvirtualization.59d28c','desktopvirtualization','azure',
  'high','Azure AVD Session Hosts: Delete AVD Session Host','Detected Microsoft.DesktopVirtualization/hostpools/sessionhosts/delete on AVD Session Hosts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DesktopVirtualization/hostpools/sessionhosts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.hybridcompute.bc60f3','hybridcompute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HybridCompute/machines/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.hybridcompute.bc60f3','hybridcompute','azure',
  'high','Azure Arc Servers: Register/Update Arc Server','Detected Microsoft.HybridCompute/machines/write on Arc Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HybridCompute/machines/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.hybridcompute.a66483','hybridcompute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HybridCompute/machines/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.hybridcompute.a66483','hybridcompute','azure',
  'high','Azure Arc Servers: Delete Arc Server','Detected Microsoft.HybridCompute/machines/delete on Arc Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HybridCompute/machines/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.hybridcompute.ff2e32','hybridcompute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HybridCompute/machines/extensions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.hybridcompute.ff2e32','hybridcompute','azure',
  'high','Azure Arc Extensions: Install Arc Server Extension','Detected Microsoft.HybridCompute/machines/extensions/write on Arc Extensions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HybridCompute/machines/extensions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.hybridcompute.a92b96','hybridcompute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HybridCompute/machines/extensions/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.hybridcompute.a92b96','hybridcompute','azure',
  'high','Azure Arc Extensions: Remove Arc Server Extension','Detected Microsoft.HybridCompute/machines/extensions/delete on Arc Extensions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HybridCompute/machines/extensions/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kubernetes.c973b8','kubernetes','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kubernetes/connectedClusters/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kubernetes.c973b8','kubernetes','azure',
  'high','Azure Arc Kubernetes: Register/Update Arc Kubernetes Cluster','Detected Microsoft.Kubernetes/connectedClusters/write on Arc Kubernetes via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Kubernetes/connectedClusters/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kubernetes.37ab5a','kubernetes','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Kubernetes/connectedClusters/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kubernetes.37ab5a','kubernetes','azure',
  'high','Azure Arc Kubernetes: Delete Arc Kubernetes Cluster','Detected Microsoft.Kubernetes/connectedClusters/delete on Arc Kubernetes via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Kubernetes/connectedClusters/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kubernetes.c31ae6','kubernetes','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KubernetesConfiguration/extensions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kubernetes.c31ae6','kubernetes','azure',
  'high','Azure Arc K8s Extensions: Create/Update Arc K8s Extension','Detected Microsoft.KubernetesConfiguration/extensions/write on Arc K8s Extensions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.KubernetesConfiguration/extensions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.kubernetes.79c749','kubernetes','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KubernetesConfiguration/extensions/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.kubernetes.79c749','kubernetes','azure',
  'high','Azure Arc K8s Extensions: Delete Arc K8s Extension','Detected Microsoft.KubernetesConfiguration/extensions/delete on Arc K8s Extensions via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.KubernetesConfiguration/extensions/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.digitaltwins.7575b2','digitaltwins','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DigitalTwins/digitalTwinsInstances/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.digitaltwins.7575b2','digitaltwins','azure',
  'high','Azure Digital Twins: Create/Update Digital Twins Instance','Detected Microsoft.DigitalTwins/digitalTwinsInstances/write on Digital Twins via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DigitalTwins/digitalTwinsInstances/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.digitaltwins.a222f4','digitaltwins','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DigitalTwins/digitalTwinsInstances/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.digitaltwins.a222f4','digitaltwins','azure',
  'high','Azure Digital Twins: Delete Digital Twins Instance','Detected Microsoft.DigitalTwins/digitalTwinsInstances/delete on Digital Twins via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DigitalTwins/digitalTwinsInstances/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.digitaltwins.e4c53f','digitaltwins','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.digitaltwins.e4c53f','digitaltwins','azure',
  'high','Azure DT Endpoints: Create/Update Digital Twins Endpoint','Detected Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write on DT Endpoints via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.appplatform.4fb048','appplatform','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.AppPlatform/Spring/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.appplatform.4fb048','appplatform','azure',
  'high','Azure Spring Apps: Create/Update Spring Apps Service','Detected Microsoft.AppPlatform/Spring/write on Spring Apps via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.AppPlatform/Spring/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.appplatform.0afe02','appplatform','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.AppPlatform/Spring/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.appplatform.0afe02','appplatform','azure',
  'high','Azure Spring Apps: Delete Spring Apps Service','Detected Microsoft.AppPlatform/Spring/delete on Spring Apps via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.AppPlatform/Spring/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.appplatform.5d83f4','appplatform','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.AppPlatform/Spring/apps/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.appplatform.5d83f4','appplatform','azure',
  'high','Azure Spring Apps: Create/Update Spring App','Detected Microsoft.AppPlatform/Spring/apps/write on Spring Apps via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.AppPlatform/Spring/apps/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.appplatform.8fa2d1','appplatform','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.AppPlatform/Spring/apps/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.appplatform.8fa2d1','appplatform','azure',
  'high','Azure Spring Apps: Delete Spring App','Detected Microsoft.AppPlatform/Spring/apps/delete on Spring Apps via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.AppPlatform/Spring/apps/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.appplatform.a215de','appplatform','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.AppPlatform/Spring/apps/deployments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.appplatform.a215de','appplatform','azure',
  'high','Azure Spring Deployments: Create/Update Spring App Deployment','Detected Microsoft.AppPlatform/Spring/apps/deployments/write on Spring Deployments via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.AppPlatform/Spring/apps/deployments/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.botservice.2814e7','botservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.BotService/botServices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.botservice.2814e7','botservice','azure',
  'high','Azure Bot Services: Create/Update Bot Service','Detected Microsoft.BotService/botServices/write on Bot Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.BotService/botServices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.botservice.b5790d','botservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.BotService/botServices/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.botservice.b5790d','botservice','azure',
  'high','Azure Bot Services: Delete Bot Service','Detected Microsoft.BotService/botServices/delete on Bot Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.BotService/botServices/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.botservice.93feba','botservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.BotService/botServices/channels/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.botservice.93feba','botservice','azure',
  'high','Azure Bot Channels: Create/Update Bot Channel','Detected Microsoft.BotService/botServices/channels/write on Bot Channels via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.BotService/botServices/channels/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.powerbidedicated.e10853','powerbidedicated','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.PowerBIDedicated/capacities/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.powerbidedicated.e10853','powerbidedicated','azure',
  'high','Azure Power BI Capacities: Create/Update Power BI Capacity','Detected Microsoft.PowerBIDedicated/capacities/write on Power BI Capacities via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.PowerBIDedicated/capacities/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.powerbidedicated.f31883','powerbidedicated','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.PowerBIDedicated/capacities/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.powerbidedicated.f31883','powerbidedicated','azure',
  'high','Azure Power BI Capacities: Delete Power BI Capacity','Detected Microsoft.PowerBIDedicated/capacities/delete on Power BI Capacities via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.PowerBIDedicated/capacities/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.purview.54022b','purview','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Purview/accounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.purview.54022b','purview','azure',
  'high','Azure Purview Accounts: Create/Update Purview Account','Detected Microsoft.Purview/accounts/write on Purview Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Purview/accounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.purview.aeb669','purview','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Purview/accounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.purview.aeb669','purview','azure',
  'high','Azure Purview Accounts: Delete Purview Account','Detected Microsoft.Purview/accounts/delete on Purview Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Purview/accounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datalakestore.1f5a9f','datalakestore','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataLakeStore/accounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datalakestore.1f5a9f','datalakestore','azure',
  'high','Azure Data Lake Store: Create/Update Data Lake Store Account','Detected Microsoft.DataLakeStore/accounts/write on Data Lake Store via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataLakeStore/accounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datalakestore.4883a9','datalakestore','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataLakeStore/accounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datalakestore.4883a9','datalakestore','azure',
  'high','Azure Data Lake Store: Delete Data Lake Store Account','Detected Microsoft.DataLakeStore/accounts/delete on Data Lake Store via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DataLakeStore/accounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datalakeanalytics.e41992','datalakeanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataLakeAnalytics/accounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datalakeanalytics.e41992','datalakeanalytics','azure',
  'high','Azure Data Lake Analytics: Create/Update Data Lake Analytics Account','Detected Microsoft.DataLakeAnalytics/accounts/write on Data Lake Analytics via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataLakeAnalytics/accounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datalakeanalytics.f702e6','datalakeanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataLakeAnalytics/accounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datalakeanalytics.f702e6','datalakeanalytics','azure',
  'high','Azure Data Lake Analytics: Delete Data Lake Analytics Account','Detected Microsoft.DataLakeAnalytics/accounts/delete on Data Lake Analytics via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DataLakeAnalytics/accounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datalakeanalytics.ec062b','datalakeanalytics','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataLakeAnalytics/accounts/jobs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datalakeanalytics.ec062b','datalakeanalytics','azure',
  'high','Azure DL Analytics Jobs: Submit Data Lake Analytics Job','Detected Microsoft.DataLakeAnalytics/accounts/jobs/write on DL Analytics Jobs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataLakeAnalytics/accounts/jobs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.f52ef2','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.f52ef2','batch','azure',
  'high','Azure Batch Accounts: Create/Update Batch Account','Detected Microsoft.Batch/batchAccounts/write on Batch Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Batch/batchAccounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.3b8fff','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.3b8fff','batch','azure',
  'high','Azure Batch Accounts: Delete Batch Account','Detected Microsoft.Batch/batchAccounts/delete on Batch Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Batch/batchAccounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.1714bf','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/pools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.1714bf','batch','azure',
  'high','Azure Batch Pools: Create/Update Batch Pool','Detected Microsoft.Batch/batchAccounts/pools/write on Batch Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Batch/batchAccounts/pools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.256bc6','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/pools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.256bc6','batch','azure',
  'high','Azure Batch Pools: Delete Batch Pool','Detected Microsoft.Batch/batchAccounts/pools/delete on Batch Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Batch/batchAccounts/pools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.df776e','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/jobs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.df776e','batch','azure',
  'high','Azure Batch Jobs: Create/Update Batch Job','Detected Microsoft.Batch/batchAccounts/jobs/write on Batch Jobs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Batch/batchAccounts/jobs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.batch.79c3f2','batch','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Batch/batchAccounts/jobs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.batch.79c3f2','batch','azure',
  'high','Azure Batch Jobs: Delete Batch Job','Detected Microsoft.Batch/batchAccounts/jobs/delete on Batch Jobs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Batch/batchAccounts/jobs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.healthcareapis.d2fbd4','healthcareapis','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HealthcareApis/workspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.healthcareapis.d2fbd4','healthcareapis','azure',
  'high','Azure Healthcare Workspaces: Create/Update Healthcare Workspace','Detected Microsoft.HealthcareApis/workspaces/write on Healthcare Workspaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HealthcareApis/workspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.healthcareapis.c2edda','healthcareapis','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HealthcareApis/workspaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.healthcareapis.c2edda','healthcareapis','azure',
  'high','Azure Healthcare Workspaces: Delete Healthcare Workspace','Detected Microsoft.HealthcareApis/workspaces/delete on Healthcare Workspaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.HealthcareApis/workspaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.healthcareapis.4fa09a','healthcareapis','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HealthcareApis/workspaces/fhirservices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.healthcareapis.4fa09a','healthcareapis','azure',
  'high','Azure FHIR Services: Create/Update FHIR Service','Detected Microsoft.HealthcareApis/workspaces/fhirservices/write on FHIR Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HealthcareApis/workspaces/fhirservices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.healthcareapis.3b6ff5','healthcareapis','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HealthcareApis/workspaces/fhirservices/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.healthcareapis.3b6ff5','healthcareapis','azure',
  'high','Azure FHIR Services: Delete FHIR Service','Detected Microsoft.HealthcareApis/workspaces/fhirservices/delete on FHIR Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.HealthcareApis/workspaces/fhirservices/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.healthcareapis.084b64','healthcareapis','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.HealthcareApis/workspaces/dicomservices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.healthcareapis.084b64','healthcareapis','azure',
  'high','Azure DICOM Services: Create/Update DICOM Service','Detected Microsoft.HealthcareApis/workspaces/dicomservices/write on DICOM Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.HealthcareApis/workspaces/dicomservices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.d071eb','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Devices/IotHubs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.d071eb','devices','azure',
  'high','Azure IoT Hubs: Create/Update IoT Hub','Detected Microsoft.Devices/IotHubs/write on IoT Hubs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Devices/IotHubs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.56a327','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Devices/IotHubs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.56a327','devices','azure',
  'high','Azure IoT Hubs: Delete IoT Hub','Detected Microsoft.Devices/IotHubs/delete on IoT Hubs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Devices/IotHubs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.50c293','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Devices/IotHubs/IotHubKeys/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.50c293','devices','azure',
  'high','Azure IoT Hub Keys: Create/Update IoT Hub Key','Detected Microsoft.Devices/IotHubs/IotHubKeys/write on IoT Hub Keys via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Devices/IotHubs/IotHubKeys/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.9bee61','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Devices/provisioningServices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.9bee61','devices','azure',
  'high','Azure IoT Provisioning: Create/Update IoT DPS','Detected Microsoft.Devices/provisioningServices/write on IoT Provisioning via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Devices/provisioningServices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.857cb0','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Devices/provisioningServices/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.857cb0','devices','azure',
  'high','Azure IoT Provisioning: Delete IoT DPS','Detected Microsoft.Devices/provisioningServices/delete on IoT Provisioning via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Devices/provisioningServices/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.128530','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.IoTCentral/IoTApps/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.128530','devices','azure',
  'high','Azure IoT Central: Create/Update IoT Central App','Detected Microsoft.IoTCentral/IoTApps/write on IoT Central via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.IoTCentral/IoTApps/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.devices.812760','devices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.IoTCentral/IoTApps/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.devices.812760','devices','azure',
  'high','Azure IoT Central: Delete IoT Central App','Detected Microsoft.IoTCentral/IoTApps/delete on IoT Central via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.IoTCentral/IoTApps/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.3051ea','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/firewallPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.3051ea','network','azure',
  'high','Azure Firewall Policies: Create/Update Firewall Policy','Detected Microsoft.Network/firewallPolicies/write on Firewall Policies via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/firewallPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.b80169','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/firewallPolicies/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.b80169','network','azure',
  'high','Azure Firewall Policies: Delete Firewall Policy','Detected Microsoft.Network/firewallPolicies/delete on Firewall Policies via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/firewallPolicies/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.08709b','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/firewallPolicies/ruleCollectionGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.08709b','network','azure',
  'high','Azure Firewall Policy Rules: Create/Update Firewall Policy Rule Collection','Detected Microsoft.Network/firewallPolicies/ruleCollectionGroups/write on Firewall Policy Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/firewallPolicies/ruleCollectionGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.d45415','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/applicationSecurityGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.d45415','network','azure',
  'high','Azure App Security Groups: Create/Update Application Security Group','Detected Microsoft.Network/applicationSecurityGroups/write on App Security Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/applicationSecurityGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.bf149e','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/applicationSecurityGroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.bf149e','network','azure',
  'high','Azure App Security Groups: Delete Application Security Group','Detected Microsoft.Network/applicationSecurityGroups/delete on App Security Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/applicationSecurityGroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.5375f3','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/trafficManagerProfiles/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.5375f3','network','azure',
  'high','Azure Traffic Manager: Create/Update Traffic Manager Profile','Detected Microsoft.Network/trafficManagerProfiles/write on Traffic Manager via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/trafficManagerProfiles/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.211a35','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/trafficManagerProfiles/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.211a35','network','azure',
  'high','Azure Traffic Manager: Delete Traffic Manager Profile','Detected Microsoft.Network/trafficManagerProfiles/delete on Traffic Manager via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/trafficManagerProfiles/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.67e1da','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/ddosProtectionPlans/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.67e1da','network','azure',
  'high','Azure DDoS Protection Plans: Create/Update DDoS Protection Plan','Detected Microsoft.Network/ddosProtectionPlans/write on DDoS Protection Plans via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/ddosProtectionPlans/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.25df64','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/ddosProtectionPlans/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.25df64','network','azure',
  'high','Azure DDoS Protection Plans: Delete DDoS Protection Plan','Detected Microsoft.Network/ddosProtectionPlans/delete on DDoS Protection Plans via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/ddosProtectionPlans/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.3e10e2','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/virtualHubs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.3e10e2','network','azure',
  'high','Azure Virtual Hubs: Create/Update Virtual Hub (WAN)','Detected Microsoft.Network/virtualHubs/write on Virtual Hubs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/virtualHubs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.eef9f6','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/virtualHubs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.eef9f6','network','azure',
  'high','Azure Virtual Hubs: Delete Virtual Hub','Detected Microsoft.Network/virtualHubs/delete on Virtual Hubs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/virtualHubs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.40849a','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/virtualWans/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.40849a','network','azure',
  'high','Azure Virtual WANs: Create/Update Virtual WAN','Detected Microsoft.Network/virtualWans/write on Virtual WANs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/virtualWans/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.7aa268','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/virtualWans/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.7aa268','network','azure',
  'high','Azure Virtual WANs: Delete Virtual WAN','Detected Microsoft.Network/virtualWans/delete on Virtual WANs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/virtualWans/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.c38a29','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/vpnSites/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.c38a29','network','azure',
  'high','Azure VPN Sites: Create/Update VPN Site','Detected Microsoft.Network/vpnSites/write on VPN Sites via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/vpnSites/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.93959e','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/frontDoors/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.93959e','network','azure',
  'high','Azure Front Doors: Create/Update Front Door','Detected Microsoft.Network/frontDoors/write on Front Doors via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/frontDoors/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.fe4c8c','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/frontDoors/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.fe4c8c','network','azure',
  'high','Azure Front Doors: Delete Front Door','Detected Microsoft.Network/frontDoors/delete on Front Doors via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/frontDoors/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.7ebb1e','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/serviceEndpointPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.7ebb1e','network','azure',
  'high','Azure Service Endpoint Policies: Create/Update Service Endpoint Policy','Detected Microsoft.Network/serviceEndpointPolicies/write on Service Endpoint Policies via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/serviceEndpointPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.dd5d5f','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/networkWatchers/flowLogs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.dd5d5f','network','azure',
  'high','Azure Flow Logs: Create/Update Flow Log','Detected Microsoft.Network/networkWatchers/flowLogs/write on Flow Logs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/networkWatchers/flowLogs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.56d87c','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/networkWatchers/flowLogs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.56d87c','network','azure',
  'high','Azure Flow Logs: Delete Flow Log','Detected Microsoft.Network/networkWatchers/flowLogs/delete on Flow Logs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Network/networkWatchers/flowLogs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.712ba4','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/ipGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.712ba4','network','azure',
  'high','Azure IP Groups: Create/Update IP Group (Firewall)','Detected Microsoft.Network/ipGroups/write on IP Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/ipGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.network.8b3c06','network','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Network/networkWatchers/connectionMonitors/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.network.8b3c06','network','azure',
  'high','Azure Connection Monitors: Create/Update Connection Monitor','Detected Microsoft.Network/networkWatchers/connectionMonitors/write on Connection Monitors via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Network/networkWatchers/connectionMonitors/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.03aafc','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/elasticPools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.03aafc','sql','azure',
  'high','Azure SQL Elastic Pools: Create/Update Elastic Pool','Detected Microsoft.Sql/servers/elasticPools/write on SQL Elastic Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/servers/elasticPools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.6f1d8a','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/elasticPools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.6f1d8a','sql','azure',
  'high','Azure SQL Elastic Pools: Delete Elastic Pool','Detected Microsoft.Sql/servers/elasticPools/delete on SQL Elastic Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Sql/servers/elasticPools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.446d39','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/failoverGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.446d39','sql','azure',
  'high','Azure SQL Failover Groups: Create/Update SQL Failover Group','Detected Microsoft.Sql/servers/failoverGroups/write on SQL Failover Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/servers/failoverGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.747e48','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/managedInstances/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.747e48','sql','azure',
  'high','Azure SQL Managed Instances: Create/Update SQL Managed Instance','Detected Microsoft.Sql/managedInstances/write on SQL Managed Instances via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/managedInstances/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.2431c1','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/managedInstances/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.2431c1','sql','azure',
  'high','Azure SQL Managed Instances: Delete SQL Managed Instance','Detected Microsoft.Sql/managedInstances/delete on SQL Managed Instances via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Sql/managedInstances/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.1cdecd','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/managedInstances/databases/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.1cdecd','sql','azure',
  'high','Azure SQL Managed DBs: Create/Update SQL Managed Database','Detected Microsoft.Sql/managedInstances/databases/write on SQL Managed DBs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/managedInstances/databases/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.de1b46','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/managedInstances/databases/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.de1b46','sql','azure',
  'high','Azure SQL Managed DBs: Delete SQL Managed Database','Detected Microsoft.Sql/managedInstances/databases/delete on SQL Managed DBs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Sql/managedInstances/databases/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.0b3339','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/securityAlertPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.0b3339','sql','azure',
  'high','Azure SQL Advanced Threat: Update SQL Advanced Threat Protection','Detected Microsoft.Sql/servers/securityAlertPolicies/write on SQL Advanced Threat via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/servers/securityAlertPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.cc26b4','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/databases/securityAlertPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.cc26b4','sql','azure',
  'high','Azure SQL Advanced Threat: Update DB-Level SQL Threat Protection','Detected Microsoft.Sql/servers/databases/securityAlertPolicies/write on SQL Advanced Threat via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/servers/databases/securityAlertPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.sql.1cd861','sql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.sql.1cd861','sql','azure',
  'high','Azure SQL Long Term Backup: Update SQL Long Term Retention Policy','Detected Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies/write on SQL Long Term Backup via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.fa7cb5','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/diskEncryptionSets/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.fa7cb5','compute','azure',
  'high','Azure Disk Encryption Sets: Create/Update Disk Encryption Set','Detected Microsoft.Compute/diskEncryptionSets/write on Disk Encryption Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/diskEncryptionSets/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.f41d9d','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/diskEncryptionSets/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.f41d9d','compute','azure',
  'high','Azure Disk Encryption Sets: Delete Disk Encryption Set','Detected Microsoft.Compute/diskEncryptionSets/delete on Disk Encryption Sets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/diskEncryptionSets/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.193260','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/hostGroups/hosts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.193260','compute','azure',
  'high','Azure Dedicated Hosts: Create/Update Dedicated Host','Detected Microsoft.Compute/hostGroups/hosts/write on Dedicated Hosts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/hostGroups/hosts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.be4821','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/hostGroups/hosts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.be4821','compute','azure',
  'high','Azure Dedicated Hosts: Delete Dedicated Host','Detected Microsoft.Compute/hostGroups/hosts/delete on Dedicated Hosts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/hostGroups/hosts/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.5f6ccb','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/capacityReservationGroups/capacityReservations/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.5f6ccb','compute','azure',
  'high','Azure Capacity Reservations: Create/Update Capacity Reservation','Detected Microsoft.Compute/capacityReservationGroups/capacityReservations/write on Capacity Reservations via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/capacityReservationGroups/capacityReservations/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.e91052','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/virtualMachines/runCommands/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.e91052','compute','azure',
  'high','Azure VM Run Commands: Create/Update VM Run Command','Detected Microsoft.Compute/virtualMachines/runCommands/write on VM Run Commands via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/virtualMachines/runCommands/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.compute.e65984','compute','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Compute/proximityPlacementGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.compute.e65984','compute','azure',
  'high','Azure Proximity Placement Groups: Create/Update Proximity Placement Group','Detected Microsoft.Compute/proximityPlacementGroups/write on Proximity Placement Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Compute/proximityPlacementGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.fad956','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/tableServices/tables/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.fad956','storage','azure',
  'high','Azure Storage Table Services: Create/Update Table Storage Table','Detected Microsoft.Storage/storageAccounts/tableServices/tables/write on Storage Table Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Storage/storageAccounts/tableServices/tables/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.b70d2d','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/tableServices/tables/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.b70d2d','storage','azure',
  'high','Azure Storage Table Services: Delete Table Storage Table','Detected Microsoft.Storage/storageAccounts/tableServices/tables/delete on Storage Table Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Storage/storageAccounts/tableServices/tables/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.9c1c70','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/encryptionScopes/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.9c1c70','storage','azure',
  'high','Azure Storage Encryption Scopes: Create/Update Encryption Scope','Detected Microsoft.Storage/storageAccounts/encryptionScopes/write on Storage Encryption Scopes via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Storage/storageAccounts/encryptionScopes/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.df7942','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/blobServices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.df7942','storage','azure',
  'high','Azure Storage ADLS: Update Blob Service Properties (ADLS/versioning)','Detected Microsoft.Storage/storageAccounts/blobServices/write on Storage ADLS via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Storage/storageAccounts/blobServices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.2bb2db','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/objectReplicationPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.2bb2db','storage','azure',
  'high','Azure Storage Object Replication: Create/Update Object Replication Policy','Detected Microsoft.Storage/storageAccounts/objectReplicationPolicies/write on Storage Object Replication via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Storage/storageAccounts/objectReplicationPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.storage.b8e555','storage','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Storage/storageAccounts/objectReplicationPolicies/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.storage.b8e555','storage','azure',
  'high','Azure Storage Object Replication: Delete Object Replication Policy','Detected Microsoft.Storage/storageAccounts/objectReplicationPolicies/delete on Storage Object Replication via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Storage/storageAccounts/objectReplicationPolicies/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.keyvault.258463','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/accessPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.keyvault.258463','keyvault','azure',
  'high','Azure Key Vault Access Policies: Update Key Vault Access Policy','Detected Microsoft.KeyVault/vaults/accessPolicies/write on Key Vault Access Policies via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.KeyVault/vaults/accessPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.keyvault.37a334','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/managedHSMs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.keyvault.37a334','keyvault','azure',
  'high','Azure Managed HSMs: Create/Update Managed HSM','Detected Microsoft.KeyVault/managedHSMs/write on Managed HSMs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.KeyVault/managedHSMs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.keyvault.0bae72','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/managedHSMs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.keyvault.0bae72','keyvault','azure',
  'high','Azure Managed HSMs: Delete Managed HSM','Detected Microsoft.KeyVault/managedHSMs/delete on Managed HSMs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.KeyVault/managedHSMs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.keyvault.86d652','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/certificates/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.keyvault.86d652','keyvault','azure',
  'high','Azure Key Vault Certificates: Create/Update Certificate','Detected Microsoft.KeyVault/vaults/certificates/write on Key Vault Certificates via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.KeyVault/vaults/certificates/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.keyvault.55918b','keyvault','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.KeyVault/vaults/certificates/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.keyvault.55918b','keyvault','azure',
  'high','Azure Key Vault Certificates: Delete Certificate','Detected Microsoft.KeyVault/vaults/certificates/delete on Key Vault Certificates via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.KeyVault/vaults/certificates/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.9c009d','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/webhooks/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.9c009d','containerregistry','azure',
  'high','Azure ACR Webhooks: Create/Update ACR Webhook','Detected Microsoft.ContainerRegistry/registries/webhooks/write on ACR Webhooks via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerRegistry/registries/webhooks/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.beef93','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/webhooks/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.beef93','containerregistry','azure',
  'high','Azure ACR Webhooks: Delete ACR Webhook','Detected Microsoft.ContainerRegistry/registries/webhooks/delete on ACR Webhooks via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ContainerRegistry/registries/webhooks/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.a6dc7b','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/replications/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.a6dc7b','containerregistry','azure',
  'high','Azure ACR Replications: Create/Update ACR Geo-Replication','Detected Microsoft.ContainerRegistry/registries/replications/write on ACR Replications via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerRegistry/registries/replications/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.61a3ef','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/tasks/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.61a3ef','containerregistry','azure',
  'high','Azure ACR Tasks: Create/Update ACR Task','Detected Microsoft.ContainerRegistry/registries/tasks/write on ACR Tasks via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerRegistry/registries/tasks/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.938287','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/scopeMaps/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.938287','containerregistry','azure',
  'high','Azure ACR ScopeMap: Create/Update ACR Scope Map','Detected Microsoft.ContainerRegistry/registries/scopeMaps/write on ACR ScopeMap via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerRegistry/registries/scopeMaps/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.00d9da','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/tokens/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.00d9da','containerregistry','azure',
  'high','Azure ACR Tokens: Create/Update ACR Token','Detected Microsoft.ContainerRegistry/registries/tokens/write on ACR Tokens via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerRegistry/registries/tokens/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerregistry.020ba5','containerregistry','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerRegistry/registries/tokens/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerregistry.020ba5','containerregistry','azure',
  'high','Azure ACR Tokens: Delete ACR Token','Detected Microsoft.ContainerRegistry/registries/tokens/delete on ACR Tokens via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ContainerRegistry/registries/tokens/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerservice.11b071','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/agentPools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerservice.11b071','containerservice','azure',
  'high','Azure AKS Node Pools: Create/Update AKS Node Pool','Detected Microsoft.ContainerService/managedClusters/agentPools/write on AKS Node Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerService/managedClusters/agentPools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerservice.ed4e13','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/agentPools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerservice.ed4e13','containerservice','azure',
  'high','Azure AKS Node Pools: Delete AKS Node Pool','Detected Microsoft.ContainerService/managedClusters/agentPools/delete on AKS Node Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ContainerService/managedClusters/agentPools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerservice.2da427','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/maintenanceConfigurations/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerservice.2da427','containerservice','azure',
  'high','Azure AKS Maintenance: Create/Update AKS Maintenance Configuration','Detected Microsoft.ContainerService/managedClusters/maintenanceConfigurations/write on AKS Maintenance via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerService/managedClusters/maintenanceConfigurations/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.containerservice.5558f2','containerservice','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ContainerService/managedClusters/privateEndpointConnections/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.containerservice.5558f2','containerservice','azure',
  'high','Azure AKS Private Link: Update AKS Private Endpoint Connection','Detected Microsoft.ContainerService/managedClusters/privateEndpointConnections/write on AKS Private Link via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ContainerService/managedClusters/privateEndpointConnections/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.6b3aa5','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.6b3aa5','documentdb','azure',
  'high','Azure Cosmos DB Accounts: Create/Update Cosmos DB Account','Detected Microsoft.DocumentDB/databaseAccounts/write on Cosmos DB Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.60753c','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.60753c','documentdb','azure',
  'high','Azure Cosmos DB Accounts: Delete Cosmos DB Account','Detected Microsoft.DocumentDB/databaseAccounts/delete on Cosmos DB Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.3fcb9a','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.3fcb9a','documentdb','azure',
  'high','Azure Cosmos SQL Databases: Create/Update Cosmos SQL Database','Detected Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write on Cosmos SQL Databases via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.acdf9e','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.acdf9e','documentdb','azure',
  'high','Azure Cosmos SQL Databases: Delete Cosmos SQL Database','Detected Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete on Cosmos SQL Databases via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.b8ef27','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.b8ef27','documentdb','azure',
  'high','Azure Cosmos SQL Containers: Create/Update Cosmos SQL Container','Detected Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write on Cosmos SQL Containers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.5a18e3','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.5a18e3','documentdb','azure',
  'high','Azure Cosmos MongoDB: Create/Update Cosmos MongoDB Database','Detected Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write on Cosmos MongoDB via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.1f0c4c','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.1f0c4c','documentdb','azure',
  'high','Azure Cosmos Cassandra: Create/Update Cosmos Cassandra Keyspace','Detected Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces/write on Cosmos Cassandra via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.8dfb35','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/gremlinDatabases/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.8dfb35','documentdb','azure',
  'high','Azure Cosmos Gremlin: Create/Update Cosmos Gremlin Database','Detected Microsoft.DocumentDB/databaseAccounts/gremlinDatabases/write on Cosmos Gremlin via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/gremlinDatabases/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.308d3f','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/tables/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.308d3f','documentdb','azure',
  'high','Azure Cosmos Table: Create/Update Cosmos Table API Table','Detected Microsoft.DocumentDB/databaseAccounts/tables/write on Cosmos Table via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/tables/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.documentdb.220eb7','documentdb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.documentdb.220eb7','documentdb','azure',
  'high','Azure Cosmos Private Endpoint: Update Cosmos DB Private Endpoint','Detected Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections/write on Cosmos Private Endpoint via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformysql.819e5b','dbformysql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMySQL/flexibleServers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformysql.819e5b','dbformysql','azure',
  'high','Azure MySQL Flexible Servers: Create/Update MySQL Flexible Server','Detected Microsoft.DBforMySQL/flexibleServers/write on MySQL Flexible Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforMySQL/flexibleServers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformysql.115882','dbformysql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMySQL/flexibleServers/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformysql.115882','dbformysql','azure',
  'high','Azure MySQL Flexible Servers: Delete MySQL Flexible Server','Detected Microsoft.DBforMySQL/flexibleServers/delete on MySQL Flexible Servers via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DBforMySQL/flexibleServers/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformysql.5fb613','dbformysql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMySQL/servers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformysql.5fb613','dbformysql','azure',
  'high','Azure MySQL Single Servers: Create/Update MySQL Single Server','Detected Microsoft.DBforMySQL/servers/write on MySQL Single Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforMySQL/servers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformysql.10343e','dbformysql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMySQL/flexibleServers/firewallRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformysql.10343e','dbformysql','azure',
  'high','Azure MySQL Firewall Rules: Create/Update MySQL Firewall Rule','Detected Microsoft.DBforMySQL/flexibleServers/firewallRules/write on MySQL Firewall Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforMySQL/flexibleServers/firewallRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbforpostgresql.ea3b52','dbforpostgresql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforPostgreSQL/flexibleServers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbforpostgresql.ea3b52','dbforpostgresql','azure',
  'high','Azure PostgreSQL Flexible: Create/Update PostgreSQL Flexible Server','Detected Microsoft.DBforPostgreSQL/flexibleServers/write on PostgreSQL Flexible via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforPostgreSQL/flexibleServers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbforpostgresql.fff15f','dbforpostgresql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforPostgreSQL/flexibleServers/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbforpostgresql.fff15f','dbforpostgresql','azure',
  'high','Azure PostgreSQL Flexible: Delete PostgreSQL Flexible Server','Detected Microsoft.DBforPostgreSQL/flexibleServers/delete on PostgreSQL Flexible via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DBforPostgreSQL/flexibleServers/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbforpostgresql.bb1fd4','dbforpostgresql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforPostgreSQL/servers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbforpostgresql.bb1fd4','dbforpostgresql','azure',
  'high','Azure PostgreSQL Single: Create/Update PostgreSQL Single Server','Detected Microsoft.DBforPostgreSQL/servers/write on PostgreSQL Single via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforPostgreSQL/servers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbforpostgresql.06ab08','dbforpostgresql','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbforpostgresql.06ab08','dbforpostgresql','azure',
  'high','Azure PostgreSQL Firewall: Create/Update PostgreSQL Firewall Rule','Detected Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write on PostgreSQL Firewall via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformariadb.63686f','dbformariadb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMariaDB/servers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformariadb.63686f','dbformariadb','azure',
  'high','Azure MariaDB Servers: Create/Update MariaDB Server','Detected Microsoft.DBforMariaDB/servers/write on MariaDB Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DBforMariaDB/servers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dbformariadb.58712d','dbformariadb','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DBforMariaDB/servers/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dbformariadb.58712d','dbformariadb','azure',
  'high','Azure MariaDB Servers: Delete MariaDB Server','Detected Microsoft.DBforMariaDB/servers/delete on MariaDB Servers via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DBforMariaDB/servers/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.c77594','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/topics/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.c77594','eventgrid','azure',
  'high','Azure Event Grid Topics: Create/Update Event Grid Topic','Detected Microsoft.EventGrid/topics/write on Event Grid Topics via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.EventGrid/topics/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.813c82','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/topics/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.813c82','eventgrid','azure',
  'high','Azure Event Grid Topics: Delete Event Grid Topic','Detected Microsoft.EventGrid/topics/delete on Event Grid Topics via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.EventGrid/topics/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.4ea637','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/domains/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.4ea637','eventgrid','azure',
  'high','Azure Event Grid Domains: Create/Update Event Grid Domain','Detected Microsoft.EventGrid/domains/write on Event Grid Domains via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.EventGrid/domains/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.c592bc','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/eventSubscriptions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.c592bc','eventgrid','azure',
  'high','Azure Event Grid Subs: Create/Update Event Subscription','Detected Microsoft.EventGrid/eventSubscriptions/write on Event Grid Subs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.EventGrid/eventSubscriptions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.2a6483','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/eventSubscriptions/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.2a6483','eventgrid','azure',
  'high','Azure Event Grid Subs: Delete Event Subscription','Detected Microsoft.EventGrid/eventSubscriptions/delete on Event Grid Subs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.EventGrid/eventSubscriptions/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.eventgrid.230db5','eventgrid','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.EventGrid/namespaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.eventgrid.230db5','eventgrid','azure',
  'high','Azure Event Grid Namespaces: Create/Update Event Grid Namespace','Detected Microsoft.EventGrid/namespaces/write on Event Grid Namespaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.EventGrid/namespaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.logic.1e2cec','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/workflows/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.logic.1e2cec','logic','azure',
  'high','Azure Logic Apps Standard: Create/Update Logic App','Detected Microsoft.Logic/workflows/write on Logic Apps Standard via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Logic/workflows/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.logic.de3bc3','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/workflows/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.logic.de3bc3','logic','azure',
  'high','Azure Logic Apps Standard: Delete Logic App','Detected Microsoft.Logic/workflows/delete on Logic Apps Standard via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Logic/workflows/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.logic.3fbfa3','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/workflows/runs/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.logic.3fbfa3','logic','azure',
  'high','Azure Logic App Runs: Delete Logic App Run History','Detected Microsoft.Logic/workflows/runs/delete on Logic App Runs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Logic/workflows/runs/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.logic.5a4f63','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/integrationAccounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.logic.5a4f63','logic','azure',
  'high','Azure Integration Accounts: Create/Update Integration Account','Detected Microsoft.Logic/integrationAccounts/write on Integration Accounts via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Logic/integrationAccounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.logic.69e730','logic','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Logic/integrationAccounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.logic.69e730','logic','azure',
  'high','Azure Integration Accounts: Delete Integration Account','Detected Microsoft.Logic/integrationAccounts/delete on Integration Accounts via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Logic/integrationAccounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.cfefa5','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.cfefa5','synapse','azure',
  'high','Azure Synapse Workspaces: Create/Update Synapse Workspace','Detected Microsoft.Synapse/workspaces/write on Synapse Workspaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Synapse/workspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.219154','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.219154','synapse','azure',
  'high','Azure Synapse Workspaces: Delete Synapse Workspace','Detected Microsoft.Synapse/workspaces/delete on Synapse Workspaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Synapse/workspaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.7d083c','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/sqlPools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.7d083c','synapse','azure',
  'high','Azure Synapse SQL Pools: Create/Update Synapse SQL Pool','Detected Microsoft.Synapse/workspaces/sqlPools/write on Synapse SQL Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Synapse/workspaces/sqlPools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.0d1663','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/sqlPools/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.0d1663','synapse','azure',
  'high','Azure Synapse SQL Pools: Delete Synapse SQL Pool','Detected Microsoft.Synapse/workspaces/sqlPools/delete on Synapse SQL Pools via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Synapse/workspaces/sqlPools/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.dbd7c8','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/bigDataPools/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.dbd7c8','synapse','azure',
  'high','Azure Synapse Spark Pools: Create/Update Synapse Spark Pool','Detected Microsoft.Synapse/workspaces/bigDataPools/write on Synapse Spark Pools via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Synapse/workspaces/bigDataPools/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.71e2ac','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/integrationRuntimes/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.71e2ac','synapse','azure',
  'high','Azure Synapse Pipelines: Create/Update Synapse Integration Runtime','Detected Microsoft.Synapse/workspaces/integrationRuntimes/write on Synapse Pipelines via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Synapse/workspaces/integrationRuntimes/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.synapse.b71f2b','synapse','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Synapse/workspaces/firewallRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.synapse.b71f2b','synapse','azure',
  'high','Azure Synapse Firewall: Create/Update Synapse Firewall Rule','Detected Microsoft.Synapse/workspaces/firewallRules/write on Synapse Firewall via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Synapse/workspaces/firewallRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.d58bf3','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/pipelines/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.d58bf3','datafactory','azure',
  'high','Azure ADF Pipelines: Create/Update ADF Pipeline','Detected Microsoft.DataFactory/factories/pipelines/write on ADF Pipelines via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataFactory/factories/pipelines/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.d2b800','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/pipelines/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.d2b800','datafactory','azure',
  'high','Azure ADF Pipelines: Delete ADF Pipeline','Detected Microsoft.DataFactory/factories/pipelines/delete on ADF Pipelines via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.DataFactory/factories/pipelines/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.2fd72d','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/datasets/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.2fd72d','datafactory','azure',
  'high','Azure ADF Datasets: Create/Update ADF Dataset','Detected Microsoft.DataFactory/factories/datasets/write on ADF Datasets via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataFactory/factories/datasets/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.8d5c07','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/linkedservices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.8d5c07','datafactory','azure',
  'high','Azure ADF Linked Services: Create/Update ADF Linked Service','Detected Microsoft.DataFactory/factories/linkedservices/write on ADF Linked Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataFactory/factories/linkedservices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.56946a','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/triggers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.56946a','datafactory','azure',
  'high','Azure ADF Triggers: Create/Update ADF Trigger','Detected Microsoft.DataFactory/factories/triggers/write on ADF Triggers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataFactory/factories/triggers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.datafactory.0025fe','datafactory','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.DataFactory/factories/integrationRuntimes/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.datafactory.0025fe','datafactory','azure',
  'high','Azure ADF IRs: Create/Update ADF Integration Runtime','Detected Microsoft.DataFactory/factories/integrationRuntimes/write on ADF IRs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.DataFactory/factories/integrationRuntimes/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.databricks.821e87','databricks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Databricks/workspaces/virtualNetworkPeerings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.databricks.821e87','databricks','azure',
  'high','Azure Databricks Clusters: Create/Update Databricks VNet Peering','Detected Microsoft.Databricks/workspaces/virtualNetworkPeerings/write on Databricks Clusters via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Databricks/workspaces/virtualNetworkPeerings/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.databricks.a0505e','databricks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Databricks/workspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.databricks.a0505e','databricks','azure',
  'high','Azure Databricks Workspaces: Create/Update Databricks Workspace','Detected Microsoft.Databricks/workspaces/write on Databricks Workspaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Databricks/workspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.databricks.e56b87','databricks','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Databricks/workspaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.databricks.e56b87','databricks','azure',
  'high','Azure Databricks Workspaces: Delete Databricks Workspace','Detected Microsoft.Databricks/workspaces/delete on Databricks Workspaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Databricks/workspaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.3ab112','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/backends/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.3ab112','apimanagement','azure',
  'high','Azure APIM Backends: Create/Update APIM Backend','Detected Microsoft.ApiManagement/service/backends/write on APIM Backends via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ApiManagement/service/backends/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.5305b3','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/policies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.5305b3','apimanagement','azure',
  'high','Azure APIM Policies: Create/Update APIM Global Policy','Detected Microsoft.ApiManagement/service/policies/write on APIM Policies via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ApiManagement/service/policies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.2be7c8','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/apis/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.2be7c8','apimanagement','azure',
  'high','Azure APIM APIs: Create/Update APIM API','Detected Microsoft.ApiManagement/service/apis/write on APIM APIs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ApiManagement/service/apis/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.4ae0bd','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/apis/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.4ae0bd','apimanagement','azure',
  'high','Azure APIM APIs: Delete APIM API','Detected Microsoft.ApiManagement/service/apis/delete on APIM APIs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ApiManagement/service/apis/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.9f739c','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/subscriptions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.9f739c','apimanagement','azure',
  'high','Azure APIM Subscriptions: Create/Update APIM Subscription','Detected Microsoft.ApiManagement/service/subscriptions/write on APIM Subscriptions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ApiManagement/service/subscriptions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.apimanagement.dd8b8e','apimanagement','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ApiManagement/service/products/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.apimanagement.dd8b8e','apimanagement','azure',
  'high','Azure APIM Products: Create/Update APIM Product','Detected Microsoft.ApiManagement/service/products/write on APIM Products via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ApiManagement/service/products/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cognitiveservices.ce7454','cognitiveservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.CognitiveServices/accounts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cognitiveservices.ce7454','cognitiveservices','azure',
  'high','Azure Cognitive Services: Create/Update Cognitive Services Account','Detected Microsoft.CognitiveServices/accounts/write on Cognitive Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.CognitiveServices/accounts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cognitiveservices.62f578','cognitiveservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.CognitiveServices/accounts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cognitiveservices.62f578','cognitiveservices','azure',
  'high','Azure Cognitive Services: Delete Cognitive Services Account','Detected Microsoft.CognitiveServices/accounts/delete on Cognitive Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.CognitiveServices/accounts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cognitiveservices.64156e','cognitiveservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.CognitiveServices/accounts/deployments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cognitiveservices.64156e','cognitiveservices','azure',
  'high','Azure Cognitive Deployments: Create/Update Cognitive Services Deployment (AI Model)','Detected Microsoft.CognitiveServices/accounts/deployments/write on Cognitive Deployments via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.CognitiveServices/accounts/deployments/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cognitiveservices.6cb850','cognitiveservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.CognitiveServices/accounts/deployments/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cognitiveservices.6cb850','cognitiveservices','azure',
  'high','Azure Cognitive Deployments: Delete Cognitive Services Model Deployment','Detected Microsoft.CognitiveServices/accounts/deployments/delete on Cognitive Deployments via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.CognitiveServices/accounts/deployments/delete','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.machinelearningservices.333ce2','machinelearningservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.MachineLearningServices/workspaces/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.machinelearningservices.333ce2','machinelearningservices','azure',
  'high','Azure ML Workspaces: Create/Update ML Workspace','Detected Microsoft.MachineLearningServices/workspaces/write on ML Workspaces via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.MachineLearningServices/workspaces/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.machinelearningservices.436d1f','machinelearningservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.MachineLearningServices/workspaces/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.machinelearningservices.436d1f','machinelearningservices','azure',
  'high','Azure ML Workspaces: Delete ML Workspace','Detected Microsoft.MachineLearningServices/workspaces/delete on ML Workspaces via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.MachineLearningServices/workspaces/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.machinelearningservices.30fd9e','machinelearningservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.MachineLearningServices/workspaces/computes/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.machinelearningservices.30fd9e','machinelearningservices','azure',
  'high','Azure ML Compute: Create/Update ML Compute Cluster','Detected Microsoft.MachineLearningServices/workspaces/computes/write on ML Compute via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.MachineLearningServices/workspaces/computes/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.machinelearningservices.7cde16','machinelearningservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.MachineLearningServices/workspaces/jobs/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.machinelearningservices.7cde16','machinelearningservices','azure',
  'high','Azure ML Jobs: Create/Update ML Training Job','Detected Microsoft.MachineLearningServices/workspaces/jobs/write on ML Jobs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.MachineLearningServices/workspaces/jobs/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.machinelearningservices.74cb37','machinelearningservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.machinelearningservices.74cb37','machinelearningservices','azure',
  'high','Azure ML Endpoints: Create/Update ML Online Endpoint','Detected Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write on ML Endpoints via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.recoveryservices.4bb285','recoveryservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.RecoveryServices/vaults/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.recoveryservices.4bb285','recoveryservices','azure',
  'high','Azure Recovery Vaults: Create/Update Recovery Services Vault','Detected Microsoft.RecoveryServices/vaults/write on Recovery Vaults via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.RecoveryServices/vaults/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.recoveryservices.c5c5c1','recoveryservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.RecoveryServices/vaults/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.recoveryservices.c5c5c1','recoveryservices','azure',
  'high','Azure Recovery Vaults: Delete Recovery Services Vault','Detected Microsoft.RecoveryServices/vaults/delete on Recovery Vaults via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.RecoveryServices/vaults/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.recoveryservices.5be894','recoveryservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.recoveryservices.5be894','recoveryservices','azure',
  'high','Azure Backup Protected Items: Create/Update Backup Protected Item','Detected Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/write on Backup Protected Items via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.recoveryservices.fd73aa','recoveryservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.RecoveryServices/vaults/replicationFabrics/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.recoveryservices.fd73aa','recoveryservices','azure',
  'high','Azure ASR Replication: Create/Update Site Recovery Fabric','Detected Microsoft.RecoveryServices/vaults/replicationFabrics/write on ASR Replication via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.RecoveryServices/vaults/replicationFabrics/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.recoveryservices.93cef6','recoveryservices','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.RecoveryServices/vaults/replicationPolicies/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.recoveryservices.93cef6','recoveryservices','azure',
  'high','Azure ASR Policies: Create/Update ASR Replication Policy','Detected Microsoft.RecoveryServices/vaults/replicationPolicies/write on ASR Policies via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.RecoveryServices/vaults/replicationPolicies/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.dd1a24','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/metricAlerts/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.dd1a24','insights','azure',
  'high','Azure Alert Rules: Create/Update Metric Alert Rule','Detected Microsoft.Insights/metricAlerts/write on Alert Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Insights/metricAlerts/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.706ff0','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/metricAlerts/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.706ff0','insights','azure',
  'high','Azure Alert Rules: Delete Metric Alert Rule','Detected Microsoft.Insights/metricAlerts/delete on Alert Rules via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Insights/metricAlerts/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.0821d8','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/actionGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.0821d8','insights','azure',
  'high','Azure Action Groups: Create/Update Action Group','Detected Microsoft.Insights/actionGroups/write on Action Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Insights/actionGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.0a73f4','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/actionGroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.0a73f4','insights','azure',
  'high','Azure Action Groups: Delete Action Group','Detected Microsoft.Insights/actionGroups/delete on Action Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Insights/actionGroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.10d3ab','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/dataCollectionRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.10d3ab','insights','azure',
  'high','Azure Data Collection Rules: Create/Update Data Collection Rule','Detected Microsoft.Insights/dataCollectionRules/write on Data Collection Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Insights/dataCollectionRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.ecf72f','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/dataCollectionRules/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.ecf72f','insights','azure',
  'high','Azure Data Collection Rules: Delete Data Collection Rule','Detected Microsoft.Insights/dataCollectionRules/delete on Data Collection Rules via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Insights/dataCollectionRules/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.c52b99','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/scheduledQueryRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.c52b99','insights','azure',
  'high','Azure Scheduled Query Rules: Create/Update Scheduled Query Alert','Detected Microsoft.Insights/scheduledQueryRules/write on Scheduled Query Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Insights/scheduledQueryRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.insights.84e4dd','insights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Insights/autoscaleSettings/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.insights.84e4dd','insights','azure',
  'high','Azure Autoscale Settings: Create/Update Autoscale Setting','Detected Microsoft.Insights/autoscaleSettings/write on Autoscale Settings via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Insights/autoscaleSettings/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.23053f','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/alertRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.23053f','securityinsights','azure',
  'high','Azure Sentinel Analytics Rules: Create/Update Sentinel Analytics Rule','Detected Microsoft.SecurityInsights/alertRules/write on Sentinel Analytics Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SecurityInsights/alertRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.1656db','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/alertRules/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.1656db','securityinsights','azure',
  'high','Azure Sentinel Analytics Rules: Delete Sentinel Analytics Rule','Detected Microsoft.SecurityInsights/alertRules/delete on Sentinel Analytics Rules via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.SecurityInsights/alertRules/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.549918','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/dataConnectors/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.549918','securityinsights','azure',
  'high','Azure Sentinel Data Connectors: Create/Update Sentinel Data Connector','Detected Microsoft.SecurityInsights/dataConnectors/write on Sentinel Data Connectors via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SecurityInsights/dataConnectors/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.e22eea','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/dataConnectors/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.e22eea','securityinsights','azure',
  'high','Azure Sentinel Data Connectors: Delete Sentinel Data Connector','Detected Microsoft.SecurityInsights/dataConnectors/delete on Sentinel Data Connectors via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.SecurityInsights/dataConnectors/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.8cc542','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/automationRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.8cc542','securityinsights','azure',
  'high','Azure Sentinel Automation Rules: Create/Update Sentinel Automation Rule','Detected Microsoft.SecurityInsights/automationRules/write on Sentinel Automation Rules via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SecurityInsights/automationRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.securityinsights.8577f3','securityinsights','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.SecurityInsights/incidents/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.securityinsights.8577f3','securityinsights','azure',
  'high','Azure Sentinel Incidents: Update Sentinel Incident','Detected Microsoft.SecurityInsights/incidents/write on Sentinel Incidents via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.SecurityInsights/incidents/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managementgroups.20c25a','managementgroups','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Management/managementGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managementgroups.20c25a','managementgroups','azure',
  'high','Azure Management Groups: Create/Update Management Group','Detected Microsoft.Management/managementGroups/write on Management Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Management/managementGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managementgroups.2deded','managementgroups','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Management/managementGroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managementgroups.2deded','managementgroups','azure',
  'high','Azure Management Groups: Delete Management Group','Detected Microsoft.Management/managementGroups/delete on Management Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Management/managementGroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managementgroups.21f433','managementgroups','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Management/managementGroups/subscriptions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managementgroups.21f433','managementgroups','azure',
  'high','Azure Subscription Placement: Move Subscription to Management Group','Detected Microsoft.Management/managementGroups/subscriptions/write on Subscription Placement via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Management/managementGroups/subscriptions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.352010','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Resources/subscriptions/resourceGroups/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.352010','resources','azure',
  'high','Azure Resource Groups: Create/Update Resource Group','Detected Microsoft.Resources/subscriptions/resourceGroups/write on Resource Groups via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Resources/subscriptions/resourceGroups/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.74dce5','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Resources/subscriptions/resourceGroups/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.74dce5','resources','azure',
  'high','Azure Resource Groups: Delete Resource Group','Detected Microsoft.Resources/subscriptions/resourceGroups/delete on Resource Groups via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Resources/subscriptions/resourceGroups/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.ff9be1','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/locks/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.ff9be1','resources','azure',
  'high','Azure Locks: Create/Update Resource Lock','Detected Microsoft.Authorization/locks/write on Locks via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Authorization/locks/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.bd9df0','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/locks/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.bd9df0','resources','azure',
  'high','Azure Locks: Delete Resource Lock','Detected Microsoft.Authorization/locks/delete on Locks via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Authorization/locks/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.81ffb8','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/policyAssignments/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.81ffb8','resources','azure',
  'high','Azure Policy Assignments: Create/Update Policy Assignment','Detected Microsoft.Authorization/policyAssignments/write on Policy Assignments via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Authorization/policyAssignments/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.0278c5','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/policyAssignments/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.0278c5','resources','azure',
  'high','Azure Policy Assignments: Delete Policy Assignment','Detected Microsoft.Authorization/policyAssignments/delete on Policy Assignments via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Authorization/policyAssignments/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.36fa56','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/policyExemptions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.36fa56','resources','azure',
  'high','Azure Policy Exemptions: Create/Update Policy Exemption','Detected Microsoft.Authorization/policyExemptions/write on Policy Exemptions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Authorization/policyExemptions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.836521','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Authorization/roleDefinitions/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.836521','resources','azure',
  'high','Azure Role Definitions: Create/Update Custom Role Definition','Detected Microsoft.Authorization/roleDefinitions/write on Role Definitions via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Authorization/roleDefinitions/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.ce733e','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Blueprint/blueprints/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.ce733e','resources','azure',
  'high','Azure Blueprints: Create/Update Blueprint','Detected Microsoft.Blueprint/blueprints/write on Blueprints via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Blueprint/blueprints/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.resources.f4c75f','resources','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Blueprint/blueprints/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.resources.f4c75f','resources','azure',
  'high','Azure Blueprints: Delete Blueprint','Detected Microsoft.Blueprint/blueprints/delete on Blueprints via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Blueprint/blueprints/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.servicefabric.8f03a8','servicefabric','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ServiceFabric/clusters/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.servicefabric.8f03a8','servicefabric','azure',
  'high','Azure Service Fabric Clusters: Create/Update Service Fabric Cluster','Detected Microsoft.ServiceFabric/clusters/write on Service Fabric Clusters via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ServiceFabric/clusters/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.servicefabric.54682e','servicefabric','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ServiceFabric/clusters/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.servicefabric.54682e','servicefabric','azure',
  'high','Azure Service Fabric Clusters: Delete Service Fabric Cluster','Detected Microsoft.ServiceFabric/clusters/delete on Service Fabric Clusters via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ServiceFabric/clusters/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.servicefabric.941c2a','servicefabric','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ServiceFabric/clusters/applications/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.servicefabric.941c2a','servicefabric','azure',
  'high','Azure SF Applications: Create/Update Service Fabric Application','Detected Microsoft.ServiceFabric/clusters/applications/write on SF Applications via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ServiceFabric/clusters/applications/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managedidentity.f9fbb8','managedidentity','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ManagedIdentity/userAssignedIdentities/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managedidentity.f9fbb8','managedidentity','azure',
  'high','Azure User-Assigned MIs: Create/Update User-Assigned Managed Identity','Detected Microsoft.ManagedIdentity/userAssignedIdentities/write on User-Assigned MIs via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ManagedIdentity/userAssignedIdentities/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managedidentity.2b03d9','managedidentity','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ManagedIdentity/userAssignedIdentities/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managedidentity.2b03d9','managedidentity','azure',
  'high','Azure User-Assigned MIs: Delete User-Assigned Managed Identity','Detected Microsoft.ManagedIdentity/userAssignedIdentities/delete on User-Assigned MIs via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ManagedIdentity/userAssignedIdentities/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managedidentity.a572b9','managedidentity','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managedidentity.a572b9','managedidentity','azure',
  'high','Azure MI Federated Credentials: Create/Update MI Federated Identity Credential','Detected Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write on MI Federated Credentials via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.managedidentity.dd2f5d','managedidentity','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.managedidentity.dd2f5d','managedidentity','azure',
  'high','Azure MI Federated Credentials: Delete MI Federated Identity Credential','Detected Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete on MI Federated Credentials via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.search.caf418','search','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Search/searchServices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.search.caf418','search','azure',
  'high','Azure Search Services: Create/Update Azure Search Service','Detected Microsoft.Search/searchServices/write on Search Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Search/searchServices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.search.efa50e','search','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Search/searchServices/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.search.efa50e','search','azure',
  'high','Azure Search Services: Delete Azure Search Service','Detected Microsoft.Search/searchServices/delete on Search Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Search/searchServices/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cache.48ea7d','cache','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cache/redisEnterprise/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cache.48ea7d','cache','azure',
  'high','Azure Redis Enterprise: Create/Update Redis Enterprise Cluster','Detected Microsoft.Cache/redisEnterprise/write on Redis Enterprise via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Cache/redisEnterprise/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cache.51accf','cache','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cache/redisEnterprise/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cache.51accf','cache','azure',
  'high','Azure Redis Enterprise: Delete Redis Enterprise Cluster','Detected Microsoft.Cache/redisEnterprise/delete on Redis Enterprise via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Cache/redisEnterprise/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cache.13e777','cache','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cache/redis/firewallRules/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cache.13e777','cache','azure',
  'high','Azure Redis Firewall: Create/Update Redis Firewall Rule','Detected Microsoft.Cache/redis/firewallRules/write on Redis Firewall via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Cache/redis/firewallRules/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cache.fb7665','cache','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cache/redis/linkedServers/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cache.fb7665','cache','azure',
  'high','Azure Redis Linked Servers: Create/Update Redis Linked Server (Geo-Replication)','Detected Microsoft.Cache/redis/linkedServers/write on Redis Linked Servers via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Cache/redis/linkedServers/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cdn.586093','cdn','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cdn/profiles/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cdn.586093','cdn','azure',
  'high','Azure CDN Profiles: Create/Update CDN Profile','Detected Microsoft.Cdn/profiles/write on CDN Profiles via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Cdn/profiles/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cdn.3a3b36','cdn','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cdn/profiles/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cdn.3a3b36','cdn','azure',
  'high','Azure CDN Profiles: Delete CDN Profile','Detected Microsoft.Cdn/profiles/delete on CDN Profiles via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Cdn/profiles/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cdn.6eb1ca','cdn','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cdn/profiles/endpoints/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cdn.6eb1ca','cdn','azure',
  'high','Azure CDN Endpoints: Create/Update CDN Endpoint','Detected Microsoft.Cdn/profiles/endpoints/write on CDN Endpoints via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Cdn/profiles/endpoints/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.cdn.c0faea','cdn','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Cdn/profiles/endpoints/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.cdn.c0faea','cdn','azure',
  'high','Azure CDN Endpoints: Delete CDN Endpoint','Detected Microsoft.Cdn/profiles/endpoints/delete on CDN Endpoints via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Cdn/profiles/endpoints/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dashboard.d39d74','dashboard','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Dashboard/grafana/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dashboard.d39d74','dashboard','azure',
  'high','Azure Managed Grafana: Create/Update Managed Grafana','Detected Microsoft.Dashboard/grafana/write on Managed Grafana via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Dashboard/grafana/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.dashboard.37bea5','dashboard','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Dashboard/grafana/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.dashboard.37bea5','dashboard','azure',
  'high','Azure Managed Grafana: Delete Managed Grafana','Detected Microsoft.Dashboard/grafana/delete on Managed Grafana via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Dashboard/grafana/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.media.0a7f01','media','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Media/mediaservices/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.media.0a7f01','media','azure',
  'high','Azure Media Services: Create/Update Media Services Account','Detected Microsoft.Media/mediaservices/write on Media Services via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Media/mediaservices/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.media.40102c','media','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Media/mediaservices/delete"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.media.40102c','media','azure',
  'high','Azure Media Services: Delete Media Services Account','Detected Microsoft.Media/mediaservices/delete on Media Services via Azure Activity Log.',
  'impact','delete','azure_activity',
  'Microsoft.Media/mediaservices/delete','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','azure'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.azure.media.1ec313','media','azure','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"azure_activity"},{"op":"equals","field":"operation","value":"Microsoft.Media/mediaservices/streamingEndpoints/write"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,
  mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.azure.media.1ec313','media','azure',
  'high','Azure Media Streaming: Create/Update Media Streaming Endpoint','Detected Microsoft.Media/mediaservices/streamingEndpoints/write on Media Streaming via Azure Activity Log.',
  'persistence','create','azure_activity',
  'Microsoft.Media/mediaservices/streamingEndpoints/write','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','azure'
) ON CONFLICT DO NOTHING;

