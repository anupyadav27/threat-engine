-- OCI CRUD round 3
INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.395b3225','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"CreateProject"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.395b3225','com.oraclecloud.devops','oci',
  'high','OCI DevOps Projects: Create DevOps Project','Detected CreateProject on DevOps Projects via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateProject','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.da814032','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"DeleteProject"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.da814032','com.oraclecloud.devops','oci',
  'high','OCI DevOps Projects: Delete DevOps Project','Detected DeleteProject on DevOps Projects via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteProject','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.5a307d69','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"CreateDeployPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.5a307d69','com.oraclecloud.devops','oci',
  'high','OCI DevOps Pipelines: Create Deployment Pipeline','Detected CreateDeployPipeline on DevOps Pipelines via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDeployPipeline','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.e853e860','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"DeleteDeployPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.e853e860','com.oraclecloud.devops','oci',
  'high','OCI DevOps Pipelines: Delete Deployment Pipeline','Detected DeleteDeployPipeline on DevOps Pipelines via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'DeleteDeployPipeline','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.19decde5','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"RunDeploymentPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.19decde5','com.oraclecloud.devops','oci',
  'high','OCI DevOps Pipelines: Run Deployment Pipeline','Detected RunDeploymentPipeline on DevOps Pipelines via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'RunDeploymentPipeline','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.0444d8e0','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"CreateBuildPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.0444d8e0','com.oraclecloud.devops','oci',
  'high','OCI DevOps Build Pipelines: Create Build Pipeline','Detected CreateBuildPipeline on DevOps Build Pipelines via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBuildPipeline','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.ed3678f4','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"RunBuildPipeline"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.ed3678f4','com.oraclecloud.devops','oci',
  'medium','OCI DevOps Build Runs: Run Build Pipeline','Detected RunBuildPipeline on DevOps Build Runs via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'RunBuildPipeline','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.9001b38d','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"CreateRepository"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.9001b38d','com.oraclecloud.devops','oci',
  'high','OCI DevOps Repositories: Create Code Repository','Detected CreateRepository on DevOps Repositories via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateRepository','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.devops.6b6535c7','com.oraclecloud.devops','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.devops"},{"op":"equals","field":"operation","value":"CreateDeployArtifact"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.devops.6b6535c7','com.oraclecloud.devops','oci',
  'high','OCI DevOps Artifacts: Create Deployment Artifact','Detected CreateDeployArtifact on DevOps Artifacts via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDeployArtifact','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.waf.968d35e1','com.oraclecloud.waf','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.waf"},{"op":"equals","field":"operation","value":"CreateWebAppFirewallPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.waf.968d35e1','com.oraclecloud.waf','oci',
  'high','OCI WAF Policies: Create WAF Policy','Detected CreateWebAppFirewallPolicy on WAF Policies via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateWebAppFirewallPolicy','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.waf.a97628a1','com.oraclecloud.waf','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.waf"},{"op":"equals","field":"operation","value":"DeleteWebAppFirewallPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.waf.a97628a1','com.oraclecloud.waf','oci',
  'high','OCI WAF Policies: Delete WAF Policy','Detected DeleteWebAppFirewallPolicy on WAF Policies via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteWebAppFirewallPolicy','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.waf.69002e26','com.oraclecloud.waf','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.waf"},{"op":"equals","field":"operation","value":"UpdateWebAppFirewallPolicy"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.waf.69002e26','com.oraclecloud.waf','oci',
  'medium','OCI WAF Policies: Update WAF Policy','Detected UpdateWebAppFirewallPolicy on WAF Policies via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateWebAppFirewallPolicy','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.waf.aef9fd94','com.oraclecloud.waf','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.waf"},{"op":"equals","field":"operation","value":"UpdateNetworkAddressList"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.waf.aef9fd94','com.oraclecloud.waf','oci',
  'high','OCI WAF Protection Capabilities: Update WAF Network Address List','Detected UpdateNetworkAddressList on WAF Protection Capabilities via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'UpdateNetworkAddressList','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.8329aa30','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"CreateGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.8329aa30','com.oraclecloud.apigateway','oci',
  'high','OCI API Gateways: Create API Gateway','Detected CreateGateway on API Gateways via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateGateway','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.304ce482','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"DeleteGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.304ce482','com.oraclecloud.apigateway','oci',
  'high','OCI API Gateways: Delete API Gateway','Detected DeleteGateway on API Gateways via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteGateway','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.c8cfcbd7','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"UpdateGateway"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.c8cfcbd7','com.oraclecloud.apigateway','oci',
  'medium','OCI API Gateways: Update API Gateway','Detected UpdateGateway on API Gateways via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateGateway','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.e80e3fff','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"CreateDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.e80e3fff','com.oraclecloud.apigateway','oci',
  'high','OCI API Deployments: Create API Deployment','Detected CreateDeployment on API Deployments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.db3305ed','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"DeleteDeployment"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.db3305ed','com.oraclecloud.apigateway','oci',
  'high','OCI API Deployments: Delete API Deployment','Detected DeleteDeployment on API Deployments via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'DeleteDeployment','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.apigateway.3319a39e','com.oraclecloud.apigateway','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.apigateway"},{"op":"equals","field":"operation","value":"CreateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.apigateway.3319a39e','com.oraclecloud.apigateway','oci',
  'high','OCI API Certificates: Create API Gateway Certificate','Detected CreateCertificate on API Certificates via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCertificate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.e9c60625','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"CreateLoadBalancer"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.e9c60625','com.oraclecloud.loadbalancer','oci',
  'high','OCI Load Balancers: Create Load Balancer','Detected CreateLoadBalancer on Load Balancers via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateLoadBalancer','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.8a37ee92','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"DeleteLoadBalancer"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.8a37ee92','com.oraclecloud.loadbalancer','oci',
  'high','OCI Load Balancers: Delete Load Balancer','Detected DeleteLoadBalancer on Load Balancers via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteLoadBalancer','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.cd7df8bd','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"CreateBackendSet"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.cd7df8bd','com.oraclecloud.loadbalancer','oci',
  'high','OCI LB Backends: Create LB Backend Set','Detected CreateBackendSet on LB Backends via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBackendSet','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.9ea6403f','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"DeleteBackendSet"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.9ea6403f','com.oraclecloud.loadbalancer','oci',
  'high','OCI LB Backends: Delete LB Backend Set','Detected DeleteBackendSet on LB Backends via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteBackendSet','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.1912aa4f','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"CreateListener"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.1912aa4f','com.oraclecloud.loadbalancer','oci',
  'high','OCI LB Listeners: Create LB Listener','Detected CreateListener on LB Listeners via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateListener','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.loadbalancer.4bb2c6c7','com.oraclecloud.loadbalancer','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.loadbalancer"},{"op":"equals","field":"operation","value":"CreateCertificate"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.loadbalancer.4bb2c6c7','com.oraclecloud.loadbalancer','oci',
  'high','OCI LB Certificates: Create LB Certificate','Detected CreateCertificate on LB Certificates via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCertificate','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bastion.cb4b3b4d','com.oraclecloud.bastion','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bastion"},{"op":"equals","field":"operation","value":"CreateBastion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bastion.cb4b3b4d','com.oraclecloud.bastion','oci',
  'high','OCI Bastions: Create OCI Bastion','Detected CreateBastion on Bastions via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateBastion','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bastion.b5282ef6','com.oraclecloud.bastion','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bastion"},{"op":"equals","field":"operation","value":"DeleteBastion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bastion.b5282ef6','com.oraclecloud.bastion','oci',
  'high','OCI Bastions: Delete OCI Bastion','Detected DeleteBastion on Bastions via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteBastion','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bastion.0b12276c','com.oraclecloud.bastion','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bastion"},{"op":"equals","field":"operation","value":"UpdateBastion"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bastion.0b12276c','com.oraclecloud.bastion','oci',
  'medium','OCI Bastions: Update OCI Bastion','Detected UpdateBastion on Bastions via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateBastion','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.bastion.a8f8ad2d','com.oraclecloud.bastion','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.bastion"},{"op":"equals","field":"operation","value":"DeleteSession"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.bastion.a8f8ad2d','com.oraclecloud.bastion','oci',
  'high','OCI Bastion Sessions: Delete Bastion Session','Detected DeleteSession on Bastion Sessions via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSession','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.be4d97c2','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"CreateApplication"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.be4d97c2','com.oraclecloud.functions','oci',
  'high','OCI Function Applications: Create Functions Application','Detected CreateApplication on Function Applications via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateApplication','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.2fb4a03a','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"DeleteApplication"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.2fb4a03a','com.oraclecloud.functions','oci',
  'high','OCI Function Applications: Delete Functions Application','Detected DeleteApplication on Function Applications via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteApplication','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.d2211535','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"UpdateApplication"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.d2211535','com.oraclecloud.functions','oci',
  'medium','OCI Function Applications: Update Functions Application','Detected UpdateApplication on Function Applications via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateApplication','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.6abe68b0','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"CreateFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.6abe68b0','com.oraclecloud.functions','oci',
  'high','OCI Functions: Create Function','Detected CreateFunction on Functions via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateFunction','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.c46be866','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"DeleteFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.c46be866','com.oraclecloud.functions','oci',
  'high','OCI Functions: Delete Function','Detected DeleteFunction on Functions via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteFunction','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.functions.4adb78ab','com.oraclecloud.functions','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.functions"},{"op":"equals","field":"operation","value":"UpdateFunction"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.functions.4adb78ab','com.oraclecloud.functions','oci',
  'medium','OCI Functions: Update Function','Detected UpdateFunction on Functions via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateFunction','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.87425979','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"CreateStream"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.87425979','com.oraclecloud.streaming','oci',
  'high','OCI Streams: Create OCI Stream','Detected CreateStream on Streams via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateStream','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.2d220a68','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"DeleteStream"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.2d220a68','com.oraclecloud.streaming','oci',
  'high','OCI Streams: Delete OCI Stream','Detected DeleteStream on Streams via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteStream','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.2f701481','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"UpdateStream"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.2f701481','com.oraclecloud.streaming','oci',
  'medium','OCI Streams: Update OCI Stream','Detected UpdateStream on Streams via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateStream','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.413896cf','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"CreateStreamPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.413896cf','com.oraclecloud.streaming','oci',
  'high','OCI Stream Pools: Create Stream Pool','Detected CreateStreamPool on Stream Pools via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateStreamPool','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.611ff9bf','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"DeleteStreamPool"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.611ff9bf','com.oraclecloud.streaming','oci',
  'high','OCI Stream Pools: Delete Stream Pool','Detected DeleteStreamPool on Stream Pools via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteStreamPool','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.streaming.7a031a26','com.oraclecloud.streaming','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.streaming"},{"op":"equals","field":"operation","value":"CreateConnectHarness"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.streaming.7a031a26','com.oraclecloud.streaming','oci',
  'high','OCI Connect Harnesses: Create Kafka Connect Harness','Detected CreateConnectHarness on Connect Harnesses via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateConnectHarness','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.sch.c53216c0','com.oraclecloud.serviceconnector','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.serviceconnector"},{"op":"equals","field":"operation","value":"UpdateServiceConnector"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.sch.c53216c0','com.oraclecloud.serviceconnector','oci',
  'medium','OCI Service Connectors: Update Service Connector','Detected UpdateServiceConnector on Service Connectors via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateServiceConnector','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.sch.bad26eba','com.oraclecloud.serviceconnector','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.serviceconnector"},{"op":"equals","field":"operation","value":"DeleteServiceConnector"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.sch.bad26eba','com.oraclecloud.serviceconnector','oci',
  'high','OCI Service Connectors: Delete Service Connector','Detected DeleteServiceConnector on Service Connectors via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteServiceConnector','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.ons.2a87cf5c','com.oraclecloud.ons','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.ons"},{"op":"equals","field":"operation","value":"CreateTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.ons.2a87cf5c','com.oraclecloud.ons','oci',
  'high','OCI Notification Topics: Create Notification Topic','Detected CreateTopic on Notification Topics via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateTopic','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.ons.6f1a47ab','com.oraclecloud.ons','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.ons"},{"op":"equals","field":"operation","value":"DeleteTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.ons.6f1a47ab','com.oraclecloud.ons','oci',
  'high','OCI Notification Topics: Delete Notification Topic','Detected DeleteTopic on Notification Topics via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteTopic','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.ons.47c1d8bf','com.oraclecloud.ons','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.ons"},{"op":"equals","field":"operation","value":"UpdateTopic"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.ons.47c1d8bf','com.oraclecloud.ons','oci',
  'medium','OCI Notification Topics: Update Notification Topic','Detected UpdateTopic on Notification Topics via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateTopic','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.ons.0e10cbcd','com.oraclecloud.ons','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.ons"},{"op":"equals","field":"operation","value":"CreateSubscription"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.ons.0e10cbcd','com.oraclecloud.ons','oci',
  'high','OCI Subscriptions: Create Notification Subscription','Detected CreateSubscription on Subscriptions via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSubscription','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.ons.451412db','com.oraclecloud.ons','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.ons"},{"op":"equals","field":"operation","value":"DeleteSubscription"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.ons.451412db','com.oraclecloud.ons','oci',
  'high','OCI Subscriptions: Delete Notification Subscription','Detected DeleteSubscription on Subscriptions via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteSubscription','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.monitoring.833ea0ec','com.oraclecloud.monitoring','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.monitoring"},{"op":"equals","field":"operation","value":"CreateAlarm"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.monitoring.833ea0ec','com.oraclecloud.monitoring','oci',
  'high','OCI Alarms: Create Monitoring Alarm','Detected CreateAlarm on Alarms via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateAlarm','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.monitoring.db0659b9','com.oraclecloud.monitoring','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.monitoring"},{"op":"equals","field":"operation","value":"DeleteAlarm"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.monitoring.db0659b9','com.oraclecloud.monitoring','oci',
  'high','OCI Alarms: Delete Monitoring Alarm','Detected DeleteAlarm on Alarms via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteAlarm','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.monitoring.44df58ae','com.oraclecloud.monitoring','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.monitoring"},{"op":"equals","field":"operation","value":"UpdateAlarm"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.monitoring.44df58ae','com.oraclecloud.monitoring','oci',
  'medium','OCI Alarms: Update Monitoring Alarm','Detected UpdateAlarm on Alarms via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateAlarm','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.monitoring.471ed4db','com.oraclecloud.monitoring','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.monitoring"},{"op":"equals","field":"operation","value":"SuppressAlarm"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.monitoring.471ed4db','com.oraclecloud.monitoring','oci',
  'medium','OCI Alarms: Suppress Monitoring Alarm','Detected SuppressAlarm on Alarms via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'SuppressAlarm','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.363c1810','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"CreateLogGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.363c1810','com.oraclecloud.logging','oci',
  'high','OCI Log Groups: Create Log Group','Detected CreateLogGroup on Log Groups via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateLogGroup','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.c7923247','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"DeleteLogGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.c7923247','com.oraclecloud.logging','oci',
  'high','OCI Log Groups: Delete Log Group','Detected DeleteLogGroup on Log Groups via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteLogGroup','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.a230faa7','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"UpdateLogGroup"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.a230faa7','com.oraclecloud.logging','oci',
  'medium','OCI Log Groups: Update Log Group','Detected UpdateLogGroup on Log Groups via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateLogGroup','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.bb070b49','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"CreateLog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.bb070b49','com.oraclecloud.logging','oci',
  'high','OCI Logs: Create Log','Detected CreateLog on Logs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateLog','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.746ac5f0','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"DeleteLog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.746ac5f0','com.oraclecloud.logging','oci',
  'high','OCI Logs: Delete Log','Detected DeleteLog on Logs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteLog','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.logging.c5546889','com.oraclecloud.logging','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.logging"},{"op":"equals","field":"operation","value":"UpdateLog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.logging.c5546889','com.oraclecloud.logging','oci',
  'medium','OCI Logs: Update Log','Detected UpdateLog on Logs via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateLog','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.resourcemanager.ed606cb7','com.oraclecloud.resourcemanager','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.resourcemanager"},{"op":"equals","field":"operation","value":"CreateStack"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.resourcemanager.ed606cb7','com.oraclecloud.resourcemanager','oci',
  'high','OCI Stacks: Create Resource Manager Stack','Detected CreateStack on Stacks via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateStack','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.resourcemanager.ae9826f9','com.oraclecloud.resourcemanager','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.resourcemanager"},{"op":"equals","field":"operation","value":"DeleteStack"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.resourcemanager.ae9826f9','com.oraclecloud.resourcemanager','oci',
  'high','OCI Stacks: Delete Resource Manager Stack','Detected DeleteStack on Stacks via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteStack','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.resourcemanager.a46d8ecc','com.oraclecloud.resourcemanager','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.resourcemanager"},{"op":"equals","field":"operation","value":"UpdateStack"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.resourcemanager.a46d8ecc','com.oraclecloud.resourcemanager','oci',
  'medium','OCI Stacks: Update Resource Manager Stack','Detected UpdateStack on Stacks via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateStack','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.resourcemanager.f8a26706','com.oraclecloud.resourcemanager','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.resourcemanager"},{"op":"equals","field":"operation","value":"CancelJob"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.resourcemanager.f8a26706','com.oraclecloud.resourcemanager','oci',
  'high','OCI Jobs: Cancel Resource Manager Job','Detected CancelJob on Jobs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'CancelJob','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.events.da861876','com.oraclecloud.events','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.events"},{"op":"equals","field":"operation","value":"UpdateRule"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.events.da861876','com.oraclecloud.events','oci',
  'medium','OCI Event Rules: Update Events Rule','Detected UpdateRule on Event Rules via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateRule','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.events.c85227e0','com.oraclecloud.events','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.events"},{"op":"equals","field":"operation","value":"DeleteRule"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.events.c85227e0','com.oraclecloud.events','oci',
  'high','OCI Event Rules: Delete Events Rule','Detected DeleteRule on Event Rules via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteRule','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.redis.f1cb5e99','com.oraclecloud.redis','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.redis"},{"op":"equals","field":"operation","value":"CreateRedisCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.redis.f1cb5e99','com.oraclecloud.redis','oci',
  'high','OCI Redis Clusters: Create OCI Redis Cluster','Detected CreateRedisCluster on Redis Clusters via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateRedisCluster','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.redis.6cacb232','com.oraclecloud.redis','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.redis"},{"op":"equals","field":"operation","value":"DeleteRedisCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.redis.6cacb232','com.oraclecloud.redis','oci',
  'high','OCI Redis Clusters: Delete OCI Redis Cluster','Detected DeleteRedisCluster on Redis Clusters via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteRedisCluster','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.redis.84820f61','com.oraclecloud.redis','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.redis"},{"op":"equals","field":"operation","value":"UpdateRedisCluster"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.redis.84820f61','com.oraclecloud.redis','oci',
  'medium','OCI Redis Clusters: Update OCI Redis Cluster','Detected UpdateRedisCluster on Redis Clusters via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateRedisCluster','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.ac2827f9','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"CreateVault"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.ac2827f9','com.oraclecloud.vaultmng','oci',
  'high','OCI Vaults: Create OCI Vault','Detected CreateVault on Vaults via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateVault','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.0c62d2e1','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"UpdateVault"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.0c62d2e1','com.oraclecloud.vaultmng','oci',
  'medium','OCI Vaults: Update OCI Vault','Detected UpdateVault on Vaults via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateVault','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.d7356c3f','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"CreateKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.d7356c3f','com.oraclecloud.vaultmng','oci',
  'high','OCI Keys: Create Vault Key','Detected CreateKey on Keys via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateKey','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.2d796d44','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"UpdateKey"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.2d796d44','com.oraclecloud.vaultmng','oci',
  'medium','OCI Keys: Update Vault Key','Detected UpdateKey on Keys via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateKey','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.9381e22e','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"CreateSecret"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.9381e22e','com.oraclecloud.vaultmng','oci',
  'high','OCI Secrets: Create Vault Secret','Detected CreateSecret on Secrets via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateSecret','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.vault.533939f8','com.oraclecloud.vaultmng','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.vaultmng"},{"op":"equals","field":"operation","value":"UpdateSecret"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.vault.533939f8','com.oraclecloud.vaultmng','oci',
  'medium','OCI Secrets: Update Vault Secret','Detected UpdateSecret on Secrets via OCI Audit Logs.',
  'persistence','modify','oci_audit',
  'UpdateSecret','modify',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1098"]',55,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datacatalog.fc4c2e4e','com.oraclecloud.datacatalog','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datacatalog"},{"op":"equals","field":"operation","value":"CreateCatalog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datacatalog.fc4c2e4e','com.oraclecloud.datacatalog','oci',
  'high','OCI Data Catalogs: Create Data Catalog','Detected CreateCatalog on Data Catalogs via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateCatalog','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datacatalog.a24483ab','com.oraclecloud.datacatalog','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datacatalog"},{"op":"equals","field":"operation","value":"DeleteCatalog"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datacatalog.a24483ab','com.oraclecloud.datacatalog','oci',
  'high','OCI Data Catalogs: Delete Data Catalog','Detected DeleteCatalog on Data Catalogs via OCI Audit Logs.',
  'impact','delete','oci_audit',
  'DeleteCatalog','delete',
  'log','{"ciem_engine"}','ciem_engine',
  '["impact"]','["T1485"]',75,'auto','oci'
) ON CONFLICT DO NOTHING;

INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)
VALUES ('log.oci.datacatalog.2e300971','com.oraclecloud.datacatalog','oci','log',true,'{"conditions":{"all":[{"op":"equals","field":"source_type","value":"oci_audit"},{"op":"equals","field":"service","value":"com.oraclecloud.datacatalog"},{"op":"equals","field":"operation","value":"CreateConnection"}]}}')
ON CONFLICT DO NOTHING;

INSERT INTO rule_metadata (
  rule_id,service,provider,severity,title,description,
  domain,subcategory,log_source_type,audit_log_event,action_category,
  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp
) VALUES (
  'log.oci.datacatalog.2e300971','com.oraclecloud.datacatalog','oci',
  'high','OCI Data Connections: Create Data Catalog Connection','Detected CreateConnection on Data Connections via OCI Audit Logs.',
  'persistence','create','oci_audit',
  'CreateConnection','create',
  'log','{"ciem_engine"}','ciem_engine',
  '["persistence"]','["T1136"]',70,'auto','oci'
) ON CONFLICT DO NOTHING;

