-- =============================================================================
-- Seed: rule_discoveries for New Engine Data Sources (Category A)
-- =============================================================================
-- Generated for: engine_container, engine_network, engine_supplychain, engine_api
-- Target table:  rule_discoveries (threat_engine_check database)
-- Pattern:       UPSERT — ON CONFLICT updates existing rows
-- Reference:     PROJECT_PLAN.md Tasks 0.1.1–0.1.12
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Task 0.1.1 [Seq 1 | BD]: Seed ECR Image Discovery
-- Consumed by: engine_container (Stage 1 ETL), engine_supplychain (SBOM)
-- Resource types: aws.ecr.repository, aws.ecr.image
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('ecr', 'aws',
     '[
       {
         "discovery_id": "aws.ecr.describe_repositories",
         "calls": [
           {
             "action": "describe_repositories",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.repositories }}",
           "as": "item",
           "item": {
             "repositoryName": "{{ item.repositoryName }}",
             "repositoryArn": "{{ item.repositoryArn }}",
             "registryId": "{{ item.registryId }}",
             "repositoryUri": "{{ item.repositoryUri }}",
             "createdAt": "{{ item.createdAt }}",
             "imageScanningConfiguration": "{{ item.imageScanningConfiguration }}",
             "imageTagMutability": "{{ item.imageTagMutability }}",
             "encryptionConfiguration": "{{ item.encryptionConfiguration }}"
           }
         }
       },
       {
         "discovery_id": "aws.ecr.describe_images",
         "calls": [
           {
             "action": "describe_images",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.imageDetails }}",
           "as": "item",
           "item": {
             "repositoryName": "{{ item.repositoryName }}",
             "registryId": "{{ item.registryId }}",
             "imageDigest": "{{ item.imageDigest }}",
             "imageTags": "{{ item.imageTags }}",
             "imageSizeInBytes": "{{ item.imageSizeInBytes }}",
             "imagePushedAt": "{{ item.imagePushedAt }}",
             "imageScanStatus": "{{ item.imageScanStatus }}",
             "imageScanFindingsSummary": "{{ item.imageScanFindingsSummary }}"
           }
         }
       }
     ]'::jsonb,
     'ecr',
     'arn:aws:ecr:{region}:{account_id}:repository/{repository_name}',
     ARRAY['describe_repositories'],
     ARRAY['describe_images'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.2 [Seq 1 | BD]: Seed K8s Workload Discovery
-- Consumed by: engine_container (pod security context, image inventory)
-- Resource types: aws.eks.pod, aws.eks.deployment, aws.eks.daemonset
-- Note: Uses Kubernetes client pattern — boto3_client_name stores 'eks'
--       for cluster enumeration; K8s API calls are handled by discovery
--       engine's K8s adapter using cluster endpoint + IRSA token.
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('eks_workloads', 'aws',
     '[
       {
         "discovery_id": "aws.eks.list_pods",
         "calls": [
           {
             "action": "list_pod_for_all_namespaces",
             "params": {},
             "save_as": "response",
             "on_error": "continue",
             "client_type": "kubernetes"
           }
         ],
         "emit": {
           "items_for": "{{ response.items }}",
           "as": "item",
           "item": {
             "namespace": "{{ item.metadata.namespace }}",
             "podName": "{{ item.metadata.name }}",
             "clusterName": "{{ cluster.name }}",
             "nodeName": "{{ item.spec.nodeName }}",
             "phase": "{{ item.status.phase }}",
             "serviceAccount": "{{ item.spec.serviceAccountName }}",
             "containers": "{{ item.spec.containers }}",
             "hostNetwork": "{{ item.spec.hostNetwork }}",
             "hostPID": "{{ item.spec.hostPID }}"
           }
         }
       },
       {
         "discovery_id": "aws.eks.list_deployments",
         "calls": [
           {
             "action": "list_deployment_for_all_namespaces",
             "params": {},
             "save_as": "response",
             "on_error": "continue",
             "client_type": "kubernetes"
           }
         ],
         "emit": {
           "items_for": "{{ response.items }}",
           "as": "item",
           "item": {
             "namespace": "{{ item.metadata.namespace }}",
             "deploymentName": "{{ item.metadata.name }}",
             "clusterName": "{{ cluster.name }}",
             "replicas": "{{ item.spec.replicas }}",
             "containers": "{{ item.spec.template.spec.containers }}",
             "serviceAccount": "{{ item.spec.template.spec.serviceAccountName }}"
           }
         }
       },
       {
         "discovery_id": "aws.eks.list_daemonsets",
         "calls": [
           {
             "action": "list_daemon_set_for_all_namespaces",
             "params": {},
             "save_as": "response",
             "on_error": "continue",
             "client_type": "kubernetes"
           }
         ],
         "emit": {
           "items_for": "{{ response.items }}",
           "as": "item",
           "item": {
             "namespace": "{{ item.metadata.namespace }}",
             "daemonsetName": "{{ item.metadata.name }}",
             "clusterName": "{{ cluster.name }}",
             "containers": "{{ item.spec.template.spec.containers }}",
             "serviceAccount": "{{ item.spec.template.spec.serviceAccountName }}"
           }
         }
       }
     ]'::jsonb,
     'eks',
     'arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}',
     ARRAY[]::TEXT[],
     ARRAY['list_pod_for_all_namespaces', 'list_deployment_for_all_namespaces', 'list_daemon_set_for_all_namespaces'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.3 [Seq 1 | BD]: Seed ECS Task Definition Discovery
-- Consumed by: engine_container (image/security context), engine_supplychain (manifest refs)
-- Resource types: aws.ecs.task_definition
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('ecs_task_definitions', 'aws',
     '[
       {
         "discovery_id": "aws.ecs.list_task_definitions",
         "calls": [
           {
             "action": "list_task_definitions",
             "params": {
               "status": "ACTIVE"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.taskDefinitionArns }}",
           "as": "item"
         }
       },
       {
         "discovery_id": "aws.ecs.describe_task_definition",
         "calls": [
           {
             "action": "describe_task_definition",
             "params": {
               "taskDefinition": "{{ parent }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response.taskDefinition }}]",
           "as": "item",
           "item": {
             "taskDefinitionArn": "{{ item.taskDefinitionArn }}",
             "family": "{{ item.family }}",
             "revision": "{{ item.revision }}",
             "containerDefinitions": "{{ item.containerDefinitions }}",
             "executionRoleArn": "{{ item.executionRoleArn }}",
             "taskRoleArn": "{{ item.taskRoleArn }}",
             "requiresCompatibilities": "{{ item.requiresCompatibilities }}",
             "networkMode": "{{ item.networkMode }}",
             "cpu": "{{ item.cpu }}",
             "memory": "{{ item.memory }}"
           }
         }
       }
     ]'::jsonb,
     'ecs',
     'arn:aws:ecs:{region}:{account_id}:task-definition/{family}:{revision}',
     ARRAY['list_task_definitions'],
     ARRAY['describe_task_definition'],
     '{"api_filters": [{"discovery_id": "aws.ecs.list_task_definitions", "parameter": "status", "value": "ACTIVE", "priority": 10, "description": "Only return active task definitions"}], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.4 [Seq 1 | BD]: Seed Lambda Code Location Discovery
-- Consumed by: engine_supplychain (Stage 1 ETL: download ZIP, extract manifests)
-- Resource types: aws.lambda.function_code
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('lambda_code', 'aws',
     '[
       {
         "discovery_id": "aws.lambda.list_functions",
         "calls": [
           {
             "action": "list_functions",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.Functions }}",
           "as": "item",
           "item": {
             "functionName": "{{ item.FunctionName }}",
             "functionArn": "{{ item.FunctionArn }}",
             "runtime": "{{ item.Runtime }}",
             "codeSize": "{{ item.CodeSize }}",
             "lastModified": "{{ item.LastModified }}"
           }
         }
       },
       {
         "discovery_id": "aws.lambda.get_function",
         "calls": [
           {
             "action": "get_function",
             "params": {
               "FunctionName": "{{ parent.functionName }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response }}]",
           "as": "item",
           "item": {
             "functionName": "{{ item.Configuration.FunctionName }}",
             "functionArn": "{{ item.Configuration.FunctionArn }}",
             "runtime": "{{ item.Configuration.Runtime }}",
             "codeLocation": {
               "repositoryType": "{{ item.Code.RepositoryType }}",
               "location": "{{ item.Code.Location }}"
             },
             "codeSize": "{{ item.Configuration.CodeSize }}",
             "lastModified": "{{ item.Configuration.LastModified }}",
             "layers": "{{ item.Configuration.Layers }}",
             "environment": "{{ item.Configuration.Environment.Variables | keys }}"
           }
         }
       }
     ]'::jsonb,
     'lambda',
     'arn:aws:lambda:{region}:{account_id}:function:{function_name}',
     ARRAY['list_functions'],
     ARRAY['get_function'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.5 [Seq 1 | BD]: Seed API Gateway Detailed Config Discovery
-- Consumed by: engine_api (Stage 1 ETL: unified API inventory)
-- Resource types: aws.apigateway.rest_api, aws.apigateway.stage,
--                 aws.apigateway.authorizer, aws.apigatewayv2.api, aws.apigatewayv2.route
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('apigateway_config', 'aws',
     '[
       {
         "discovery_id": "aws.apigateway.get_rest_apis",
         "calls": [
           {
             "action": "get_rest_apis",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.items }}",
           "as": "item",
           "item": {
             "id": "{{ item.id }}",
             "name": "{{ item.name }}",
             "apiType": "REST",
             "description": "{{ item.description }}",
             "createdDate": "{{ item.createdDate }}",
             "apiKeySource": "{{ item.apiKeySource }}",
             "endpointConfiguration": "{{ item.endpointConfiguration }}",
             "minimumCompressionSize": "{{ item.minimumCompressionSize }}"
           }
         }
       },
       {
         "discovery_id": "aws.apigateway.get_stages",
         "calls": [
           {
             "action": "get_stages",
             "params": {
               "restApiId": "{{ parent.id }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.item }}",
           "as": "item",
           "item": {
             "restApiId": "{{ parent.id }}",
             "stageName": "{{ item.stageName }}",
             "deploymentId": "{{ item.deploymentId }}",
             "cacheClusterEnabled": "{{ item.cacheClusterEnabled }}",
             "cacheClusterSize": "{{ item.cacheClusterSize }}",
             "tracingEnabled": "{{ item.tracingEnabled }}",
             "accessLogSettings": "{{ item.accessLogSettings }}",
             "methodSettings": "{{ item.methodSettings }}",
             "webAclArn": "{{ item.webAclArn }}"
           }
         }
       },
       {
         "discovery_id": "aws.apigateway.get_authorizers",
         "calls": [
           {
             "action": "get_authorizers",
             "params": {
               "restApiId": "{{ parent.id }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.items }}",
           "as": "item",
           "item": {
             "restApiId": "{{ parent.id }}",
             "authorizerId": "{{ item.id }}",
             "authorizerName": "{{ item.name }}",
             "authType": "{{ item.type }}",
             "authorizerResultTtlInSeconds": "{{ item.authorizerResultTtlInSeconds }}",
             "providerARNs": "{{ item.providerARNs }}"
           }
         }
       },
       {
         "discovery_id": "aws.apigatewayv2.get_apis",
         "calls": [
           {
             "action": "get_apis",
             "params": {},
             "save_as": "response",
             "on_error": "continue",
             "client_override": "apigatewayv2"
           }
         ],
         "emit": {
           "items_for": "{{ response.Items }}",
           "as": "item",
           "item": {
             "apiId": "{{ item.ApiId }}",
             "name": "{{ item.Name }}",
             "apiType": "{{ item.ProtocolType }}",
             "apiEndpoint": "{{ item.ApiEndpoint }}",
             "corsConfiguration": "{{ item.CorsConfiguration }}",
             "disableExecuteApiEndpoint": "{{ item.DisableExecuteApiEndpoint }}"
           }
         }
       },
       {
         "discovery_id": "aws.apigatewayv2.get_routes",
         "calls": [
           {
             "action": "get_routes",
             "params": {
               "ApiId": "{{ parent.apiId }}"
             },
             "save_as": "response",
             "on_error": "continue",
             "client_override": "apigatewayv2"
           }
         ],
         "emit": {
           "items_for": "{{ response.Items }}",
           "as": "item",
           "item": {
             "apiId": "{{ parent.apiId }}",
             "routeId": "{{ item.RouteId }}",
             "routeKey": "{{ item.RouteKey }}",
             "authorizationType": "{{ item.AuthorizationType }}",
             "authorizerId": "{{ item.AuthorizerId }}",
             "apiKeyRequired": "{{ item.ApiKeyRequired }}"
           }
         }
       }
     ]'::jsonb,
     'apigateway',
     'arn:aws:apigateway:{region}::/restapis/{api_id}',
     ARRAY['get_rest_apis'],
     ARRAY['get_stages', 'get_authorizers', 'get_routes'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.6 [Seq 1 | BD]: Seed ALB Listeners & Rules Discovery
-- Consumed by: engine_api (TLS version), engine_network (exposed ports, WAF)
-- Resource types: aws.elbv2.load_balancer, aws.elbv2.listener, aws.elbv2.listener_rule
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('elbv2_listeners', 'aws',
     '[
       {
         "discovery_id": "aws.elbv2.describe_load_balancers",
         "calls": [
           {
             "action": "describe_load_balancers",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.LoadBalancers }}",
           "as": "item",
           "item": {
             "loadBalancerArn": "{{ item.LoadBalancerArn }}",
             "loadBalancerName": "{{ item.LoadBalancerName }}",
             "type": "{{ item.Type }}",
             "scheme": "{{ item.Scheme }}",
             "state": "{{ item.State }}",
             "vpcId": "{{ item.VpcId }}",
             "securityGroups": "{{ item.SecurityGroups }}",
             "availabilityZones": "{{ item.AvailabilityZones }}"
           }
         }
       },
       {
         "discovery_id": "aws.elbv2.describe_listeners",
         "calls": [
           {
             "action": "describe_listeners",
             "params": {
               "LoadBalancerArn": "{{ parent.loadBalancerArn }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.Listeners }}",
           "as": "item",
           "item": {
             "listenerArn": "{{ item.ListenerArn }}",
             "loadBalancerArn": "{{ parent.loadBalancerArn }}",
             "loadBalancerName": "{{ parent.loadBalancerName }}",
             "port": "{{ item.Port }}",
             "protocol": "{{ item.Protocol }}",
             "sslPolicy": "{{ item.SslPolicy }}",
             "certificates": "{{ item.Certificates }}",
             "defaultActions": "{{ item.DefaultActions }}"
           }
         }
       },
       {
         "discovery_id": "aws.elbv2.describe_rules",
         "calls": [
           {
             "action": "describe_rules",
             "params": {
               "ListenerArn": "{{ parent.listenerArn }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.Rules }}",
           "as": "item",
           "item": {
             "ruleArn": "{{ item.RuleArn }}",
             "listenerArn": "{{ parent.listenerArn }}",
             "priority": "{{ item.Priority }}",
             "conditions": "{{ item.Conditions }}",
             "actions": "{{ item.Actions }}",
             "isDefault": "{{ item.IsDefault }}"
           }
         }
       }
     ]'::jsonb,
     'elbv2',
     'arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/app/{lb_name}/{lb_id}',
     ARRAY['describe_load_balancers'],
     ARRAY['describe_listeners', 'describe_rules'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.7 [Seq 1 | BD]: Seed WAF Web ACL Discovery
-- Consumed by: engine_api (WAF coverage), engine_network (WAF association)
-- Resource types: aws.wafv2.web_acl
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('wafv2', 'aws',
     '[
       {
         "discovery_id": "aws.wafv2.list_web_acls",
         "calls": [
           {
             "action": "list_web_acls",
             "params": {
               "Scope": "REGIONAL"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.WebACLs }}",
           "as": "item",
           "item": {
             "webAclId": "{{ item.Id }}",
             "webAclArn": "{{ item.ARN }}",
             "webAclName": "{{ item.Name }}",
             "scope": "REGIONAL",
             "lockToken": "{{ item.LockToken }}"
           }
         }
       },
       {
         "discovery_id": "aws.wafv2.get_web_acl",
         "calls": [
           {
             "action": "get_web_acl",
             "params": {
               "Name": "{{ parent.webAclName }}",
               "Scope": "REGIONAL",
               "Id": "{{ parent.webAclId }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response.WebACL }}]",
           "as": "item",
           "item": {
             "webAclId": "{{ item.Id }}",
             "webAclArn": "{{ item.ARN }}",
             "webAclName": "{{ item.Name }}",
             "scope": "REGIONAL",
             "defaultAction": "{{ item.DefaultAction }}",
             "rules": "{{ item.Rules }}",
             "visibilityConfig": "{{ item.VisibilityConfig }}",
             "capacity": "{{ item.Capacity }}"
           }
         }
       },
       {
         "discovery_id": "aws.wafv2.list_resources_for_web_acl",
         "calls": [
           {
             "action": "list_resources_for_web_acl",
             "params": {
               "WebACLArn": "{{ parent.webAclArn }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response }}]",
           "as": "item",
           "item": {
             "webAclArn": "{{ parent.webAclArn }}",
             "webAclName": "{{ parent.webAclName }}",
             "associatedResources": "{{ item.ResourceArns }}"
           }
         }
       }
     ]'::jsonb,
     'wafv2',
     'arn:aws:wafv2:{region}:{account_id}:regional/webacl/{name}/{id}',
     ARRAY['list_web_acls'],
     ARRAY['get_web_acl', 'list_resources_for_web_acl'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.8 [Seq 1 | BD]: Seed VPC Flow Log Config Discovery
-- Consumed by: engine_network (Stage 1 ETL: verify flow logging, join to log_events)
-- Resource types: aws.ec2.flow_log
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('vpc_flow_logs', 'aws',
     '[
       {
         "discovery_id": "aws.ec2.describe_flow_logs",
         "calls": [
           {
             "action": "describe_flow_logs",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.FlowLogs }}",
           "as": "item",
           "item": {
             "flowLogId": "{{ item.FlowLogId }}",
             "flowLogStatus": "{{ item.FlowLogStatus }}",
             "resourceId": "{{ item.ResourceId }}",
             "resourceType": "{{ item.ResourceType }}",
             "trafficType": "{{ item.TrafficType }}",
             "logDestination": "{{ item.LogDestination }}",
             "logDestinationType": "{{ item.LogDestinationType }}",
             "logFormat": "{{ item.LogFormat }}",
             "creationTime": "{{ item.CreationTime }}",
             "deliverLogsStatus": "{{ item.DeliverLogsStatus }}",
             "maxAggregationInterval": "{{ item.MaxAggregationInterval }}",
             "tags": "{{ item.Tags }}"
           }
         }
       }
     ]'::jsonb,
     'ec2',
     'arn:aws:ec2:{region}:{account_id}:vpc-flow-log/{flow_log_id}',
     ARRAY['describe_flow_logs'],
     ARRAY[]::TEXT[],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.9 [Seq 1 | BD]: Seed CodeCommit Repositories & Manifest Files Discovery
-- Consumed by: engine_supplychain (Stage 1 ETL: parse manifests, cross-ref vuln_cache)
-- Resource types: aws.codecommit.repository, aws.codecommit.manifest_file
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('codecommit', 'aws',
     '[
       {
         "discovery_id": "aws.codecommit.list_repositories",
         "calls": [
           {
             "action": "list_repositories",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.repositories }}",
           "as": "item",
           "item": {
             "repositoryId": "{{ item.repositoryId }}",
             "repositoryName": "{{ item.repositoryName }}"
           }
         }
       },
       {
         "discovery_id": "aws.codecommit.get_repository",
         "calls": [
           {
             "action": "get_repository",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response.repositoryMetadata }}]",
           "as": "item",
           "item": {
             "repositoryName": "{{ item.repositoryName }}",
             "repositoryArn": "{{ item.Arn }}",
             "cloneUrlHttps": "{{ item.cloneUrlHttp }}",
             "defaultBranch": "{{ item.defaultBranch }}",
             "creationDate": "{{ item.creationDate }}"
           }
         }
       },
       {
         "discovery_id": "aws.codecommit.get_manifest_files",
         "calls": [
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "package.json"
             },
             "save_as": "package_json",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "requirements.txt"
             },
             "save_as": "requirements_txt",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "go.mod"
             },
             "save_as": "go_mod",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "pom.xml"
             },
             "save_as": "pom_xml",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "Gemfile"
             },
             "save_as": "gemfile",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "Cargo.toml"
             },
             "save_as": "cargo_toml",
             "on_error": "continue"
           },
           {
             "action": "get_file",
             "params": {
               "repositoryName": "{{ parent.repositoryName }}",
               "filePath": "composer.json"
             },
             "save_as": "composer_json",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ package_json }}, {{ requirements_txt }}, {{ go_mod }}, {{ pom_xml }}, {{ gemfile }}, {{ cargo_toml }}, {{ composer_json }}]",
           "as": "item",
           "item": {
             "repositoryName": "{{ parent.repositoryName }}",
             "filePath": "{{ item.filePath }}",
             "fileContent": "{{ item.fileContent }}",
             "commitId": "{{ item.commitId }}",
             "blobId": "{{ item.blobId }}"
           }
         }
       }
     ]'::jsonb,
     'codecommit',
     'arn:aws:codecommit:{region}:{account_id}:{repository_name}',
     ARRAY['list_repositories'],
     ARRAY['get_repository', 'get_file'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.10 [Seq 1 | BD]: Seed CodeArtifact Packages Discovery
-- Consumed by: engine_supplychain (dependency confusion detection)
-- Resource types: aws.codeartifact.repository, aws.codeartifact.package
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('codeartifact', 'aws',
     '[
       {
         "discovery_id": "aws.codeartifact.list_domains",
         "calls": [
           {
             "action": "list_domains",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.domains }}",
           "as": "item",
           "item": {
             "domainName": "{{ item.name }}",
             "domainArn": "{{ item.arn }}",
             "domainOwner": "{{ item.owner }}",
             "status": "{{ item.status }}"
           }
         }
       },
       {
         "discovery_id": "aws.codeartifact.list_repositories",
         "calls": [
           {
             "action": "list_repositories",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.repositories }}",
           "as": "item",
           "item": {
             "repositoryName": "{{ item.name }}",
             "repositoryArn": "{{ item.arn }}",
             "domainName": "{{ item.domainName }}",
             "domainOwner": "{{ item.domainOwner }}",
             "description": "{{ item.description }}"
           }
         }
       },
       {
         "discovery_id": "aws.codeartifact.list_packages",
         "calls": [
           {
             "action": "list_packages",
             "params": {
               "domain": "{{ parent.domainName }}",
               "repository": "{{ parent.repositoryName }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.packages }}",
           "as": "item",
           "item": {
             "packageName": "{{ item.package }}",
             "format": "{{ item.format }}",
             "namespace": "{{ item.namespace }}",
             "domainName": "{{ parent.domainName }}",
             "repositoryName": "{{ parent.repositoryName }}",
             "originConfiguration": "{{ item.originConfiguration }}"
           }
         }
       }
     ]'::jsonb,
     'codeartifact',
     'arn:aws:codeartifact:{region}:{account_id}:repository/{domain}/{repository}',
     ARRAY['list_domains', 'list_repositories'],
     ARRAY['list_packages'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.11 [Seq 1 | BD]: Seed AppSync GraphQL API Discovery
-- Consumed by: engine_api (auth type inventory, logging verification)
-- Resource types: aws.appsync.graphql_api
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('appsync', 'aws',
     '[
       {
         "discovery_id": "aws.appsync.list_graphql_apis",
         "calls": [
           {
             "action": "list_graphql_apis",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.graphqlApis }}",
           "as": "item",
           "item": {
             "apiId": "{{ item.apiId }}",
             "apiName": "{{ item.name }}",
             "apiArn": "{{ item.arn }}",
             "authenticationType": "{{ item.authenticationType }}",
             "additionalAuthenticationProviders": "{{ item.additionalAuthenticationProviders }}",
             "logConfig": "{{ item.logConfig }}",
             "wafWebAclArn": "{{ item.wafWebAclArn }}",
             "xrayEnabled": "{{ item.xrayEnabled }}",
             "uris": "{{ item.uris }}"
           }
         }
       },
       {
         "discovery_id": "aws.appsync.get_graphql_api",
         "calls": [
           {
             "action": "get_graphql_api",
             "params": {
               "apiId": "{{ parent.apiId }}"
             },
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "[{{ response.graphqlApi }}]",
           "as": "item",
           "item": {
             "apiId": "{{ item.apiId }}",
             "apiName": "{{ item.name }}",
             "authenticationType": "{{ item.authenticationType }}",
             "logConfig": "{{ item.logConfig }}",
             "userPoolConfig": "{{ item.userPoolConfig }}",
             "openIDConnectConfig": "{{ item.openIDConnectConfig }}",
             "lambdaAuthorizerConfig": "{{ item.lambdaAuthorizerConfig }}",
             "wafWebAclArn": "{{ item.wafWebAclArn }}",
             "xrayEnabled": "{{ item.xrayEnabled }}"
           }
         }
       }
     ]'::jsonb,
     'appsync',
     'arn:aws:appsync:{region}:{account_id}:apis/{api_id}',
     ARRAY['list_graphql_apis'],
     ARRAY['get_graphql_api'],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- ---------------------------------------------------------------------------
-- Task 0.1.12 [Seq 1 | BD]: Seed CloudWatch Log Groups Discovery
-- Consumed by: engine_api (verify log groups), engine_network (flow log groups)
-- Resource types: aws.logs.log_group
-- ---------------------------------------------------------------------------
INSERT INTO rule_discoveries
    (service, provider, discoveries_data, boto3_client_name,
     arn_identifier, arn_identifier_independent_methods, arn_identifier_dependent_methods,
     filter_rules, source, generated_by, is_active, updated_at)
VALUES
    ('cloudwatch_logs', 'aws',
     '[
       {
         "discovery_id": "aws.logs.describe_log_groups",
         "calls": [
           {
             "action": "describe_log_groups",
             "params": {},
             "save_as": "response",
             "on_error": "continue"
           }
         ],
         "emit": {
           "items_for": "{{ response.logGroups }}",
           "as": "item",
           "item": {
             "logGroupName": "{{ item.logGroupName }}",
             "logGroupArn": "{{ item.arn }}",
             "creationTime": "{{ item.creationTime }}",
             "retentionInDays": "{{ item.retentionInDays }}",
             "storedBytes": "{{ item.storedBytes }}",
             "kmsKeyId": "{{ item.kmsKeyId }}",
             "dataProtectionStatus": "{{ item.dataProtectionStatus }}"
           }
         }
       }
     ]'::jsonb,
     'logs',
     'arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}',
     ARRAY['describe_log_groups'],
     ARRAY[]::TEXT[],
     '{"api_filters": [], "response_filters": []}'::jsonb,
     'seed', 'seed_new_engines', TRUE, NOW())
ON CONFLICT (service, provider, customer_id, tenant_id) DO UPDATE SET
    discoveries_data  = EXCLUDED.discoveries_data,
    boto3_client_name = EXCLUDED.boto3_client_name,
    arn_identifier    = EXCLUDED.arn_identifier,
    arn_identifier_independent_methods = EXCLUDED.arn_identifier_independent_methods,
    arn_identifier_dependent_methods   = EXCLUDED.arn_identifier_dependent_methods,
    filter_rules      = EXCLUDED.filter_rules,
    is_active         = TRUE,
    updated_at        = NOW();

-- =============================================================================
-- END: 12 discovery seeds for new engines
-- Total: 12 INSERT statements (one per new service discovery)
-- Services: ecr, eks_workloads, ecs_task_definitions, lambda_code,
--           apigateway_config, elbv2_listeners, wafv2, vpc_flow_logs,
--           codecommit, codeartifact, appsync, cloudwatch_logs
-- =============================================================================
