-- Migration: Enterprise Attack Path Relationship Rules
-- Version: 021
-- Date: 2026-04-07
-- Description:
--   Adds new resource_security_relationship_rules rows for enterprise attack path
--   coverage matching Wiz/Orca capabilities. Covers:
--     - Credential theft: Compute → SecretsManager / SSM Parameter Store
--     - KMS decrypt chain: Compute → KMS key
--     - AI/ML paths: Compute → Bedrock / SageMaker
--     - Supply chain: ECR → Lambda / ECS / EKS
--     - ECS task data access
--     - Cognito unauthenticated → IAM Role
--     - CloudFront → origin (S3/ALB) traversal
--     - API Gateway → S3 direct integration
--
--   Also adds new attack_path_category values to seed_attack_path_categories
--   for these relation types.
--
-- Target DB: threat_engine_inventory (resource_security_relationship_rules)

-- ============================================================================
-- 1. CREDENTIAL THEFT PATHS  (T1552, T1552.006)
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('ec2.instance',       'stores_data_in', 'secretsmanager.secret',    'credential_theft',    'EC2 → SecretsManager (IMDS role → GetSecretValue)',    TRUE, 20),
    ('lambda.function',    'stores_data_in', 'secretsmanager.secret',    'credential_theft',    'Lambda → SecretsManager credential access',            TRUE, 20),
    ('lambda.resource',    'stores_data_in', 'secretsmanager.secret',    'credential_theft',    'Lambda → SecretsManager credential access',            TRUE, 20),
    ('eks.cluster',        'stores_data_in', 'secretsmanager.secret',    'credential_theft',    'EKS → SecretsManager (pod role → GetSecretValue)',     TRUE, 20),
    ('ecs.task-definition','stores_data_in', 'secretsmanager.secret',    'credential_theft',    'ECS task → SecretsManager credential injection',      TRUE, 20),
    ('ec2.instance',       'stores_data_in', 'ssm.parameter',            'credential_theft',    'EC2 → SSM Parameter Store (GetParameter)',             TRUE, 20),
    ('lambda.function',    'stores_data_in', 'ssm.parameter',            'credential_theft',    'Lambda → SSM Parameter Store',                        TRUE, 20),
    ('eks.cluster',        'stores_data_in', 'ssm.parameter',            'credential_theft',    'EKS → SSM Parameter Store',                          TRUE, 20)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 2. KMS DECRYPT CHAIN  (T1485, T1552)
-- Compromise of KMS key unlocks all data encrypted with it.
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('ec2.instance',       'uses', 'kms.key',    'data_access', 'EC2 → KMS key (decrypt EBS/S3/RDS data)',            TRUE, 15),
    ('lambda.function',    'uses', 'kms.key',    'data_access', 'Lambda → KMS key (decrypt env vars / S3 objects)',   TRUE, 15),
    ('lambda.resource',    'uses', 'kms.key',    'data_access', 'Lambda → KMS key',                                   TRUE, 15),
    ('eks.cluster',        'uses', 'kms.key',    'data_access', 'EKS → KMS key (secrets envelope encryption)',        TRUE, 15),
    ('ecs.task-definition','uses', 'kms.key',    'data_access', 'ECS task → KMS key',                                 TRUE, 15),
    ('rds.instance',       'encrypted_by', 'kms.key', 'data_access', 'RDS encrypted by KMS — key = data access',     TRUE, 5),
    ('rds.cluster',        'encrypted_by', 'kms.key', 'data_access', 'RDS cluster encrypted by KMS',                 TRUE, 5),
    ('s3.resource',        'encrypted_by', 'kms.key', 'data_access', 'S3 encrypted by KMS key',                      TRUE, 5),
    ('dynamodb.table',     'encrypted_by', 'kms.key', 'data_access', 'DynamoDB encrypted by KMS key',                TRUE, 5)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 3. AI / ML PATHS  (T1565: data manipulation)
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('ec2.instance',       'invokes', 'bedrock.foundation-model',   'data_access', 'EC2 → Bedrock model invocation (prompt injection / exfil)', TRUE, 20),
    ('lambda.function',    'invokes', 'bedrock.foundation-model',   'data_access', 'Lambda → Bedrock model invocation',                         TRUE, 20),
    ('lambda.resource',    'invokes', 'bedrock.foundation-model',   'data_access', 'Lambda → Bedrock model invocation',                         TRUE, 20),
    ('eks.cluster',        'invokes', 'bedrock.foundation-model',   'data_access', 'EKS → Bedrock model invocation',                            TRUE, 20),
    ('ec2.instance',       'invokes', 'bedrock.agent',              'data_access', 'EC2 → Bedrock agent (orchestrated actions)',                TRUE, 20),
    ('lambda.function',    'invokes', 'bedrock.agent',              'data_access', 'Lambda → Bedrock agent',                                    TRUE, 20),
    ('ec2.instance',       'invokes', 'sagemaker.endpoint',         'data_access', 'EC2 → SageMaker inference endpoint',                        TRUE, 20),
    ('lambda.function',    'invokes', 'sagemaker.endpoint',         'data_access', 'Lambda → SageMaker inference endpoint',                     TRUE, 20),
    ('eks.cluster',        'invokes', 'sagemaker.endpoint',         'data_access', 'EKS → SageMaker endpoint',                                  TRUE, 20),
    ('ec2.instance',       'stores_data_in', 'sagemaker.notebook-instance', 'data_access', 'EC2 → SageMaker notebook (training data access)',   TRUE, 15),
    ('lambda.function',    'stores_data_in', 'sagemaker.training-job', 'data_access', 'Lambda → SageMaker training job',                       TRUE, 15)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 4. SUPPLY CHAIN / CONTAINER REGISTRY  (T1195.002, T1525)
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('ecr.repository',     'invokes', 'lambda.function',    'lateral_movement', 'ECR → Lambda (container image supply chain)',       TRUE, 25),
    ('ecr.repository',     'invokes', 'lambda.resource',    'lateral_movement', 'ECR → Lambda (container image supply chain)',       TRUE, 25),
    ('ecr.repository',     'invokes', 'ecs.task-definition','lateral_movement', 'ECR → ECS task (container image supply chain)',     TRUE, 25),
    ('ecr.repository',     'invokes', 'ecs.service',        'lateral_movement', 'ECR → ECS service (container image supply chain)', TRUE, 25),
    ('ecr.repository',     'invokes', 'eks.cluster',        'lateral_movement', 'ECR → EKS (container image supply chain)',          TRUE, 25),
    ('ecr.resource',       'invokes', 'lambda.function',    'lateral_movement', 'ECR → Lambda (supply chain)',                      TRUE, 25),
    ('ecr.resource',       'invokes', 'ecs.task-definition','lateral_movement', 'ECR → ECS task (supply chain)',                    TRUE, 25)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 5. ECS TASK DATA ACCESS
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('ecs.task-definition', 'stores_data_in', 's3.resource',                   'data_access', 'ECS task → S3 bucket',               TRUE, 15),
    ('ecs.task-definition', 'stores_data_in', 'dynamodb.table',                'data_access', 'ECS task → DynamoDB table',           TRUE, 15),
    ('ecs.task-definition', 'stores_data_in', 'rds.instance',                  'data_access', 'ECS task → RDS instance',             TRUE, 15),
    ('ecs.task-definition', 'stores_data_in', 'elasticache.cluster',           'data_access', 'ECS task → ElastiCache',              TRUE, 15),
    ('ecs.task-definition', 'publishes_to',   'sqs.queue',                     'data_flow',   'ECS task → SQS queue',                TRUE, 10),
    ('ecs.task-definition', 'publishes_to',   'sns.topic',                     'data_flow',   'ECS task → SNS topic',                TRUE, 10),
    ('ecs.service',         'stores_data_in', 's3.resource',                   'data_access', 'ECS service → S3',                    TRUE, 15),
    ('ecs.service',         'stores_data_in', 'rds.instance',                  'data_access', 'ECS service → RDS',                   TRUE, 15)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 6. COGNITO FEDERATION  (T1621)
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('cognito.identity-pool', 'assumes', 'iam.role', 'privilege_escalation',
     'Cognito identity pool → IAM role assumption (unauthenticated access)', TRUE, 25),
    ('cognito.resource',      'assumes', 'iam.role', 'privilege_escalation',
     'Cognito → IAM role assumption (unauthenticated access)',               TRUE, 25)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 7. CLOUDFRONT → ORIGIN TRAVERSAL
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('cloudfront.distribution', 'routes_to', 's3.resource',                        'data_access', 'CloudFront → S3 origin',        TRUE, 15),
    ('cloudfront.distribution', 'routes_to', 's3.bucket',                          'data_access', 'CloudFront → S3 origin',        TRUE, 15),
    ('cloudfront.distribution', 'routes_to', 'elbv2.load-balancer',                'lateral_movement', 'CloudFront → ALB origin',  TRUE, 15),
    ('cloudfront.distribution', 'routes_to', 'elasticloadbalancingv2.loadbalancer','lateral_movement', 'CloudFront → ALB origin',  TRUE, 15)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 8. API GATEWAY → DIRECT S3 INTEGRATION
-- ============================================================================

INSERT INTO resource_security_relationship_rules
    (source_resource_type, relation_type, target_resource_type, attack_path_category,
     description, is_active, priority)
VALUES
    ('apigateway.item_rest_api', 'stores_data_in', 's3.resource', 'data_access',
     'API GW → S3 direct integration (PutObject/GetObject)',  TRUE, 20),
    ('apigatewayv2.api',         'stores_data_in', 's3.resource', 'data_access',
     'API GW v2 → S3 direct integration',                    TRUE, 20)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 9. UPDATE attack_path_category classification for new relation_types
-- ============================================================================

UPDATE resource_security_relationship_rules
SET attack_path_category = CASE relation_type
    WHEN 'invokes'       THEN 'execution'
    WHEN 'stores_data_in' THEN 'data_access'
    ELSE attack_path_category
END
WHERE relation_type IN ('invokes', 'stores_data_in')
  AND attack_path_category IS NULL;
