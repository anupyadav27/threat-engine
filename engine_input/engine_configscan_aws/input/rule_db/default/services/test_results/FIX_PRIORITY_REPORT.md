# Test-Driven Fix Priority Report

Generated: 2025-11-25 12:32:59
Region: us-east-1

## 🔴 CRITICAL Priority (Fix First)

**11 services completely broken**

### costexplorer

- Discovery steps: 4
- Failed: 4
- Checks affected: 10

**Fix needed**: Invalid service: costexplorer
- Suggestion: Check AWS documentation for 'costexplorer'

**Fix needed**: Invalid service: costexplorer
- Suggestion: Check AWS documentation for 'costexplorer'


### edr

- Discovery steps: 1
- Failed: 1
- Checks affected: 1

**Fix needed**: Invalid service: edr
- Suggestion: Not a standalone service


### eip

- Discovery steps: 1
- Failed: 1
- Checks affected: 1


### eventbridge

- Discovery steps: 7
- Failed: 7
- Checks affected: 20

**Fix needed**: Invalid service: eventbridge
- Suggestion: Check AWS documentation for 'eventbridge'

**Fix needed**: Invalid service: eventbridge
- Suggestion: Check AWS documentation for 'eventbridge'


### fargate

- Discovery steps: 4
- Failed: 4
- Checks affected: 10

**Fix needed**: Invalid service: fargate
- Suggestion: ecs (Fargate is part of ECS)

**Fix needed**: Invalid service: fargate
- Suggestion: ecs (Fargate is part of ECS)


### macie

- Discovery steps: 6
- Failed: 6
- Checks affected: 13

**Fix needed**: Invalid service: macie
- Suggestion: Check AWS documentation for 'macie'

**Fix needed**: Invalid service: macie
- Suggestion: Check AWS documentation for 'macie'


### networkfirewall

- Discovery steps: 5
- Failed: 5
- Checks affected: 6

**Fix needed**: Invalid service: networkfirewall
- Suggestion: Check AWS documentation for 'networkfirewall'

**Fix needed**: Invalid service: networkfirewall
- Suggestion: Check AWS documentation for 'networkfirewall'


### no

- Discovery steps: 1
- Failed: 1
- Checks affected: 1

**Fix needed**: Invalid service: no
- Suggestion: Invalid service name


### parameterstore

- Discovery steps: 2
- Failed: 2
- Checks affected: 5

**Fix needed**: Invalid service: parameterstore
- Suggestion: Check AWS documentation for 'parameterstore'

**Fix needed**: Invalid service: parameterstore
- Suggestion: Check AWS documentation for 'parameterstore'


### timestream

- Discovery steps: 7
- Failed: 7
- Checks affected: 18


## 🟡 HIGH Priority (Fix Next)

**16 services partially working**

### account

- Passed: 2
- Failed: 1
- Partial: 0

### apigateway

- Passed: 13
- Failed: 3
- Partial: 0

### apigatewayv2

- Passed: 3
- Failed: 2
- Partial: 0

### athena

- Passed: 6
- Failed: 1
- Partial: 0

### directconnect

- Passed: 2
- Failed: 3
- Partial: 0

## 🟢 LOW Priority (Working)

**75 services working correctly**

- accessanalyzer (2 checks)
- acm (14 checks)
- appstream (1 checks)
- appsync (2 checks)
- autoscaling (4 checks)
- backup (66 checks)
- batch (8 checks)
- bedrock (8 checks)
- budgets (4 checks)
- cloudformation (3 checks)
- cloudfront (26 checks)
- cloudtrail (42 checks)
- cloudwatch (86 checks)
- codeartifact (1 checks)
- codebuild (8 checks)
- cognito (12 checks)
- config (23 checks)
- controltower (8 checks)
- datasync (1 checks)
- detective (4 checks)
- directoryservice (2 checks)
- dms (5 checks)
- docdb (25 checks)
- drs (1 checks)
- dynamodb (22 checks)
- ebs (13 checks)
- ecr (16 checks)
- ecs (8 checks)
- efs (11 checks)
- eks (78 checks)
- elastic (1 checks)
- elasticache (19 checks)
- emr (3 checks)
- firehose (1 checks)
- fsx (8 checks)
- glacier (13 checks)
- globalaccelerator (4 checks)
- glue (97 checks)
- guardduty (24 checks)
- inspector (9 checks)
- kafka (3 checks)
- keyspaces (2 checks)
- kinesis (7 checks)
- kinesisanalytics (3 checks)
- kinesisvideostreams (3 checks)
- kms (24 checks)
- lakeformation (3 checks)
- mq (3 checks)
- neptune (24 checks)
- opensearch (10 checks)
- organizations (41 checks)
- qldb (5 checks)
- quicksight (16 checks)
- rds (62 checks)
- redshift (51 checks)
- route53 (16 checks)
- s3 (64 checks)
- sagemaker (83 checks)
- savingsplans (3 checks)
- secretsmanager (9 checks)
- securityhub (14 checks)
- servicecatalog (1 checks)
- ses (10 checks)
- shield (11 checks)
- sns (24 checks)
- sqs (6 checks)
- ssm (25 checks)
- stepfunctions (37 checks)
- storagegateway (11 checks)
- transfer (1 checks)
- waf (28 checks)
- wafv2 (21 checks)
- wellarchitected (1 checks)
- workspaces (4 checks)
- xray (6 checks)
