#!/usr/bin/env python3
import json
import os

# All configured services
configured_services = ['accessanalyzer','acm','apigateway','apigatewayv2','appstream','appsync','athena','autoscaling','backup','batch','bedrock','budgets','cloudformation','cloudfront','cloudtrail','cloudwatch','codeartifact','codebuild','cognito','config','controltower','costexplorer','datasync','detective','directconnect','directoryservice','dms','docdb','drs','dynamodb','ebs','ec2','ecr','ecs','edr','efs','eip','eks','elastic','elasticache','elasticbeanstalk','elb','elbv2','emr','eventbridge','fargate','firehose','fsx','glacier','globalaccelerator','glue','guardduty','iam','identitycenter','inspector','kafka','keyspaces','kinesis','kinesisanalytics','kinesisfirehose','kinesisvideostreams','kms','lakeformation','lambda','lightsail','macie','mq','neptune','networkfirewall','no','opensearch','organizations','parameterstore','qldb','quicksight','rds','redshift','route53','s3','sagemaker','savingsplans','secretsmanager','securityhub','servicecatalog','ses','shield','sns','sqs','ssm','stepfunctions','storagegateway','timestream','transfer','vpc','vpcflowlogs','waf','wafv2','wellarchitected','workflows','workspaces','xray']

# Get YAML files
yaml_files = [f for f in os.listdir('output') if f.endswith('_generated.yaml')]
yaml_services = set([f.replace('_generated.yaml', '') for f in yaml_files])

# Get validated data
with open('output/requirements_validated.json') as f:
    validated_data = json.load(f)
    
services_with_rules = {s: len(validated_data[s]) for s in validated_data if validated_data[s]}

print("=" * 70)
print("ANALYSIS OF RESULTS")
print("=" * 70)
print()
print(f"Configured services: {len(configured_services)}")
print(f"YAML files created:  {len(yaml_services)}")
print(f"Services with rules: {len(services_with_rules)}")
print()

# Missing YAMLs
missing = set(configured_services) - yaml_services

print("=" * 70)
print(f"21 SERVICES WITHOUT YAML FILES:")
print("=" * 70)
print()

for svc in sorted(missing):
    if svc in services_with_rules:
        print(f"  ⚠️  {svc:30} HAS {services_with_rules[svc]:3} RULES")
    else:
        print(f"  ✓  {svc:30} No rules (expected)")

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
total_rules = sum(len(validated_data[s]) for s in validated_data)
validated_rules = sum(1 for s in validated_data.values() for r in s if r.get('all_fields_valid'))
print(f"Total rules processed: {total_rules}")
print(f"Validated rules: {validated_rules}")
print(f"Validation rate: {validated_rules/total_rules*100:.1f}%")
print()
print(f"Services missing YAMLs: {len(missing)}")
print(f"  - With rules: {len([s for s in missing if s in services_with_rules])}")
print(f"  - Without rules: {len([s for s in missing if s not in services_with_rules])}")

