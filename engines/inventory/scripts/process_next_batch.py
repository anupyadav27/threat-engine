#!/usr/bin/env python3
"""Process next batch of services"""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "engine_inventory" / "inventory_engine" / "config"
SCRIPT_PATH = PROJECT_ROOT / "engine_inventory" / "scripts" / "generate_relationships_with_openai.py"

# Already processed (will be updated from index)
PROCESSED = []

def get_remaining_services():
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    CONFIGSCAN_SERVICES = PROJECT_ROOT / "engine_configscan" / "engine_configscan_aws" / "services"
    
    # Get services with discovery files
    services_with_discovery = []
    for service_dir in CONFIGSCAN_SERVICES.iterdir():
        if service_dir.is_dir():
            discovery_file = service_dir / "discoveries" / f"{service_dir.name}.discoveries.yaml"
            if discovery_file.exists():
                services_with_discovery.append(service_dir.name)
    
    # Get services already processed (from by_service structure)
    index_file = CONFIG_DIR / "aws_relationship_index.json"
    with open(index_file) as f:
        data = json.load(f)
    by_service = data.get("by_service", {})
    services_with_relations = set(by_service.keys())
    
    # Priority services (important AWS services)
    priority_services = [
        'apigateway', 'apigatewayv2', 'applicationautoscaling', 'applicationinsights',
        'artifact', 'auditmanager', 'autoscaling', 'backup', 'batch', 'bedrock',
        'cloudformation', 'cloudfront', 'cloudhsm', 'cloudsearch', 'cloudtrail',
        'cloudwatch', 'codebuild', 'codecommit', 'codedeploy', 'codepipeline',
        'codestar', 'cognito', 'comprehend', 'computeoptimizer', 'connect',
        'controltower', 'costexplorer', 'databrew', 'datapipeline', 'datasync',
        'devicefarm', 'directconnect', 'dms', 'docdb', 'drs', 'dynamodb',
        'ec2', 'ecr', 'ecs', 'efs', 'eks', 'elasticache', 'elasticbeanstalk',
        'elastictranscoder', 'emr', 'eventbridge', 'firehose', 'fis', 'forecast',
        'frauddetector', 'fsx', 'gamelift', 'glacier', 'globalaccelerator',
        'glue', 'grafana', 'greengrass', 'groundstation', 'guardduty', 'health',
        'iam', 'identitystore', 'imagebuilder', 'inspector', 'iot', 'iotanalytics',
        'iotevents', 'iotwireless', 'kafka', 'kendra', 'kinesis', 'kinesisanalytics',
        'kinesisfirehose', 'kinesisvideostreams', 'kms', 'lakeformation', 'lambda',
        'lex', 'licensemanager', 'lightsail', 'location', 'logs', 'lookoutmetrics',
        'macie', 'mediaconnect', 'mediaconvert', 'medialive', 'mediapackage',
        'mediastore', 'mediatailor', 'memorydb', 'migrationhub', 'mq', 'neptune',
        'networkfirewall', 'networkmanager', 'nimblestudio', 'opensearch', 'opsworks',
        'organizations', 'outposts', 'personalize', 'pinpoint', 'polly', 'pricing',
        'qldb', 'quicksight', 'ram', 'rds', 'redshift', 'rekognition', 'resiliencehub',
        'resourcegroups', 'robomaker', 'route53', 'route53domains', 's3', 'sagemaker',
        'savingsplans', 'schemas', 'secretsmanager', 'securityhub', 'serverlessrepo',
        'servicecatalog', 'servicediscovery', 'ses', 'shield', 'signer', 'sms',
        'snowball', 'sns', 'sqs', 'ssm', 'sso', 'stepfunctions', 'storagegateway',
        'support', 'swf', 'synthetics', 'textract', 'timestream', 'transcribe',
        'transfer', 'translate', 'trustedadvisor', 'waf', 'wafv2', 'wellarchitected',
        'workdocs', 'worklink', 'workmail', 'workspaces', 'xray'
    ]
    
    # Find priority services that haven't been processed
    remaining_priority = [s for s in priority_services if s in services_with_discovery and s not in services_with_relations]
    
    # Also include non-priority services that have discovery files
    all_remaining = [s for s in services_with_discovery if s not in services_with_relations]
    non_priority = [s for s in all_remaining if s not in remaining_priority]
    
    # Return priority first, then others
    return sorted(remaining_priority) + sorted(non_priority)

def main():
    if len(sys.argv) < 2:
        print("Usage: python process_next_batch.py <api_key> [--count 20] [--model gpt-4o]")
        sys.exit(1)
    
    api_key = sys.argv[1]
    count = 20
    model = "gpt-4o"
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--count" and i + 1 < len(sys.argv):
            count = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    remaining = get_remaining_services()
    services_to_process = remaining[:count]
    
    print(f"Processing {len(services_to_process)} services...")
    
    success = []
    failed = []
    
    for service in services_to_process:
        print(f"\nProcessing: {service}")
        cmd = [sys.executable, str(SCRIPT_PATH), service, "--model", model, "--api-key", api_key]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                success.append(service)
                print(f"✓ {service}")
            else:
                failed.append(service)
                print(f"✗ {service}: {result.stderr[:200]}")
        except Exception as e:
            failed.append(service)
            print(f"✗ {service}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Success: {len(success)}/{len(services_to_process)}")
    print(f"Failed: {len(failed)}")
    if failed:
        print(f"Failed: {', '.join(failed)}")

if __name__ == "__main__":
    main()
