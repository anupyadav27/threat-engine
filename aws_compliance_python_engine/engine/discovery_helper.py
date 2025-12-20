"""
Discovery Helper - AWS Service to Boto3 Client Mapping

This module provides comprehensive mapping of AWS service names (as used in YAML files)
to their corresponding boto3 client names. Most services use the same name, but some
require special mapping due to naming differences.

The mapping includes:
1. Special mappings: Services that require different boto3 client names
2. Standard mappings: Services that use the same name (explicitly listed for clarity)
3. Auto-normalization: Services not explicitly listed are normalized (underscores removed)
"""

# Service name mapping: YAML service name -> boto3 client name
# Most services use the same name, but some require special mapping
SERVICE_TO_BOTO3_CLIENT = {
    # ============================================================
    # SPECIAL MAPPINGS - Services with different boto3 client names
    # ============================================================
    'cognito': 'cognito-idp',                    # cognito -> cognito-idp
    'vpc': 'ec2',                                 # vpc -> ec2
    'vpcflowlogs': 'ec2',                         # vpcflowlogs -> ec2
    'workflows': 'stepfunctions',                 # workflows -> stepfunctions
    'parameterstore': 'ssm',                     # parameterstore -> ssm
    'elastic': 'es',                             # elastic -> es (Elasticsearch)
    'eip': 'ec2',                                 # eip -> ec2
    'eventbridge': 'events',                      # eventbridge -> events
    'fargate': 'ecs',                             # fargate -> ecs
    'kinesisfirehose': 'firehose',                # kinesisfirehose -> firehose
    'costexplorer': 'ce',                        # costexplorer -> ce
    'directoryservice': 'ds',                     # directoryservice -> ds
    'identitycenter': 'sso',                     # identitycenter -> sso
    'macie': 'macie2',                            # macie -> macie2
    'networkfirewall': 'network-firewall',       # networkfirewall -> network-firewall
    'kinesisvideostreams': 'kinesisvideo',       # kinesisvideostreams -> kinesisvideo
    'timestream': 'timestream-query',            # timestream -> timestream-query
    'edr': 'security-ir',                        # edr -> security-ir
    
    # ============================================================
    # STANDARD MAPPINGS - Services with same name in boto3
    # Explicitly listed for clarity and validation
    # ============================================================
    'accessanalyzer': 'accessanalyzer',
    'acm': 'acm',
    'apigateway': 'apigateway',
    'apigatewayv2': 'apigatewayv2',
    'appstream': 'appstream',
    'appsync': 'appsync',
    'athena': 'athena',
    'autoscaling': 'autoscaling',
    'backup': 'backup',
    'batch': 'batch',
    'bedrock': 'bedrock',
    'budgets': 'budgets',
    'cloudformation': 'cloudformation',
    'cloudfront': 'cloudfront',
    'cloudtrail': 'cloudtrail',
    'cloudwatch': 'cloudwatch',
    'codeartifact': 'codeartifact',
    'codebuild': 'codebuild',
    'config': 'config',
    'controltower': 'controltower',
    'datasync': 'datasync',
    'detective': 'detective',
    'directconnect': 'directconnect',
    'dms': 'dms',
    'docdb': 'docdb',
    'drs': 'drs',
    'dynamodb': 'dynamodb',
    'ebs': 'ebs',
    'ec2': 'ec2',
    'ecr': 'ecr',
    'ecs': 'ecs',
    'efs': 'efs',
    'eks': 'eks',
    'elasticache': 'elasticache',
    'elasticbeanstalk': 'elasticbeanstalk',
    'elb': 'elb',
    'elbv2': 'elbv2',
    'emr': 'emr',
    'firehose': 'firehose',
    'fsx': 'fsx',
    'glacier': 'glacier',
    'globalaccelerator': 'globalaccelerator',
    'glue': 'glue',
    'guardduty': 'guardduty',
    'iam': 'iam',
    'inspector': 'inspector',
    'kafka': 'kafka',
    'keyspaces': 'keyspaces',
    'kinesis': 'kinesis',
    'kinesisanalytics': 'kinesisanalytics',
    'kms': 'kms',
    'lakeformation': 'lakeformation',
    'lambda': 'lambda',
    'lightsail': 'lightsail',
    'mq': 'mq',
    'neptune': 'neptune',
    'opensearch': 'opensearch',
    'organizations': 'organizations',
    'quicksight': 'quicksight',
    'rds': 'rds',
    'redshift': 'redshift',
    'route53': 'route53',
    's3': 's3',
    'sagemaker': 'sagemaker',
    'savingsplans': 'savingsplans',
    'secretsmanager': 'secretsmanager',
    'securityhub': 'securityhub',
    'servicecatalog': 'servicecatalog',
    'ses': 'ses',
    'shield': 'shield',
    'sns': 'sns',
    'sqs': 'sqs',
    'ssm': 'ssm',
    'stepfunctions': 'stepfunctions',
    'storagegateway': 'storagegateway',
    'transfer': 'transfer',
    'waf': 'waf',
    'wafv2': 'wafv2',
    'wellarchitected': 'wellarchitected',
    'workspaces': 'workspaces',
    'xray': 'xray',
    
    # Additional services from config (all AWS services)
    'account': 'account',
    'apprunner': 'apprunner',
    'artifact': 'artifact',
    'auditmanager': 'auditmanager',
    'ce': 'ce',
    'codecommit': 'codecommit',
    'codepipeline': 'codepipeline',
    'dlm': 'dlm',
    'fis': 'fis',
    'fms': 'fms',
    'inspector2': 'inspector2',
    'nlb': 'nlb',
    'qldb': 'qldb',
    'resource-explorer-2': 'resource-explorer-2',
    'resource-groups': 'resource-groups',
    'route53resolverdnsfirewall': 'route53resolverdnsfirewall',
    'ssm-incidents': 'ssm-incidents',
    'signer': 'signer',
    'tag': 'tag',
    'transitgateway': 'transitgateway',
    'trustedadvisor': 'trustedadvisor',
    'vpn': 'vpn',
    'workdocs': 'workdocs',
}


def get_boto3_client_name(service_name: str) -> str:
    """
    Map YAML service name to boto3 client name.
    
    Args:
        service_name: Service name from YAML file or config
        
    Returns:
        boto3 client name to use for creating boto3.client()
        
    Examples:
        >>> get_boto3_client_name('cognito')
        'cognito-idp'
        >>> get_boto3_client_name('vpc')
        'ec2'
        >>> get_boto3_client_name('s3')
        's3'
    """
    # Try exact match first
    if service_name in SERVICE_TO_BOTO3_CLIENT:
        return SERVICE_TO_BOTO3_CLIENT[service_name]
    
    # Try normalized name (remove underscores, lowercase)
    service_normalized = service_name.replace('_', '').lower()
    if service_normalized in SERVICE_TO_BOTO3_CLIENT:
        return SERVICE_TO_BOTO3_CLIENT[service_normalized]
    
    # If no mapping found, normalize the service name (boto3 uses no underscores)
    # e.g., api_gateway -> apigateway
    return service_normalized


def get_all_service_mappings() -> dict:
    """
    Get all service to boto3 client mappings.
    
    Returns:
        Dictionary mapping service names to boto3 client names
    """
    return SERVICE_TO_BOTO3_CLIENT.copy()


def is_service_mapped(service_name: str) -> bool:
    """
    Check if a service has an explicit mapping.
    
    Args:
        service_name: Service name to check
        
    Returns:
        True if service has explicit mapping, False otherwise
    """
    service_normalized = service_name.replace('_', '').lower()
    return service_name in SERVICE_TO_BOTO3_CLIENT or service_normalized in SERVICE_TO_BOTO3_CLIENT
