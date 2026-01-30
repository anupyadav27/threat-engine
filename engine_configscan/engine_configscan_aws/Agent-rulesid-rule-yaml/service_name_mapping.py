"""
Centralized Service Name Mapping

Maps metadata service names to boto3 service names.
Used by Agent 1 and Agent 2 to ensure correct service lookup.
"""

# Service name mapping: metadata name -> boto3 service name
SERVICE_NAME_MAPPING = {
    # Core services
    'cognito': 'cognito-idp',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'workflows': 'stepfunctions',
    'parameterstore': 'ssm',
    'elastic': 'es',
    'eip': 'ec2',
    'eventbridge': 'events',
    'fargate': 'ecs',
    'kinesisfirehose': 'firehose',
    'costexplorer': 'ce',
    'directoryservice': 'ds',
    'identitycenter': 'sso',
    'macie': 'macie2',
    'networkfirewall': 'network-firewall',
    'edr': 'guardduty',
    'kinesisvideostreams': 'kinesisvideo',
    'timestream': 'timestream-query',
    # Note: qldb may not be in boto3 catalog - will be handled gracefully
    'qldb': 'qldb',  # Will check if exists
}


def get_boto3_service_name(service: str) -> str:
    """
    Map metadata service name to boto3 service name.
    
    Args:
        service: Metadata service name (e.g., 'cognito', 'costexplorer')
    
    Returns:
        Boto3 service name (e.g., 'cognito-idp', 'ce')
    """
    return SERVICE_NAME_MAPPING.get(service, service)


def verify_service_mapping(boto3_data: dict) -> dict:
    """
    Verify all mappings exist in boto3 data.
    
    Args:
        boto3_data: Loaded boto3 dependencies data
    
    Returns:
        Dict with verification results
    """
    results = {
        'valid': [],
        'invalid': [],
        'missing': []
    }
    
    for meta_service, boto3_service in SERVICE_NAME_MAPPING.items():
        if boto3_service in boto3_data:
            results['valid'].append((meta_service, boto3_service))
        else:
            results['invalid'].append((meta_service, boto3_service))
            # Try to find alternative
            boto3_services = [k for k in boto3_data.keys() if isinstance(boto3_data[k], (dict, list))]
            matches = [s for s in boto3_services if boto3_service.lower() in s.lower() or s.lower() in boto3_service.lower()]
            if matches:
                results['missing'].append((meta_service, boto3_service, matches[:3]))
    
    return results
