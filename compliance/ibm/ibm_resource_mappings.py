#!/usr/bin/env python3
"""
IBM Cloud Resource Mappings
Maps various resource names to IBM SDK standard resource types
"""

# IBM Cloud SDK Resource Type Mappings
# Organized by service category
IBM_RESOURCE_MAPPINGS = {
    # === Watson ML / AI Services ===
    'machine_learning_training_job': 'training_job',
    'studio_notebook': 'notebook',
    'studio_workspace': 'workspace',
    'studio_experiment': 'experiment',
    'studio_cluster': 'cluster',
    
    # === Data & Analytics ===
    'catalog_table': 'table',
    'catalog_quality': 'quality_rule',
    
    # === VPC & Compute ===
    'private_cloud_server': 'instance',
    'private_cloud_instance_template': 'instance_template',
    'private_cloud_image': 'image',
    'private_cloud_block_storage': 'volume',
    'private_cloud_instance_group': 'instance_group',
    'private_cloud_load_balancer': 'load_balancer',
    'private_cloud_subnet': 'subnet',
    'floating_ip': 'public_ip',
    
    # === Security ===
    'groups_group': 'security_group',
    'groups_waf': 'waf_rule',
    'advisor_automation': 'automation',
    'advisor_finding': 'finding',
    'advisor_ip_set': 'ip_set',
    'advisor_patch': 'patch',
    'advisor_response': 'response_plan',
    'advisor_scan': 'scan',
    'advisor_workflow': 'workflow',
    'advisor_assessment': 'assessment',
    'advisor_note': 'note',
    'protect_secret': 'secret',
    'protect_vault': 'vault',
    
    # === Containers ===
    'task_definitions_logging_block_mode': 'task_definition',
    'security_context_constraint': 'security_constraint',
    
    # === Backup ===
    'backup_backup_plan': 'backup_plan',
    'backup_backup_vault': 'vault',
    'backup_backup_job': 'backup_job',
    'backup_replication': 'replication',
    'backup_restore_job': 'restore_job',
    'backup_automation': 'automation',
    'functions_function': 'function',
    
    # === API Gateway ===
    'rate_limit': 'throttle',
    'request_validator': 'validator',
    
    # === Logging & Monitoring ===
    'notification_channel': 'channel',
    'capture': 'capture_rule',
    'log_group': 'log_group',
    
    # === Networking ===
    'rule_group': 'rule_set',
    'origin': 'origin_server',
    
    # === Storage ===
    'bucket_policy': 'policy',
    'notification_configuration': 'notification',
    'retention_policy': 'retention_policy',
    
    # === IAM ===
    'identity_provider': 'idp',
    'service_id': 'service_id',
    'access_group': 'group',
    
    # === Events ===
    'hub_topic': 'topic',
    'subscription': 'subscription',
    
    # === Generic mappings ===
    # These will be service-specific
}

# Service-specific resource inference rules
# When resource is 'resource', infer the actual resource from the service
SERVICE_DEFAULT_RESOURCES = {
    'watson_ml': 'model',
    'databases': 'deployment',
    'vpc': 'instance',
    'containers': 'cluster',
    'object_storage': 'bucket',
    'key_protect': 'key',
    'secrets_manager': 'secret',
    'certificate_manager': 'certificate',
    'iam': 'policy',
    'security_advisor': 'finding',
    'data_virtualization': 'catalog',
    'backup': 'backup_plan',
    'activity_tracker': 'target',
    'log_analysis': 'instance',
    'monitoring': 'alert',
    'api_gateway': 'api',
    'event_notifications': 'topic',
    'event_streams': 'topic',
    'code_engine': 'application',
    'container_registry': 'namespace',
    'continuous_delivery': 'toolchain',
    'schematics': 'workspace',
    'security_compliance_center': 'profile',
    'internet_services': 'zone',
    'dns': 'zone',
    'load_balancer': 'load_balancer',
    'direct_link': 'gateway',
    'transit_gateway': 'gateway',
    'cloudant': 'database',
    'analytics_engine': 'instance',
    'datastage': 'flow',
    'cognos_dashboard': 'dashboard',
    'billing': 'account',
    'resource_controller': 'resource_instance',
    'block_storage': 'volume',
    'file_storage': 'share',
}

def get_resource_name(service, resource):
    """Get the normalized resource name for a service"""
    # First check if it's a generic 'resource'
    if resource == 'resource' and service in SERVICE_DEFAULT_RESOURCES:
        return SERVICE_DEFAULT_RESOURCES[service]
    
    # Then check if there's a mapping
    if resource in IBM_RESOURCE_MAPPINGS:
        return IBM_RESOURCE_MAPPINGS[resource]
    
    # Otherwise return as-is
    return resource

print(f"IBM Resource Mappings: {len(IBM_RESOURCE_MAPPINGS)}")
print(f"Service Default Resources: {len(SERVICE_DEFAULT_RESOURCES)}")
print("✅ IBM Cloud Resource Mappings Complete!")

