"""
IBM Cloud Python SDK Validation Mappings

This module provides comprehensive mappings for IBM Cloud services and resources
to their official Python SDK equivalents.

Based on official IBM Cloud SDK packages:
- ibm-platform-services
- ibm-vpc
- ibm-cloud-databases
- ibm-key-protect
- ibm-secrets-manager-sdk
- ibm-schematics
- ibm-cos-sdk
- ibm-watson
- cloudant

Multi-Cloud Note:
This ruleset contains AWS, Azure, and GCP services. Those are handled separately.
"""

# =============================================================================
# IBM CLOUD NATIVE SERVICE MAPPINGS
# =============================================================================

IBM_SERVICE_MAPPINGS = {
    # Current Service Name → Official IBM Python SDK Service Name
    
    # Core Platform Services
    "activity": "activity_tracker",      # ibm-platform-services
    "certificate": "certificate_manager", # ibm-cloud-networking
    "cis": "cis",                        # ibm-cloud-networking (Cloud Internet Services)
    "cos": "cos",                        # ibm-cos-sdk (Cloud Object Storage)
    "cloudant": "cloudant",              # cloudant
    "cloudstorage": "cos",               # Should be COS
    
    # Database Services
    "databases": "cloud_databases",      # ibm-cloud-databases
    "db2": "cloud_databases",            # Part of cloud databases
    "cloudant": "cloudant",              # cloudant
    "cosmosdb": "cloud_databases",       # If IBM, else Azure
    
    # Code & Compute
    "code": "code_engine",               # ibm-code-engine-sdk
    "compute": "vsi",                    # IBM calls it VSI (Virtual Server Instance)
    "container": "container_registry",   # ibm-container-registry
    
    # IAM & Security
    "iam": "iam",                        # ibm-platform-services
    "key": "key_protect",                # ibm-key-protect
    "secrets": "secrets_manager",        # ibm-secrets-manager-sdk
    "secretsmanager": "secrets_manager", # ibm-secrets-manager-sdk
    "scc": "security_compliance",        # ibm-scc
    "guardium": "security_compliance",   # IBM Guardium → SCC
    
    # Networking
    "vpc": "vpc",                        # ibm-vpc
    "vsi": "vsi",                        # ibm-vpc (Virtual Server Instance)
    "virtual": "vpc",                    # virtual.private_cloud_* → vpc
    "network": "vpc",                    # Generic network → vpc
    "load": "vpc",                       # load.balancer → vpc.load_balancer
    "floating": "vpc",                   # floating.ip → vpc.floating_ip
    
    # Kubernetes & OpenShift
    "kubernetes": "kubernetes_service",  # ibm-container-service-api
    "k8s": "kubernetes_service",         # ibm-container-service-api
    "openshift": "openshift_service",    # ibm-container-service-api
    "ocp": "openshift_service",          # OpenShift Container Platform
    
    # Logging & Monitoring
    "logging": "log_analysis",           # ibm-log-analysis
    "monitoring": "monitoring",          # ibm-cloud-monitoring
    
    # DevOps & Automation
    "schematics": "schematics",          # ibm-schematics
    "devops": "devops",                  # ibm-continuous-delivery
    
    # Watson & AI
    "watson": "watson_machine_learning", # ibm-watson
    "aisearch": "watson_discovery",      # ibm-watson
    
    # Data & Analytics
    "data": "data_virtualization",       # ibm-platform-services
    "datastage": "datastage",            # IBM DataStage
    "dataproc": "analytics_engine",      # IBM Analytics Engine (similar to Dataproc)
    "cognos": "cognos_analytics",        # IBM Cognos Analytics
    
    # Resource Management
    "resource": "resource_controller",   # ibm-platform-services
    "organizations": "resource_controller", # Part of resource management
    
    # API & Event
    "api": "api_gateway",                # IBM API Gateway
    "event": "event_notifications",      # ibm-platform-services
    "eventbridge": "event_notifications",# IBM equivalent
    
    # DNS & CDN
    "dns": "dns_services",               # ibm-cloud-networking
    "cdn": "cdn",                        # ibm-cloud-networking
    "cloudfront": "cdn",                 # AWS CloudFront → IBM CDN
    
    # Messaging
    "mq": "mq",                          # IBM MQ
    "message": "event_notifications",    # message.hub → event_notifications
    
    # File & Block Storage
    "file": "file_storage",              # IBM Cloud File Storage
    "block": "block_storage",            # IBM Cloud Block Storage
    "storage": "cos",                    # Generic storage → COS
    "object": "cos",                     # object.storage → cos
    
    # Transfer & Backup
    "transfer": "aspera",                # IBM Aspera (high-speed transfer)
    "cloud": "backup_recovery",          # cloud.backup_* → backup_recovery
    "datasync": "aspera",                # Similar to Aspera
    
    # API Keys & Access
    "apikeys": "iam",                    # API keys part of IAM
    "accessanalyzer": "iam",             # Access analyzer part of IAM
    
    # Application Services
    "app": "code_engine",                # app.function → code_engine.function
    
    # Well-Architected & Compliance
    "wellarchitected": "security_compliance", # Part of SCC
    "config": "security_compliance",     # Configuration rules → SCC
    
    # Other IBM Services
    "acm": "certificate_manager",        # ACM → Certificate Manager
    "artifacts": "container_registry",   # artifacts → Container Registry
    "defender": "security_compliance",   # If IBM, else Azure
    "directconnect": "direct_link",      # IBM Direct Link
    "directoryservice": "app_id",        # IBM App ID (directory service)
    "glacier": "cos",                    # glacier.policy → cos (archive tier)
    "route53": "dns_services",           # AWS Route53 → IBM DNS
    "servicecatalog": "catalog",         # IBM Cloud Catalog
    "shield": "cis",                     # AWS Shield → IBM CIS (DDoS protection)
    "unmapped": "unknown",               # Need manual mapping
}

# =============================================================================
# IBM CLOUD RESOURCE MAPPINGS (BY SERVICE)
# =============================================================================

IBM_RESOURCE_MAPPINGS = {
    # Activity Tracker
    "activity_tracker": {
        "bucket": "event",
        "resource": "event",
        "tracker_alert_configuration_verification": "route",
        "tracker_data_encryption_at_rest": "target",
        "tracker_threat_detection_enumeration": "event",
        "tracker_threat_detection_llm_jacking": "event",
        "tracker_threat_detection_privilege_escalation": "event",
    },
    
    # API Gateway
    "api_gateway": {
        "connect": "api",
        "connect_authorizer": "authorizer",
        "connect_key": "api_key",
        "connect_rate_limit": "rate_limit",
        "connect_restapi_waf_acl_attached": "api",
        "connect_stage": "deployment",
        "connect_usage_plan": "usage_plan",
        "connect_validation": "request_validator",
        "gateway_monitoring": "api",
    },
    
    # API Keys (IAM)
    "iam": {
        "api_restrictions_configured": "api_key",
        "key": "api_key",
        "access_group": "access_group",
        "account": "account_settings",
        "group": "access_group",
        "identity_federation_status": "account_settings",
        "identity_provider": "identity_provider",
        "no_guest_accounts_with_permissions": "user",
        "organization_essential_contacts_configured": "account_settings",
        "password": "account_settings",
        "policy": "policy",
        "role": "role",
        "service_id": "service_id",
        "user": "user",
    },
    
    # Block Storage
    "block_storage": {
        "storage_snapshot": "snapshot",
        "storage_volume": "volume",
    },
    
    # CDN (Content Delivery Network)
    "cdn": {
        "cache_policy": "cache_behavior",
        "distribution": "distribution",
        "distributions_using_deprecated_ssl_protocols": "distribution",
        "ip_set": "whitelist",
        "origin_request_policy": "origin",
        "regex_pattern_set": "rule",
        "resource": "distribution",
        "rule": "rule",
        "rule_group": "rule_group",
    },
    
    # Certificate Manager
    "certificate_manager": {
        "manager": "certificate",
        "resource": "certificate",
    },
    
    # CIS (Cloud Internet Services)
    "cis": {
        "resource": "zone",
    },
    
    # Cloud Databases
    "cloud_databases": {
        "cluster": "deployment",
        "for_postgresql_cluster": "deployment",
        "for_postgresql_instance": "deployment",
        "for_postgresql_option_group": "deployment",
        "for_postgresql_parameter_group": "configuration",
        "for_postgresql_security_group": "whitelist",
        "for_postgresql_snapshot": "backup",
        "for_postgresql_subnet_group": "deployment",
        "for_postgresql_user": "user",
        "instance": "deployment",
        "warehouse_authorization": "user",
        "warehouse_cluster": "deployment",
        "warehouse_endpoint": "connection",
        "warehouse_parameter_group": "configuration",
        "warehouse_snapshot": "backup",
    },
    
    # Cloud Object Storage (COS)
    "cos": {
        "bucket": "bucket",
        "policy": "bucket_policy",
    },
    
    # Cloudant
    "cloudant": {
        "database": "database",
        "document": "document",
        "table": "database",  # Cloudant doesn't have "tables", only databases
    },
    
    # Code Engine
    "code_engine": {
        "function": "function",
        "resource": "application",
        "minimum_tls_version_12": "application",
    },
    
    # Container Registry
    "container_registry": {
        "registry_lifecycle_policy": "retention_policy",
        "registry_policy": "namespace",
        "registry_replication_config": "namespace",
        "registry_repository": "namespace",
        "resource": "namespace",
    },
    
    # Cost Management
    "cost_management": {
        "management_allocation": "allocation",
        "management_anomaly": "anomaly_detector",
        "management_budget": "budget",
        "management_category": "tag",
        "management_commitment": "commitment",
    },
    
    # Data Services
    "data_virtualization": {
        "catalog_catalog": "catalog",
        "catalog_classifier": "classifier",
        "catalog_connection": "connection",
        "catalog_crawler": "crawler",
        "catalog_database": "database",
        "catalog_endpoint": "endpoint",
        "catalog_job": "job",
        "catalog_lineage": "lineage",
        "catalog_ml_transform": "transform",
        "catalog_partition": "partition",
    },
    
    # DataStage
    "datastage": {
        "object": "flow",
        "parameter": "parameter_set",
        "pipeline": "job",
    },
    
    # DNS Services
    "dns_services": {
        "health_check": "monitor",
        "key": "dnssec_key",
        "policy": "policy",
        "resource": "zone",
        "resource_record_set": "resource_record",
        "rsasha1_in_use_to_zone_sign_in_dnssec": "zone",
        "zone": "zone",
    },
    
    # Event Notifications
    "event_notifications": {
        "notifications_topic_subscription_configured": "subscription",
        "streams_analytics_application": "application",
        "streams_firehose": "destination",
        "streams_stream": "topic",
        "streams_stream_consumer": "subscription",
        "streams_subscription": "subscription",
        "streams_topic": "topic",
        "streams_video_stream": "source",
    },
    
    # File Storage
    "file_storage": {
        "storage_share": "share",
    },
    
    # Key Protect
    "key_protect": {
        "instance": "instance",
        "key": "key",
        "protect_alias": "key",
        "protect_certificate": "key",
        "protect_cmk_are_used": "key",
        "protect_cmk_not_deleted_unintentionally": "key",
        "protect_cmk_not_multi_region": "key",
        "protect_configuration": "instance_policy",
        "protect_encryption": "key",
        "protect_grant": "key_policy",
        "protect_key": "key",
        "protect_managed": "key",
        "protect_parameter": "instance_policy",
        "protect_patch": "key",
        "protect_private_ca": "key",
        "protect_store": "instance",
    },
    
    # Kubernetes Service
    "kubernetes_service": {
        "cluster": "cluster",
        "resource": "cluster",
        "service_addon": "cluster_addon",
        "service_admission_controller": "cluster",
        "service_cluster": "cluster",
        "service_namespace": "cluster",
        "service_network_policy": "cluster",
        "service_serverless": "cluster",
        "service_service": "cluster",
        "service_worker_node": "worker",
        "service_worker_pool": "worker_pool",
        "service_workload": "cluster",
    },
    
    # Log Analysis
    "log_analysis": {
        "log_destination": "target",
        "log_stream": "view",
        "query_definition": "view",
        "sink": "target",
        "store": "instance",
    },
    
    # Monitoring
    "monitoring": {
        "alert": "alert",
        "anomaly_detector": "alert",
        "dashboard": "dashboard",
        "log": "capture",
        "notification_channel": "notification_channel",
        "sampling_rule": "capture",
        "trace": "capture",
    },
    
    # MQ (Message Queue)
    "mq": {
        "broker_active_deployment_mode": "queue_manager",
        "cluster": "queue_manager",
        "resource": "queue_manager",
    },
    
    # Object Storage (COS)
    "cos": {
        "storage": "bucket",
        "storage_bucket": "bucket",
        "storage_notification": "notification_configuration",
        "storage_policy": "bucket_policy",
    },
    
    # OpenShift Service
    "openshift_service": {
        "cluster": "cluster",
        "image_provenance_registry_sources_configured": "cluster",
        "kubelet_client_ca_file_verification": "worker",
        "namespace_resource_verification": "cluster",
        "network": "cluster",
        "resource": "cluster",
        "scc_capabilities_minimized": "security_context_constraint",
        "scc_enforce_non_root_containers": "security_context_constraint",
        "scc_host_ipc_restriction": "security_context_constraint",
        "service": "cluster",
        "vm_admin_role_access_not_allowed": "cluster",
    },
    
    # Resource Controller
    "resource_controller": {
        "controller_aggregation": "resource_group",
        "controller_aggregator": "resource_group",
        "controller_delivery": "resource_group",
        "controller_folder": "resource_group",
        "controller_organization": "resource_group",
        "controller_policy": "resource_group",
        "controller_project": "resource_group",
        "controller_recorder": "resource_instance",
        "account": "account",
        "resource": "resource_instance",
    },
    
    # Schematics (IaC)
    "schematics": {
        "managed": "workspace",
        "workspace": "workspace",
    },
    
    # Secrets Manager
    "secrets_manager": {
        "resource": "secret",
    },
    
    # Security and Compliance Center
    "security_compliance": {
        "advisor_assessment": "assessment",
        "advisor_automation": "rule",
        "advisor_baseline": "profile",
        "advisor_breach_detection": "finding",
        "advisor_centrally_managed": "profile",
        "advisor_custom_identifier": "rule",
        "advisor_detector": "rule",
        "advisor_finding": "finding",
        "advisor_hub": "profile",
        "advisor_ip_set": "rule",
        "resource": "profile",
    },
    
    # VPC (Virtual Private Cloud)
    "vpc": {
        "different_regions": "vpc",
        "ebs": "volume",  # IBM uses "volume", not EBS
        "endpoint_connections_trust_boundaries": "endpoint_gateway",
        "endpoint_services_allowed_principals_trust_boundaries": "endpoint_gateway",
        "group": "security_group",
        "network": "vpc",
        "networkacl": "network_acl",
        "securitygroup": "security_group",
        "securitygroup_default_restrict_traffic": "security_group",
        "subnet_different_az": "subnet",
        "tunnel": "vpn_gateway",
    },
    
    # VSI (Virtual Server Instance)
    "vsi": {
        "elastic": "floating_ip",
        "elastic_ip_shodan": "floating_ip",
        "elastic_ip_unassigned": "floating_ip",
        "instance": "instance",
        "launch_template_no_secrets": "instance_template",
        "management_compliance": "instance",
        "networkacl_unused": "network_acl",
        "patch_compliance": "instance",
        "resource": "instance",
        "securitygroup_common_ports_restricted": "security_group",
        "securitygroup_restricted": "security_group",
        "securitygroup_unrestricted": "security_group",
        "snapshot": "snapshot",
        "ssm_managed_compliant_association": "instance",
        "volume": "volume",
        "vpc_multi_subnets_different_az": "subnet",
    },
    
    # Watson Machine Learning
    "watson_machine_learning": {
        "machine_learning_auto_ml": "training",
        "machine_learning_batch_scoring": "deployment",
        "machine_learning_data_set": "data_asset",
        "machine_learning_deployment": "deployment",
        "machine_learning_feature_store": "data_asset",
        "machine_learning_hyperparameter_tuning": "training",
        "machine_learning_model": "model",
        "machine_learning_model_monitoring": "monitor",
        "machine_learning_model_version": "model",
        "machine_learning_pipeline": "pipeline",
    },
}

# =============================================================================
# MULTI-CLOUD SERVICES (AWS, Azure, GCP)
# =============================================================================

MULTICLOUD_AWS_SERVICES = [
    "awslambda", "ec2", "ebs", "s3", "rds", "dynamodb", "elb", "elbv2",
    "lambda", "sqs", "sns", "cloudtrail", "ecr", "ecs", "efs", "emr",
    "elasticache", "elasticbeanstalk", "fsx", "glue", "guardduty",
    "kinesis", "neptune", "opensearch", "redshift", "route53", "sagemaker",
    "ssm", "stepfunctions", "storagegateway", "transfer", "waf", "wafv2",
    "athena", "bedrock", "codeartifact", "codebuild", "dms", "datasync",
    "directconnect", "directoryservice", "documentdb", "networkfirewall",
    "securityhub", "servicecatalog", "shield", "workspaces",
]

MULTICLOUD_AZURE_SERVICES = [
    "entra", "defender", "keyvault", "monitor", "vm",
]

MULTICLOUD_GCP_SERVICES = [
    "bigquery", "gcr", "cloudsql", "dataproc",
]

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

def is_ibm_native_service(service_name: str) -> bool:
    """Check if a service is IBM Cloud native."""
    return service_name in IBM_SERVICE_MAPPINGS and \
           service_name not in MULTICLOUD_AWS_SERVICES and \
           service_name not in MULTICLOUD_AZURE_SERVICES and \
           service_name not in MULTICLOUD_GCP_SERVICES

def is_multi_cloud_service(service_name: str) -> bool:
    """Check if a service is multi-cloud (AWS/Azure/GCP)."""
    return service_name in MULTICLOUD_AWS_SERVICES or \
           service_name in MULTICLOUD_AZURE_SERVICES or \
           service_name in MULTICLOUD_GCP_SERVICES

def get_official_service_name(current_name: str) -> str:
    """Get the official IBM Cloud SDK service name."""
    return IBM_SERVICE_MAPPINGS.get(current_name, current_name)

def get_official_resource_name(service: str, current_resource: str) -> str:
    """Get the official IBM Cloud SDK resource name for a service."""
    official_service = get_official_service_name(service)
    
    if official_service in IBM_RESOURCE_MAPPINGS:
        return IBM_RESOURCE_MAPPINGS[official_service].get(
            current_resource, 
            current_resource
        )
    
    return current_resource

def validate_ibm_rule(rule_id: str) -> dict:
    """
    Validate an IBM rule ID against official IBM Cloud Python SDK.
    
    Returns:
        dict with keys: is_valid, issues, recommendations
    """
    parts = rule_id.split('.')
    
    if len(parts) < 4:
        return {
            "is_valid": False,
            "issues": ["Rule ID must have at least 4 parts"],
            "recommendations": []
        }
    
    csp, service, resource, *assertion = parts
    assertion = '.'.join(assertion)
    
    issues = []
    recommendations = []
    
    # Check if IBM native or multi-cloud
    if is_multi_cloud_service(service):
        issues.append(f"Multi-cloud service '{service}' detected (AWS/Azure/GCP)")
        recommendations.append(f"Consider mapping to IBM equivalent or keeping AWS/Azure SDK naming")
    elif is_ibm_native_service(service):
        # Validate service name
        official_service = get_official_service_name(service)
        if official_service != service:
            issues.append(f"Service '{service}' should be '{official_service}'")
            recommendations.append(f"ibm.{service}.* → ibm.{official_service}.*")
        
        # Validate resource name
        official_resource = get_official_resource_name(service, resource)
        if official_resource != resource:
            issues.append(f"Resource '{resource}' should be '{official_resource}'")
            recommendations.append(f"ibm.{service}.{resource}.* → ibm.{official_service}.{official_resource}.*")
    else:
        issues.append(f"Unknown service '{service}'")
        recommendations.append("Manual review needed")
    
    return {
        "is_valid": len(issues) == 0,
        "issues": issues,
        "recommendations": recommendations
    }

if __name__ == "__main__":
    print("IBM Cloud Python SDK Validation Mappings Loaded")
    print(f"IBM Native Services: {len([s for s in IBM_SERVICE_MAPPINGS if is_ibm_native_service(s)])}")
    print(f"Multi-Cloud Services: AWS={len(MULTICLOUD_AWS_SERVICES)}, Azure={len(MULTICLOUD_AZURE_SERVICES)}, GCP={len(MULTICLOUD_GCP_SERVICES)}")

