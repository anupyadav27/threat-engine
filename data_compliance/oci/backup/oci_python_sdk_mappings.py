"""
Oracle Cloud Infrastructure (OCI) Python SDK Mappings

This module provides comprehensive mappings for OCI services and resources
to their official Python SDK equivalents.

Based on official OCI Python SDK package: oci
Documentation: https://docs.oracle.com/en-us/iaas/tools/python/latest/

Key SDK Modules:
- oci.core (Compute, Networking, Block Volume)
- oci.database (Autonomous DB, MySQL, etc.)
- oci.object_storage (Object Storage)
- oci.identity (IAM)
- oci.load_balancer (Load Balancing)
- oci.key_management (KMS/Vault)
- oci.container_engine (OKE - Kubernetes)
- oci.analytics (Analytics)
- oci.data_catalog (Data Catalog)
- oci.data_science (Data Science)
- oci.functions (Functions)
- oci.monitoring (Monitoring)
- oci.logging (Logging)
And 50+ more services...
"""

# =============================================================================
# OCI SERVICE MAPPINGS (Current → Official OCI Python SDK)
# =============================================================================

OCI_SERVICE_MAPPINGS = {
    # Compute Services
    "compute": "compute",  # oci.core.ComputeClient
    "ec2": "compute",  # AWS EC2 → OCI Compute
    "block_volume": "block_storage",  # oci.core.BlockstorageClient
    "block_storage": "block_storage",  # oci.core.BlockstorageClient
    "vcn": "virtual_network",  # oci.core.VirtualNetworkClient
    "network": "virtual_network",  # oci.core.VirtualNetworkClient
    "networking": "virtual_network",  # oci.core.VirtualNetworkClient
    
    # Database Services
    "autonomous_data_warehouse": "database",  # oci.database.DatabaseClient
    "autonomous_data_warehouse_adw": "database",
    "autonomous_db": "database",
    "autonomous_database": "database",
    "adw": "database",
    "adb": "database",
    "rds": "database",  # AWS RDS → OCI Database
    "redshift": "database",  # AWS Redshift → OCI ADW
    "dynamodb": "nosql",  # AWS DynamoDB → OCI NoSQL
    "elasticache": "redis",  # AWS ElastiCache → OCI Redis
    "adb_adw_projects": "database",
    "adw_adb_partitions": "database",
    "adw_adb_partitions_metadata": "database",
    "adw_adb_schemas": "database",
    "adw_backup_snapshot": "database",
    "adw_external_tables_hive_metastore_entries": "database",
    "adw_hdfs_os_objects": "database",
    "adw_network_acl_iam": "database",
    "adw_parameter_sets_init_params": "database",
    "adw_parameters_profile": "database",
    "adw_private_endpoint_vpn": "database",
    "autonomous_data_lakehouse_adw_schemas": "database",
    "autonomous_data_warehouse_adw": "database",
    "autonomous_db_db_system_entries": "database",
    "db_backup": "database",
    "db_backups": "database",
    "db_external_tables": "database",
    "db_options_features_parameterized": "database",
    "db_parameter_groups_db_systems": "database",
    "db_schemas": "database",
    "db_schemas_adb_adw": "database",
    "db_subnet_vcn_subnets": "virtual_network",
    "db_tables_adb_adw": "database",
    "db_users_db_native_iam_db_auth_where_supported": "database",
    "db_volume_restore": "database",
    "mysql": "mysql",  # oci.mysql.DbSystemClient
    "nosql": "nosql",  # oci.nosql.NosqlClient
    "redis": "redis",  # OCI Cache with Redis
    
    # Data & Analytics
    "data_catalog": "data_catalog",  # oci.data_catalog.DataCatalogClient
    "data_science": "data_science",  # oci.data_science.DataScienceClient
    "data_flow": "data_flow",  # oci.data_flow.DataFlowClient
    "data_flow_applications": "data_flow",
    "data_flow_di_transforms": "data_flow",
    "data_flow_notebooks_jupyter_via_ds": "data_science",  # Notebooks → Data Science
    "data_flow_spark_ml": "data_flow",
    "data_integration": "data_integration",  # oci.data_integration.DataIntegrationClient
    "data_integration_artifact": "data_integration",
    "data_integration_checks": "data_integration",
    "data_integration_connections": "data_integration",
    "data_integration_dq_custom": "data_integration",
    "data_integration_dq_expression": "data_integration",
    "data_integration_dq_recommendation": "data_integration",
    "data_integration_dq_ruleset": "data_integration",
    "data_integration_dq_run": "data_integration",
    "data_integration_pipelines": "data_integration",
    "data_integration_tasks": "data_integration",
    "analytics": "analytics",  # oci.analytics.AnalyticsClient
    "oac_adw_backups_snapshots": "analytics",  # Oracle Analytics Cloud
    "oac_adw_workspaces_projects": "analytics",
    "oac_datasets": "analytics",
    "oac_folders_projects": "analytics",
    "oac_users_identity_domains": "identity",  # Users → Identity
    "big_data_service": "bds",  # oci.bds.BdsClient
    "big_data_service_if_used": "bds",
    
    # Storage
    "object_storage": "object_storage",  # oci.object_storage.ObjectStorageClient
    "s3": "object_storage",  # AWS S3 → OCI Object Storage
    "object_storage_lifecycle_policies": "object_storage",
    "object_storage_object": "object_storage",
    "object_storage_prefixes_adw_partitions": "object_storage",
    "object_storage_replication": "object_storage",
    "object_events_events_notifications_functions": "events",  # Events service
    "file_storage": "file_storage",  # oci.file_storage.FileStorageClient
    "archive_storage": "object_storage",  # Part of object storage
    
    # Kubernetes & Containers
    "oke": "container_engine",  # oci.container_engine.ContainerEngineClient
    "container_engine": "container_engine",
    "eks": "container_engine",  # AWS EKS → OCI OKE
    "aks": "container_engine",  # Azure AKS → OCI OKE
    "ecs": "container_instances",  # AWS ECS → OCI Container Instances
    "container_instances": "container_instances",  # oci.container_instances
    
    # Security & Identity
    "iam": "identity",  # oci.identity.IdentityClient
    "identity": "identity",
    "identity_domains": "identity",
    "identity_domains_idp": "identity",
    "identity_domains_saml_federation": "identity",
    "identity_domains_user_data_requests_via_workflow": "identity",
    "identity_domains_conditional_mfa": "identity",
    "identity_domains_groups": "identity",
    "identity_domains_policies_iam": "identity",
    "identity_domains_users": "identity",
    "kms": "key_management",  # oci.key_management.KmsVaultClient (also AWS KMS)
    "vault": "key_management",
    "key_management": "key_management",
    "cloud_guard": "cloud_guard",  # oci.cloud_guard.CloudGuardClient
    "cloud_guard_custom_detectors": "cloud_guard",
    "cloud_guard_dashboard": "cloud_guard",
    "cloud_guard_targets": "cloud_guard",
    "security_zone": "cloud_guard",
    "bastion": "bastion",  # oci.bastion.BastionClient
    "certificates": "certificates",  # oci.certificates.CertificatesClient
    "certificates_service": "certificates",
    "data_safe": "data_safe",  # oci.data_safe.DataSafeClient
    "data_safe_db_compliance": "data_safe",
    "data_safe_masking_policies": "data_safe",
    "data_safe_security_assessment": "data_safe",
    "data_safe_target_database": "data_safe",
    "data_safe_user_assessment": "data_safe",
    
    # Networking Services
    "load_balancer": "load_balancer",  # oci.load_balancer.LoadBalancerClient
    "lb_backend_set_backend_pool": "load_balancer",
    "elb": "load_balancer",  # AWS ELB → OCI Load Balancer
    "network_load_balancer": "network_load_balancer",
    "dns": "dns",  # oci.dns.DnsClient
    "waf": "waf",  # oci.waf.WafClient
    "web_application_firewall": "waf",
    "cloudfront": "cdn",  # AWS CloudFront → OCI CDN
    "cdn": "cdn",  # oci.cdn (via Akamai partnership)
    "ipsec_vpn": "virtual_network",  # VPN is part of VCN
    "network_security_group_nsg": "virtual_network",
    "nsg_based_segmentation": "virtual_network",
    "nsg_egress_rule": "virtual_network",
    "nsg_ingress_rule": "virtual_network",
    "nsg_security_lists_for_db": "virtual_network",
    "nsg_security_lists_iam": "virtual_network",
    "network_firewall": "network_firewall",  # oci.network_firewall.NetworkFirewallClient
    "network_firewall_objects": "network_firewall",
    
    # Monitoring & Management
    "monitoring": "monitoring",  # oci.monitoring.MonitoringClient
    "monitoring_flow_logs_vcn_flow_logs_via_logging": "logging",  # Flow logs → Logging
    "logging": "logging",  # oci.logging.LoggingManagementClient
    "logging_retention": "logging",
    "events": "events",  # oci.events.EventsClient
    "notifications": "ons",  # oci.ons.NotificationDataPlaneClient
    "alarms": "monitoring",  # Part of monitoring
    "alarms_escalation": "monitoring",
    
    # Functions & Serverless
    "functions": "functions",  # oci.functions.FunctionsManagementClient
    "lambda": "functions",  # AWS Lambda → OCI Functions
    "api_gateway": "apigateway",  # oci.apigateway.ApiGatewayClient
    "api_gateway_stage_deployment": "apigateway",
    "api_gateway_api_keys_usage_plans": "apigateway",
    "api_gateway_jwt_custom_auth": "apigateway",
    "api_gateway_usage_plans_quotas": "apigateway",
    
    # Special Cases - N/A services (represent best practices that don't have a specific service)
    "n_a_use_compute_functions_oke": "compute",  # Best practice → use Compute/Functions/OKE
    "n_a_use_fn_dependencies_buildpacks": "functions",  # Best practice → use Functions
    "n_a_use_mysql_db_service_autonomous_db": "mysql",  # Best practice → use MySQL
    "n_a_use_oke_virtual_nodes_container_instances": "container_engine",  # Best practice → use OKE
    
    # API & Application Services
    "apis": "apigateway",  # oci.apigateway.ApiGatewayClient
    "oci_api_gateway_api": "apigateway",
    "oci_api_gateway_authorizer": "apigateway",
    "oci_api_gateway_deployment": "apigateway",
    "email": "email",  # oci.email.EmailClient
    "streaming": "streaming",  # oci.streaming.StreamClient
    "queue": "queue",  # oci.queue.QueueClient
    "sns": "ons",  # AWS SNS → OCI ONS (Oracle Notification Service)
    
    # Data Catalog Related
    "catalog_classifications": "data_catalog",
    "catalog_dq_fields": "data_catalog",
    "catalog_harvest_jobs_di_jobs": "data_catalog",
    "catalog_harvesters": "data_catalog",
    "catalog_integration_connections": "data_catalog",
    "catalog_metastore": "data_catalog",
    "catalog_policies_tags": "data_catalog",
    
    # Developer Services
    "devops": "devops",  # oci.devops.DevopsClient
    "resource_manager": "resource_manager",  # oci.resource_manager.ResourceManagerClient
    "artifacts": "artifacts",  # oci.artifacts.ArtifactsClient
    
    # Observability & Management
    "apm": "apm_control_plane",  # oci.apm_control_plane
    "application_performance_monitoring": "apm_control_plane",
    "os_management": "os_management",  # oci.os_management.OsManagementClient
    "operations_insights": "opsi",  # oci.opsi.OperationsInsightsClient
    
    # AI & ML
    "ai_services": "ai_language",  # oci.ai_language, ai_vision, ai_speech
    "anomaly_detection": "ai_anomaly_detection",  # oci.ai_anomaly_detection
    "anomaly_detection_net_metrics": "ai_anomaly_detection",
    "ai_anomaly_detection": "ai_anomaly_detection",
    "oci_anomaly_detection_service": "ai_anomaly_detection",
    "language": "ai_language",
    "vision": "ai_vision",
    "speech": "ai_speech",
    "data_science_artifact": "data_science",
    "data_science_deployment_config": "data_science",
    "data_science_endpoint": "data_science",
    "data_science_endpoint_vcn_secured": "data_science",
    "data_science_experiments": "data_science",
    "data_science_experiments_trials": "data_science",
    "data_science_hpo": "data_science",
    "data_science_hpo_via_sdk": "data_science",
    "data_science_job": "data_science",
    "data_science_job_transform": "data_science",
    "data_science_jobs_governed_by_iam_vault": "data_science",
    "data_science_model": "data_science",
    "data_science_model_artifact": "data_science",
    "data_science_notebook": "data_science",
    "data_science_notebook_session": "data_science",
    "data_science_pipeline": "data_science",
    "data_science_pipelines": "data_science",
    
    # Backup & DR
    "backup": "database",  # Part of database for DB backups
    "backup_jobs": "database",
    "block_volume_backups": "block_storage",
    "block_volume_replication": "block_storage",
    "block_volume_boot_volume_snapshot": "block_storage",
    
    # Audit & Governance
    "audit": "audit",  # oci.audit.AuditClient
    "audit_object_storage_logging": "audit",
    "compliance": "cloud_guard",
    
    # Edge Services
    "healthchecks": "healthchecks",  # oci.healthchecks.HealthChecksClient
    "traffic_management": "dns",  # Part of DNS
    
    # Integration
    "integration": "integration",  # oci.integration.IntegrationInstanceClient
    "service_mesh": "service_mesh",  # oci.service_mesh.ServiceMeshClient
    
    # Automation
    "automation": "oda",  # oci.oda.OdaClient (Digital Assistant)
    "automation_via_functions": "functions",
    
    # Service Connector Hub
    "service_connector": "sch",  # oci.sch.ServiceConnectorClient
    
    # Marketplace
    "marketplace": "marketplace",  # oci.marketplace.MarketplaceClient
    
    # Limits & Usage
    "limits": "limits",  # oci.limits.LimitsClient
    "usage": "usage_api",  # oci.usage_api.UsageapiClient
    "budgets": "budget",  # oci.budget.BudgetClient
}

# =============================================================================
# OCI RESOURCE MAPPINGS (BY SERVICE)
# =============================================================================

OCI_RESOURCE_MAPPINGS = {
    # Compute
    "compute": {
        "instance": "instance",
        "image": "image",
        "boot_volume": "boot_volume",
        "boot_volume_attachment": "boot_volume_attachment",
        "volume_attachment": "volume_attachment",
        "instance_configuration": "instance_configuration",
        "instance_pool": "instance_pool",
        "dedicated_vm_host": "dedicated_vm_host",
        "cluster_network": "cluster_network",
    },
    
    # Block Storage
    "block_storage": {
        "volume": "volume",
        "boot_volume": "boot_volume",
        "backup": "volume_backup",
        "boot_volume_backup": "boot_volume_backup",
        "volume_group": "volume_group",
        "volume_group_backup": "volume_group_backup",
        "block_volume_replication": "volume_group_replica",
        "resource": "volume",  # Generic → volume
    },
    
    # Virtual Network
    "virtual_network": {
        "vcn": "vcn",
        "subnet": "subnet",
        "security_list": "security_list",
        "network_security_group": "network_security_group",
        "route_table": "route_table",
        "internet_gateway": "internet_gateway",
        "nat_gateway": "nat_gateway",
        "service_gateway": "service_gateway",
        "drg": "drg",
        "drg_attachment": "drg_attachment",
        "public_ip": "public_ip",
        "private_ip": "private_ip",
        "vnic": "vnic",
        "resource": "vcn",  # Generic → vcn
    },
    
    # Database
    "database": {
        "autonomous_database": "autonomous_database",
        "db_system": "db_system",
        "db_home": "db_home",
        "database": "database",
        "backup": "backup",
        "pluggable_database": "pluggable_database",
        "external_database": "external_container_database",
        "resource": "autonomous_database",  # Generic → autonomous_database
    },
    
    # Object Storage
    "object_storage": {
        "bucket": "bucket",
        "object": "object",
        "preauthenticated_request": "preauthenticated_request",
        "replication_policy": "replication_policy",
        "retention_rule": "retention_rule",
        "resource": "bucket",  # Generic → bucket
    },
    
    # File Storage
    "file_storage": {
        "file_system": "file_system",
        "mount_target": "mount_target",
        "export": "export",
        "export_set": "export_set",
        "snapshot": "snapshot",
        "resource": "file_system",  # Generic → file_system
    },
    
    # Container Engine (OKE)
    "container_engine": {
        "cluster": "cluster",
        "node_pool": "node_pool",
        "workload": "workload",
        "resource": "cluster",  # Generic → cluster
    },
    
    # Identity
    "identity": {
        "user": "user",
        "group": "group",
        "policy": "policy",
        "compartment": "compartment",
        "dynamic_group": "dynamic_group",
        "network_source": "network_source",
        "identity_provider": "identity_provider",
        "api_key": "api_key",
        "auth_token": "auth_token",
        "resource": "user",  # Generic → user
    },
    
    # Key Management
    "key_management": {
        "vault": "vault",
        "key": "key",
        "key_version": "key_version",
        "resource": "vault",  # Generic → vault
    },
    
    # Load Balancer
    "load_balancer": {
        "load_balancer": "load_balancer",
        "backend_set": "backend_set",
        "backend": "backend",
        "listener": "listener",
        "certificate": "certificate",
        "path_route_set": "path_route_set",
        "rule_set": "rule_set",
        "resource": "load_balancer",  # Generic → load_balancer
    },
    
    # API Gateway
    "apigateway": {
        "gateway": "gateway",
        "deployment": "deployment",
        "api": "api",
        "resource": "gateway",  # Generic → gateway
    },
    
    # Functions
    "functions": {
        "application": "application",
        "function": "function",
        "resource": "application",  # Generic → application
    },
    
    # Monitoring
    "monitoring": {
        "alarm": "alarm",
        "metric": "metric",
        "resource": "alarm",  # Generic → alarm
    },
    
    # Logging
    "logging": {
        "log_group": "log_group",
        "log": "log",
        "unified_agent_configuration": "unified_agent_configuration",
        "resource": "log_group",  # Generic → log_group
    },
    
    # Data Catalog
    "data_catalog": {
        "catalog": "catalog",
        "data_asset": "data_asset",
        "connection": "connection",
        "glossary": "glossary",
        "term": "term",
        "resource": "catalog",  # Generic → catalog
    },
    
    # Data Science
    "data_science": {
        "project": "project",
        "notebook_session": "notebook_session",
        "model": "model",
        "model_deployment": "model_deployment",
        "job": "job",
        "pipeline": "pipeline",
        "model_artifact": "model",
        "deployment_config": "model_deployment",
        "endpoint": "model_deployment",
        "experiment": "project",
        "hpo_job": "job",
        "resource": "project",  # Generic → project
    },
    
    # Data Flow
    "data_flow": {
        "application": "application",
        "run": "run",
        "private_endpoint": "private_endpoint",
        "resource": "application",  # Generic → application
    },
    
    # Data Integration
    "data_integration": {
        "workspace": "workspace",
        "application": "application",
        "connection": "connection",
        "data_asset": "data_asset",
        "task": "task",
        "pipeline": "pipeline",
        "artifact": "application",
        "resource": "workspace",  # Generic → workspace
    },
    
    # Data Catalog
    "data_catalog": {
        "catalog": "catalog",
        "data_asset": "data_asset",
        "connection": "connection",
        "glossary": "glossary",
        "term": "term",
        "classification": "custom_property",
        "harvest_job": "job",
        "metastore": "metastore",
        "resource": "catalog",  # Generic → catalog
    },
    
    # Data Safe
    "data_safe": {
        "target_database": "target_database",
        "security_assessment": "security_assessment",
        "user_assessment": "user_assessment",
        "masking_policy": "masking_policy",
        "sensitive_data_model": "sensitive_data_model",
        "resource": "target_database",  # Generic → target_database
    },
    
    # Analytics
    "analytics": {
        "instance": "analytics_instance",
        "private_access_channel": "private_access_channel",
        "vanity_url": "vanity_url",
        "resource": "analytics_instance",  # Generic → analytics_instance
    },
    
    # BDS (Big Data Service)
    "bds": {
        "bds_instance": "bds_instance",
        "metastore_config": "bds_metastore_configuration",
        "api_key": "bds_api_key",
        "resource": "bds_instance",  # Generic → bds_instance
    },
    
    # Cloud Guard
    "cloud_guard": {
        "target": "target",
        "detector_recipe": "detector_recipe",
        "responder_recipe": "responder_recipe",
        "managed_list": "managed_list",
        "resource": "target",  # Generic → target
    },
    
    # WAF
    "waf": {
        "web_app_firewall": "web_app_firewall",
        "web_app_firewall_policy": "web_app_firewall_policy",
        "address_list": "network_address_list",
        "protection_rule": "protection_rule",
        "resource": "web_app_firewall",  # Generic → web_app_firewall
    },
    
    # Network Firewall
    "network_firewall": {
        "network_firewall": "network_firewall",
        "network_firewall_policy": "network_firewall_policy",
        "address_list": "address_list",
        "service_list": "service_list",
        "resource": "network_firewall",  # Generic → network_firewall
    },
    
    # DevOps
    "devops": {
        "project": "project",
        "repository": "repository",
        "build_pipeline": "build_pipeline",
        "deployment_pipeline": "deployment_pipeline",
        "trigger": "trigger",
        "resource": "project",  # Generic → project
    },
    
    # Events
    "events": {
        "rule": "rule",
        "resource": "rule",  # Generic → rule
    },
    
    # ONS (Notification Service)
    "ons": {
        "topic": "topic",
        "subscription": "subscription",
        "resource": "topic",  # Generic → topic
    },
    
    # Resource Manager
    "resource_manager": {
        "stack": "stack",
        "job": "job",
        "configuration_source_provider": "configuration_source_provider",
        "instance": "stack",  # Common alias
        "resource": "stack",  # Generic → stack
    },
}

# =============================================================================
# COMMON OCI PATTERNS FOR MISSING SERVICES
# =============================================================================

def get_official_service_name(current_name: str) -> str:
    """Get the official OCI Python SDK service name."""
    # Direct mapping
    if current_name in OCI_SERVICE_MAPPINGS:
        return OCI_SERVICE_MAPPINGS[current_name]
    
    # Pattern-based inference
    if current_name.startswith("autonomous_"):
        return "database"
    if current_name.startswith("block_"):
        return "block_storage"
    if current_name.startswith("api_gateway_"):
        return "apigateway"
    if current_name.startswith("adw_") or current_name.startswith("adb_"):
        return "database"
    if current_name.startswith("db_"):
        return "database"
    if current_name.startswith("data_science_"):
        return "data_science"
    if current_name.startswith("data_flow_"):
        return "data_flow"
    if current_name.startswith("data_integration_"):
        return "data_integration"
    if current_name.startswith("data_safe_"):
        return "data_safe"
    if current_name.startswith("catalog_"):
        return "data_catalog"
    if current_name.startswith("object_storage_"):
        return "object_storage"
    if current_name.startswith("oac_"):
        return "analytics"
    if current_name.startswith("identity_domains_"):
        return "identity"
    if current_name.startswith("nsg_"):
        return "virtual_network"
    if current_name.startswith("cloud_guard_"):
        return "cloud_guard"
    if current_name.startswith("n_a_use_"):
        # Special handling for N/A services
        if "compute" in current_name or "oke" in current_name:
            return "compute"
        if "function" in current_name or "fn_" in current_name:
            return "functions"
        if "mysql" in current_name or "db_" in current_name:
            return "mysql"
        return "compute"  # Default for N/A cases
    if "data_warehouse" in current_name:
        return "database"
    if "datalake" in current_name or "data_lake" in current_name:
        return "data_catalog"
    if "analytics" in current_name:
        return "analytics"
    if "monitoring" in current_name or "logging" in current_name:
        if "flow_log" in current_name:
            return "logging"
        return "monitoring"
    if "oci_" in current_name:
        # Remove oci_ prefix and try again
        cleaned = current_name.replace("oci_", "")
        if cleaned in OCI_SERVICE_MAPPINGS:
            return OCI_SERVICE_MAPPINGS[cleaned]
    
    # Return as-is if no mapping found
    return current_name

def get_official_resource_name(service: str, current_resource: str) -> str:
    """Get the official OCI Python SDK resource name for a service."""
    official_service = get_official_service_name(service)
    
    if official_service in OCI_RESOURCE_MAPPINGS:
        mappings = OCI_RESOURCE_MAPPINGS[official_service]
        if current_resource in mappings:
            return mappings[current_resource]
    
    # Generic "resource" should be mapped to service-appropriate default
    if current_resource == "resource":
        # Return most common resource type for the service
        if official_service == "database":
            return "autonomous_database"
        elif official_service == "block_storage":
            return "volume"
        elif official_service == "object_storage":
            return "bucket"
        elif official_service == "compute":
            return "instance"
        elif official_service == "container_engine":
            return "cluster"
        elif official_service == "virtual_network":
            return "vcn"
        elif official_service == "identity":
            return "user"
        elif official_service == "key_management":
            return "vault"
        elif official_service == "functions":
            return "application"
        elif official_service == "apigateway":
            return "gateway"
    
    return current_resource

if __name__ == "__main__":
    print("OCI Python SDK Mappings Loaded")
    print(f"Services Mapped: {len(OCI_SERVICE_MAPPINGS)}")
    print(f"Resource Mappings: {len(OCI_RESOURCE_MAPPINGS)}")

