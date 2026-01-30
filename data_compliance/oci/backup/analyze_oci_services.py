#!/usr/bin/env python3
"""
OCI Service & Resource Normalization
Extracts services and resources from rule_ids.yaml and:
1. Validates they are actual OCI services
2. Maps non-OCI services to OCI equivalents
3. Normalizes names to match OCI Python SDK client names
4. Creates standardized service and resource mappings
"""

import yaml
from collections import Counter, defaultdict
import json

# Official OCI Python SDK Service Mappings
# Based on: https://docs.oracle.com/en-us/iaas/tools/python/latest/
OCI_SDK_SERVICES = {
    # Core Services (oci.core)
    "compute": {"sdk": "oci.core.ComputeClient", "module": "core", "valid": True},
    "block_storage": {"sdk": "oci.core.BlockstorageClient", "module": "core", "valid": True},
    "virtual_network": {"sdk": "oci.core.VirtualNetworkClient", "module": "core", "valid": True},
    
    # Database Services (oci.database, oci.mysql, oci.nosql)
    "database": {"sdk": "oci.database.DatabaseClient", "module": "database", "valid": True},
    "mysql": {"sdk": "oci.mysql.DbSystemClient", "module": "mysql", "valid": True},
    "nosql": {"sdk": "oci.nosql.NosqlClient", "module": "nosql", "valid": True},
    
    # Storage Services
    "object_storage": {"sdk": "oci.object_storage.ObjectStorageClient", "module": "object_storage", "valid": True},
    "file_storage": {"sdk": "oci.file_storage.FileStorageClient", "module": "file_storage", "valid": True},
    
    # Container & Kubernetes
    "container_engine": {"sdk": "oci.container_engine.ContainerEngineClient", "module": "container_engine", "valid": True},
    "container_instances": {"sdk": "oci.container_instances.ContainerInstanceClient", "module": "container_instances", "valid": True},
    
    # Identity & Security
    "identity": {"sdk": "oci.identity.IdentityClient", "module": "identity", "valid": True},
    "key_management": {"sdk": "oci.key_management.KmsVaultClient", "module": "key_management", "valid": True},
    "cloud_guard": {"sdk": "oci.cloud_guard.CloudGuardClient", "module": "cloud_guard", "valid": True},
    "vault": {"sdk": "oci.vault.VaultsClient", "module": "vault", "valid": True},
    "bastion": {"sdk": "oci.bastion.BastionClient", "module": "bastion", "valid": True},
    "certificates": {"sdk": "oci.certificates.CertificatesClient", "module": "certificates", "valid": True},
    
    # Data & Analytics
    "data_science": {"sdk": "oci.data_science.DataScienceClient", "module": "data_science", "valid": True},
    "data_catalog": {"sdk": "oci.data_catalog.DataCatalogClient", "module": "data_catalog", "valid": True},
    "data_flow": {"sdk": "oci.data_flow.DataFlowClient", "module": "data_flow", "valid": True},
    "data_integration": {"sdk": "oci.data_integration.DataIntegrationClient", "module": "data_integration", "valid": True},
    "analytics": {"sdk": "oci.analytics.AnalyticsClient", "module": "analytics", "valid": True},
    "bds": {"sdk": "oci.bds.BdsClient", "module": "bds", "valid": True},
    "data_safe": {"sdk": "oci.data_safe.DataSafeClient", "module": "data_safe", "valid": True},
    
    # Monitoring & Management
    "monitoring": {"sdk": "oci.monitoring.MonitoringClient", "module": "monitoring", "valid": True},
    "logging": {"sdk": "oci.logging.LoggingManagementClient", "module": "logging", "valid": True},
    "audit": {"sdk": "oci.audit.AuditClient", "module": "audit", "valid": True},
    "events": {"sdk": "oci.events.EventsClient", "module": "events", "valid": True},
    "ons": {"sdk": "oci.ons.NotificationDataPlaneClient", "module": "ons", "valid": True},
    
    # Networking
    "load_balancer": {"sdk": "oci.load_balancer.LoadBalancerClient", "module": "load_balancer", "valid": True},
    "network_load_balancer": {"sdk": "oci.network_load_balancer.NetworkLoadBalancerClient", "module": "network_load_balancer", "valid": True},
    "dns": {"sdk": "oci.dns.DnsClient", "module": "dns", "valid": True},
    "waf": {"sdk": "oci.waf.WafClient", "module": "waf", "valid": True},
    "network_firewall": {"sdk": "oci.network_firewall.NetworkFirewallClient", "module": "network_firewall", "valid": True},
    
    # Functions & API
    "functions": {"sdk": "oci.functions.FunctionsManagementClient", "module": "functions", "valid": True},
    "apigateway": {"sdk": "oci.apigateway.ApiGatewayClient", "module": "apigateway", "valid": True},
    
    # DevOps
    "devops": {"sdk": "oci.devops.DevopsClient", "module": "devops", "valid": True},
    "resource_manager": {"sdk": "oci.resource_manager.ResourceManagerClient", "module": "resource_manager", "valid": True},
    "artifacts": {"sdk": "oci.artifacts.ArtifactsClient", "module": "artifacts", "valid": True},
    
    # AI & ML
    "ai_anomaly_detection": {"sdk": "oci.ai_anomaly_detection.AnomalyDetectionClient", "module": "ai_anomaly_detection", "valid": True},
    "ai_language": {"sdk": "oci.ai_language.AIServiceLanguageClient", "module": "ai_language", "valid": True},
    "ai_vision": {"sdk": "oci.ai_vision.AIServiceVisionClient", "module": "ai_vision", "valid": True},
    "ai_speech": {"sdk": "oci.ai_speech.AIServiceSpeechClient", "module": "ai_speech", "valid": True},
    
    # Other Services
    "streaming": {"sdk": "oci.streaming.StreamClient", "module": "streaming", "valid": True},
    "queue": {"sdk": "oci.queue.QueueClient", "module": "queue", "valid": True},
    "email": {"sdk": "oci.email.EmailClient", "module": "email", "valid": True},
    "redis": {"sdk": "oci.redis.RedisClusterClient", "module": "redis", "valid": True},
    "healthchecks": {"sdk": "oci.healthchecks.HealthChecksClient", "module": "healthchecks", "valid": True},
}

# Non-OCI services that need mapping
NON_OCI_SERVICE_MAPPINGS = {
    # Generic/Invalid services
    "no": {"map_to": "identity", "reason": "Invalid service name", "valid": False},
    "object": {"map_to": "object_storage", "reason": "Incomplete service name", "valid": False},
    "acm": {"map_to": "certificates", "reason": "AWS ACM → OCI Certificates", "valid": False},
    "api": {"map_to": "apigateway", "reason": "Incomplete service name", "valid": False},
    "apigatewayv2": {"map_to": "apigateway", "reason": "Version-specific API Gateway", "valid": False},
    "app": {"map_to": "functions", "reason": "Generic app → Functions", "valid": False},
    "appsync": {"map_to": "apigateway", "reason": "AWS AppSync → API Gateway", "valid": False},
    "autoscaling": {"map_to": "compute", "reason": "Auto Scaling → Compute autoscale", "valid": False},
    "batch": {"map_to": "data_flow", "reason": "Batch jobs → Data Flow", "valid": False},
    "cloudformation": {"map_to": "resource_manager", "reason": "CloudFormation → Resource Manager", "valid": False},
    "cloudwatch": {"map_to": "monitoring", "reason": "CloudWatch → Monitoring", "valid": False},
    "codebuild": {"map_to": "devops", "reason": "CodeBuild → DevOps", "valid": False},
    "config": {"map_to": "cloud_guard", "reason": "AWS Config → Cloud Guard", "valid": False},
    "defender": {"map_to": "cloud_guard", "reason": "Azure Defender → Cloud Guard", "valid": False},
    "directconnect": {"map_to": "virtual_network", "reason": "Direct Connect → FastConnect", "valid": False},
    "dms": {"map_to": "database", "reason": "DMS → Database Migration", "valid": False},
    "docdb": {"map_to": "database", "reason": "DocumentDB → Autonomous DB", "valid": False},
    "ebs": {"map_to": "block_storage", "reason": "EBS → Block Storage", "valid": False},
    "ecr": {"map_to": "artifacts", "reason": "ECR → Artifact Registry", "valid": False},
    "ecs": {"map_to": "container_instances", "reason": "ECS → Container Instances", "valid": False},
    "efs": {"map_to": "file_storage", "reason": "EFS → File Storage", "valid": False},
    "emr": {"map_to": "bds", "reason": "EMR → Big Data Service", "valid": False},
    "eventbridge": {"map_to": "events", "reason": "EventBridge → Events", "valid": False},
    "guardduty": {"map_to": "cloud_guard", "reason": "GuardDuty → Cloud Guard", "valid": False},
    "inspector": {"map_to": "cloud_guard", "reason": "Inspector → Cloud Guard", "valid": False},
    "kinesis": {"map_to": "streaming", "reason": "Kinesis → Streaming", "valid": False},
    "lakeformation": {"map_to": "data_catalog", "reason": "Lake Formation → Data Catalog", "valid": False},
    "macie": {"map_to": "data_safe", "reason": "Macie → Data Safe", "valid": False},
    "mq": {"map_to": "streaming", "reason": "MQ → Streaming", "valid": False},
    "neptune": {"map_to": "database", "reason": "Neptune → Autonomous DB", "valid": False},
    "networkfirewall": {"map_to": "network_firewall", "reason": "AWS Network Firewall", "valid": False},
    "opensearch": {"map_to": "analytics", "reason": "OpenSearch → Analytics", "valid": False},
    "organizations": {"map_to": "identity", "reason": "Organizations → Identity Domains", "valid": False},
    "os": {"map_to": "compute", "reason": "OS Management", "valid": False},
    "rds": {"map_to": "database", "reason": "RDS → Database", "valid": False},
    "redshift": {"map_to": "database", "reason": "Redshift → Autonomous DW", "valid": False},
    "route53": {"map_to": "dns", "reason": "Route53 → DNS", "valid": False},
    "s3": {"map_to": "object_storage", "reason": "S3 → Object Storage", "valid": False},
    "sagemaker": {"map_to": "data_science", "reason": "SageMaker → Data Science", "valid": False},
    "secretsmanager": {"map_to": "vault", "reason": "Secrets Manager → Vault", "valid": False},
    "securityhub": {"map_to": "cloud_guard", "reason": "Security Hub → Cloud Guard", "valid": False},
    "servicecatalog": {"map_to": "resource_manager", "reason": "Service Catalog → Resource Manager", "valid": False},
    "ses": {"map_to": "email", "reason": "SES → Email Delivery", "valid": False},
    "sns": {"map_to": "ons", "reason": "SNS → ONS", "valid": False},
    "sqs": {"map_to": "queue", "reason": "SQS → Queue", "valid": False},
    "ssm": {"map_to": "compute", "reason": "SSM → OS Management", "valid": False},
    "stepfunctions": {"map_to": "data_integration", "reason": "Step Functions → Data Integration", "valid": False},
    "storagegateway": {"map_to": "object_storage", "reason": "Storage Gateway", "valid": False},
    "transfer": {"map_to": "object_storage", "reason": "Transfer Family → Object Storage", "valid": False},
    "wafv2": {"map_to": "waf", "reason": "WAFv2 → WAF", "valid": False},
    "workspaces": {"map_to": "compute", "reason": "WorkSpaces → Compute", "valid": False},
    "xray": {"map_to": "monitoring", "reason": "X-Ray → APM", "valid": False},
}

print("=" * 100)
print("OCI SERVICE & RESOURCE NORMALIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Extract services and resources
services_count = Counter()
resources_by_service = defaultdict(Counter)
service_examples = {}

for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        service = parts[1]
        resource = parts[2]
        
        services_count[service] += 1
        resources_by_service[service][resource] += 1
        
        if service not in service_examples:
            service_examples[service] = rule

print(f"Unique Services: {len(services_count)}")
print(f"Unique Resources: {sum(len(resources) for resources in resources_by_service.values())}")

# Analyze services
print(f"\n{'=' * 100}")
print("SERVICE ANALYSIS")
print(f"{'=' * 100}")

valid_oci_services = []
invalid_services = []
mapping_needed = []

service_analysis = {}

for service in sorted(services_count.keys()):
    count = services_count[service]
    
    if service in OCI_SDK_SERVICES:
        valid_oci_services.append(service)
        service_analysis[service] = {
            "status": "✅ Valid OCI Service",
            "sdk": OCI_SDK_SERVICES[service]["sdk"],
            "module": OCI_SDK_SERVICES[service]["module"],
            "rules": count,
            "action": "KEEP",
            "resources": list(resources_by_service[service].keys())
        }
    elif service in NON_OCI_SERVICE_MAPPINGS:
        mapping_needed.append(service)
        map_info = NON_OCI_SERVICE_MAPPINGS[service]
        service_analysis[service] = {
            "status": "⚠️  Needs Mapping",
            "map_to": map_info["map_to"],
            "reason": map_info["reason"],
            "target_sdk": OCI_SDK_SERVICES[map_info["map_to"]]["sdk"],
            "rules": count,
            "action": "MAP",
            "resources": list(resources_by_service[service].keys())
        }
    else:
        invalid_services.append(service)
        service_analysis[service] = {
            "status": "❌ Unknown Service",
            "rules": count,
            "action": "NEEDS_INVESTIGATION",
            "resources": list(resources_by_service[service].keys())
        }

print(f"\n✅ Valid OCI Services: {len(valid_oci_services)}")
print(f"⚠️  Services Needing Mapping: {len(mapping_needed)}")
print(f"❌ Unknown Services: {len(invalid_services)}")

# Display details
if mapping_needed:
    print(f"\n{'=' * 100}")
    print("SERVICES NEEDING MAPPING TO OCI")
    print(f"{'=' * 100}")
    for service in sorted(mapping_needed):
        info = service_analysis[service]
        print(f"\n{service} ({info['rules']} rules)")
        print(f"  → Map to: {info['map_to']}")
        print(f"  → Reason: {info['reason']}")
        print(f"  → Target SDK: {info['target_sdk']}")
        print(f"  → Resources: {', '.join(info['resources'][:5])}")
        if len(info['resources']) > 5:
            print(f"     ... and {len(info['resources']) - 5} more")

if invalid_services:
    print(f"\n{'=' * 100}")
    print("UNKNOWN/INVALID SERVICES")
    print(f"{'=' * 100}")
    for service in sorted(invalid_services):
        info = service_analysis[service]
        print(f"\n{service} ({info['rules']} rules)")
        print(f"  → Status: {info['status']}")
        print(f"  → Resources: {', '.join(info['resources'][:5])}")
        print(f"  → Example: {service_examples[service]}")

# Top valid services
print(f"\n{'=' * 100}")
print("TOP 20 VALID OCI SERVICES")
print(f"{'=' * 100}")
for service in [s for s in services_count.most_common(30) if s[0] in valid_oci_services][:20]:
    svc_name, count = service
    info = service_analysis[svc_name]
    print(f"{svc_name:30s} {count:4d} rules | {info['sdk']}")

# Generate mapping report
print(f"\n{'=' * 100}")
print("GENERATING DETAILED REPORTS")
print(f"{'=' * 100}")

# Save service analysis
with open('oci_service_analysis.json', 'w') as f:
    json.dump(service_analysis, f, indent=2)
print("✅ Saved: oci_service_analysis.json")

# Save service mapping recommendations
mapping_report = {
    "summary": {
        "total_services": len(services_count),
        "valid_oci_services": len(valid_oci_services),
        "need_mapping": len(mapping_needed),
        "unknown": len(invalid_services)
    },
    "valid_services": {s: service_analysis[s] for s in valid_oci_services},
    "services_to_map": {s: service_analysis[s] for s in mapping_needed},
    "unknown_services": {s: service_analysis[s] for s in invalid_services}
}

with open('oci_service_mapping_report.json', 'w') as f:
    json.dump(mapping_report, f, indent=2)
print("✅ Saved: oci_service_mapping_report.json")

# Generate resource analysis per service
resource_report = {}
for service, resources in resources_by_service.items():
    resource_report[service] = {
        "total_resources": len(resources),
        "resources": {res: count for res, count in resources.most_common()}
    }

with open('oci_resource_analysis.json', 'w') as f:
    json.dump(resource_report, f, indent=2)
print("✅ Saved: oci_resource_analysis.json")

print(f"\n{'=' * 100}")
print("SUMMARY")
print(f"{'=' * 100}")
print(f"Total Rules:              {len(rules)}")
print(f"Total Services:           {len(services_count)}")
print(f"  ✅ Valid OCI:           {len(valid_oci_services)} ({len(valid_oci_services)/len(services_count)*100:.1f}%)")
print(f"  ⚠️  Need Mapping:        {len(mapping_needed)} ({len(mapping_needed)/len(services_count)*100:.1f}%)")
print(f"  ❌ Unknown:             {len(invalid_services)} ({len(invalid_services)/len(services_count)*100:.1f}%)")
print(f"\nRules affected by mapping: {sum(services_count[s] for s in mapping_needed)}")
print(f"{'=' * 100}")

