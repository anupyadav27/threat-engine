#!/usr/bin/env python3
"""
Create manual catalogs for IBM Cloud services that are REST-only (no Python SDK).

These services are identified from service_analysis.txt but don't have Python SDK packages.
We create basic catalogs based on common REST API patterns and IBM Cloud documentation.
"""

import json
from pathlib import Path
from typing import Dict, Any

# REST-only services from service_analysis.txt
REST_ONLY_SERVICES = {
    'data_virtualization': {
        'description': 'Data Virtualization Service',
        'base_url': 'https://api.dataplatform.cloud.ibm.com',
        'operations': ['list_tables', 'get_table', 'query_data']
    },
    'watson_ml': {
        'description': 'Watson Machine Learning',
        'base_url': 'https://us-south.ml.cloud.ibm.com',
        'operations': ['list_models', 'get_model', 'deploy_model']
    },
    'security_advisor': {
        'description': 'Security Advisor',
        'base_url': 'https://us-south.advisor.cloud.ibm.com',
        'operations': ['list_findings', 'get_finding', 'update_finding']
    },
    'containers': {
        'description': 'IBM Kubernetes Service',
        'base_url': 'https://containers.cloud.ibm.com',
        'operations': ['list_clusters', 'get_cluster', 'list_workers']
    },
    'backup': {
        'description': 'IBM Cloud Backup Service',
        'base_url': 'https://api.backup.cloud.ibm.com',
        'operations': ['list_backups', 'get_backup', 'create_backup']
    },
    'cdn': {
        'description': 'Content Delivery Network',
        'base_url': 'https://api.cdn.cloud.ibm.com',
        'operations': ['list_distributions', 'get_distribution', 'purge_cache']
    },
    'monitoring': {
        'description': 'IBM Cloud Monitoring',
        'base_url': 'https://api.ingest.cloud.ibm.com',
        'operations': ['list_metrics', 'get_metric', 'query_metrics']
    },
    'event_notifications': {
        'description': 'Event Notifications Service',
        'base_url': 'https://api.event-notifications.cloud.ibm.com',
        'operations': ['list_topics', 'get_topic', 'publish_event']
    },
    'api_gateway': {
        'description': 'API Gateway',
        'base_url': 'https://api.apigateway.cloud.ibm.com',
        'operations': ['list_apis', 'get_api', 'deploy_api']
    },
    'datastage': {
        'description': 'DataStage Service',
        'base_url': 'https://api.dataplatform.cloud.ibm.com',
        'operations': ['list_jobs', 'get_job', 'run_job']
    },
    'activity_tracker': {
        'description': 'Activity Tracker',
        'base_url': 'https://api.logging.cloud.ibm.com',
        'operations': ['list_events', 'get_event', 'query_logs']
    },
    'dns': {
        'description': 'DNS Services',
        'base_url': 'https://api.dns.cloud.ibm.com',
        'operations': ['list_zones', 'get_zone', 'list_records']
    },
    'log_analysis': {
        'description': 'Log Analysis',
        'base_url': 'https://api.logging.cloud.ibm.com',
        'operations': ['list_logs', 'get_log', 'query_logs']
    },
    'file_storage': {
        'description': 'File Storage',
        'base_url': 'https://api.fs.cloud.ibm.com',
        'operations': ['list_shares', 'get_share', 'create_share']
    },
    'block_storage': {
        'description': 'Block Storage',
        'base_url': 'https://api.blockstorage.cloud.ibm.com',
        'operations': ['list_volumes', 'get_volume', 'create_volume']
    },
    'load_balancer': {
        'description': 'Load Balancer',
        'base_url': 'https://api.loadbalancer.cloud.ibm.com',
        'operations': ['list_load_balancers', 'get_load_balancer', 'create_load_balancer']
    },
    'internet_services': {
        'description': 'Internet Services',
        'base_url': 'https://api.internet.cloud.ibm.com',
        'operations': ['list_services', 'get_service']
    },
    'event_streams': {
        'description': 'Event Streams',
        'base_url': 'https://api.eventstreams.cloud.ibm.com',
        'operations': ['list_topics', 'get_topic', 'publish_message']
    },
    'security_compliance_center': {
        'description': 'Security and Compliance Center',
        'base_url': 'https://api.compliance.cloud.ibm.com',
        'operations': ['list_assessments', 'get_assessment', 'run_assessment']
    },
    'continuous_delivery': {
        'description': 'Continuous Delivery',
        'base_url': 'https://api.continuous-delivery.cloud.ibm.com',
        'operations': ['list_pipelines', 'get_pipeline', 'run_pipeline']
    },
    'cognos_dashboard': {
        'description': 'Cognos Dashboard',
        'base_url': 'https://api.cognos.cloud.ibm.com',
        'operations': ['list_dashboards', 'get_dashboard']
    },
    'analytics_engine': {
        'description': 'Analytics Engine',
        'base_url': 'https://api.analytics.cloud.ibm.com',
        'operations': ['list_clusters', 'get_cluster', 'submit_job']
    },
    'certificate_manager': {
        'description': 'Certificate Manager',
        'base_url': 'https://api.certificate-manager.cloud.ibm.com',
        'operations': ['list_certificates', 'get_certificate', 'import_certificate']
    },
    'account': {
        'description': 'Account Management',
        'base_url': 'https://api.account.cloud.ibm.com',
        'operations': ['get_account', 'list_accounts', 'update_account']
    },
    'direct_link': {
        'description': 'Direct Link',
        'base_url': 'https://api.directlink.cloud.ibm.com',
        'operations': ['list_connections', 'get_connection', 'create_connection']
    },
    'billing': {
        'description': 'Billing Service',
        'base_url': 'https://api.billing.cloud.ibm.com',
        'operations': ['list_invoices', 'get_invoice', 'get_usage']
    },
    'iam': {
        'description': 'Identity and Access Management (REST API)',
        'base_url': 'https://iam.cloud.ibm.com',
        'operations': ['list_users', 'get_user', 'list_policies', 'get_policy']
    },
    'object_storage': {
        'description': 'Object Storage (COS) - REST API',
        'base_url': 'https://s3.{region}.cloud-object-storage.appdomain.cloud',
        'operations': ['list_buckets', 'get_bucket', 'list_objects']
    },
    # Additional missing services
    'cloudant': {
        'description': 'Cloudant Database Service',
        'base_url': 'https://{account}.cloudant.com',
        'operations': ['list_databases', 'get_database', 'list_documents', 'get_document']
    },
    'code_engine': {
        'description': 'Code Engine Service',
        'base_url': 'https://api.codeengine.cloud.ibm.com',
        'operations': ['list_projects', 'get_project', 'list_apps', 'get_app', 'list_jobs', 'get_job']
    },
    'container_registry': {
        'description': 'Container Registry Service',
        'base_url': 'https://api.registry.cloud.ibm.com',
        'operations': ['list_namespaces', 'get_namespace', 'list_images', 'get_image']
    },
    'databases': {
        'description': 'Cloud Databases Service',
        'base_url': 'https://api.databases.cloud.ibm.com',
        'operations': ['list_deployments', 'get_deployment', 'list_backups', 'get_backup']
    },
    'key_protect': {
        'description': 'Key Protect Service',
        'base_url': 'https://{region}.kms.cloud.ibm.com',
        'operations': ['list_keys', 'get_key', 'create_key', 'rotate_key']
    },
    'secrets_manager': {
        'description': 'Secrets Manager Service',
        'base_url': 'https://{region}.secrets-manager.appdomain.cloud',
        'operations': ['list_secrets', 'get_secret', 'create_secret', 'rotate_secret']
    },
    'watson_discovery': {
        'description': 'Watson Discovery Service',
        'base_url': 'https://api.discovery.watson.cloud.ibm.com',
        'operations': ['list_environments', 'get_environment', 'list_collections', 'get_collection', 'query']
    }
}


def create_rest_service_catalog(service_name: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
    """Create a basic catalog structure for a REST-only service"""
    
    operations = []
    for op_name in service_info['operations']:
        # Determine operation type
        op_type = 'dependent'
        if 'list' in op_name.lower() or 'get_all' in op_name.lower():
            op_type = 'independent'
        
        operation = {
            'operation': op_name,
            'python_method': None,  # REST-only, no Python SDK method
            'yaml_action': op_name.replace('_', '-'),
            'required_params': [],
            'optional_params': [],
            'total_optional': 0,
            'operation_type': op_type,
            'description': service_info['description'],
            'rest_endpoint': f"{service_info['base_url']}/{op_name}",
            'output_fields': {},
            'item_fields': {}
        }
        operations.append(operation)
    
    catalog = {
        service_name: {
            'service': service_name,
            'package': None,  # REST-only, no Python package
            'service_class': None,
            'description': service_info['description'],
            'total_operations': len(operations),
            'independent': [op for op in operations if op['operation_type'] == 'independent'],
            'dependent': [op for op in operations if op['operation_type'] == 'dependent'],
            'operations': operations,
            'rest_api': True,
            'base_url': service_info['base_url']
        }
    }
    
    return catalog


def main():
    """Create catalogs for all REST-only services"""
    
    ibm_root = Path('pythonsdk-database/ibm')
    ibm_root.mkdir(parents=True, exist_ok=True)
    
    main_file = ibm_root / 'ibm_dependencies_with_python_names_fully_enriched.json'
    
    # Load existing data
    if main_file.exists():
        with open(main_file) as f:
            data = json.load(f)
    else:
        data = {}
    
    print(f"\n{'='*70}")
    print(f"CREATING REST-ONLY SERVICE CATALOGS")
    print(f"{'='*70}\n")
    
    added_count = 0
    skipped_count = 0
    
    for service_name, service_info in REST_ONLY_SERVICES.items():
        if service_name in data:
            print(f"⚠️  {service_name} - Already exists, skipping")
            skipped_count += 1
            continue
        
        print(f"Creating {service_name}...", end=" ")
        
        catalog = create_rest_service_catalog(service_name, service_info)
        data.update(catalog)
        
        # Create service folder
        service_dir = ibm_root / service_name
        service_dir.mkdir(exist_ok=True)
        
        service_file = service_dir / 'ibm_dependencies_with_python_names_fully_enriched.json'
        with open(service_file, 'w') as f:
            json.dump(catalog, f, indent=2)
        
        print(f"✅ ({len(service_info['operations'])} operations)")
        added_count += 1
    
    # Save updated main file
    with open(main_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Services added: {added_count}")
    print(f"Services skipped: {skipped_count}")
    print(f"Total services in database: {len([k for k in data.keys() if k not in ['total_services', 'metadata', 'version']])}")
    print(f"\n✅ REST-only service catalogs created")


if __name__ == '__main__':
    main()

