"""
Configuration management for onboarding module
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # Database Configuration
    # NOTE: Database connection is managed by consolidated_services/database
    # This setting is deprecated and kept only for backward compatibility
    # Use consolidated_services/database/config/database_config.py instead
    database_url: Optional[str] = os.getenv("DATABASE_URL", None)  # Deprecated - use consolidated DB
    
    # Schema search_path for consolidated database (engine_onboarding,engine_shared)
    db_schema: str = os.getenv("DB_SCHEMA", "engine_onboarding,engine_shared")
    
    # AWS Services Configuration
    aws_region: str = os.getenv('AWS_REGION', 'ap-south-1')
    
    # DynamoDB table names (optional - kept for backward compatibility if needed)
    dynamodb_tenants_table: str = os.getenv('DYNAMODB_TENANTS_TABLE', 'threat-engine-tenants')
    dynamodb_providers_table: str = os.getenv('DYNAMODB_PROVIDERS_TABLE', 'threat-engine-providers')
    dynamodb_accounts_table: str = os.getenv('DYNAMODB_ACCOUNTS_TABLE', 'threat-engine-accounts')
    dynamodb_schedules_table: str = os.getenv('DYNAMODB_SCHEDULES_TABLE', 'threat-engine-schedules')
    dynamodb_executions_table: str = os.getenv('DYNAMODB_EXECUTIONS_TABLE', 'threat-engine-executions')
    dynamodb_scan_results_table: str = os.getenv('DYNAMODB_SCAN_RESULTS_TABLE', 'threat-engine-scan-results')
    
    # Secrets Manager configuration
    secrets_manager_prefix: str = os.getenv('SECRETS_MANAGER_PREFIX', 'threat-engine')
    secrets_manager_kms_key_id: Optional[str] = os.getenv('SECRETS_MANAGER_KMS_KEY_ID')
    
    # Platform configuration
    platform_aws_account_id: str = os.getenv('PLATFORM_AWS_ACCOUNT_ID', '')
    
    # Logging
    log_level: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # Engine service URLs (ClusterIP)
    aws_engine_url: str = os.getenv(
        'AWS_ENGINE_URL',
        'http://aws-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    azure_engine_url: str = os.getenv(
        'AZURE_ENGINE_URL',
        'http://azure-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    gcp_engine_url: str = os.getenv(
        'GCP_ENGINE_URL',
        'http://gcp-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    alicloud_engine_url: str = os.getenv(
        'ALICLOUD_ENGINE_URL',
        'http://alicloud-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    oci_engine_url: str = os.getenv(
        'OCI_ENGINE_URL',
        'http://oci-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    ibm_engine_url: str = os.getenv(
        'IBM_ENGINE_URL',
        'http://ibm-compliance-engine.threat-engine-engines.svc.cluster.local'
    )
    k8s_engine_url: str = os.getenv(
        'K8S_ENGINE_URL',
        'http://engine-discoveries.threat-engine-engines.svc.cluster.local'
    )
    rule_engine_url: str = os.getenv(
        'RULE_ENGINE_URL',
        'http://engine-rule.threat-engine-engines.svc.cluster.local'
    )
    # Backward compatibility
    yaml_rule_builder_url: str = os.getenv(
        'YAML_RULE_BUILDER_URL',
        os.getenv('RULE_ENGINE_URL', 'http://engine-rule.threat-engine-engines.svc.cluster.local')
    )
    
    # Downstream engine URLs (for orchestration) — engine_* naming
    threat_engine_url: str = os.getenv(
        'THREAT_ENGINE_URL',
        'http://engine-threat.threat-engine-engines.svc.cluster.local'
    )
    compliance_engine_url: str = os.getenv(
        'COMPLIANCE_ENGINE_URL',
        'http://engine-compliance.threat-engine-engines.svc.cluster.local'
    )
    datasec_engine_url: str = os.getenv(
        'DATASEC_ENGINE_URL',
        'http://engine-datasec.threat-engine-engines.svc.cluster.local'
    )
    inventory_engine_url: str = os.getenv(
        'INVENTORY_ENGINE_URL',
        'http://engine-inventory.threat-engine-engines.svc.cluster.local'
    )
    
    # API Configuration
    api_host: str = os.getenv('API_HOST', '0.0.0.0')
    api_port: int = int(os.getenv('API_PORT', '8000'))
    
    # Scheduler
    scheduler_interval_seconds: int = int(os.getenv('SCHEDULER_INTERVAL_SECONDS', '60'))

    # Engine polling (how long onboarding waits for an engine scan to finish)
    engine_scan_poll_interval_seconds: int = int(os.getenv('ENGINE_SCAN_POLL_INTERVAL_SECONDS', '10'))
    engine_scan_max_wait_seconds: int = int(os.getenv('ENGINE_SCAN_MAX_WAIT_SECONDS', '3600'))
    
    class Config:
        env_file = '.env'
        case_sensitive = False


# Global settings instance
settings = Settings()

