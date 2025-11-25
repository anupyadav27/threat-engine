#!/usr/bin/env python3
"""
Comprehensive IBM Cloud Service Mappings
Maps all service names to IBM Cloud Python SDK standards
"""

# Comprehensive IBM Cloud Service Mappings
IBM_CLOUD_SERVICE_MAPPINGS = {
    # === Core IBM Cloud Services (Already Valid) ===
    'iam': 'iam',
    'vpc': 'vpc',
    'resource_controller': 'resource_controller',
    'resource_manager': 'resource_manager',
    'account': 'account',
    'key_protect': 'key_protect',
    'secrets_manager': 'secrets_manager',
    'certificate_manager': 'certificate_manager',
    'activity_tracker': 'activity_tracker',
    'log_analysis': 'log_analysis',
    'monitoring': 'monitoring',
    'api_gateway': 'api_gateway',
    'code_engine': 'code_engine',
    'container_registry': 'container_registry',
    'block_storage': 'block_storage',
    'file_storage': 'file_storage',
    'cdn': 'cdn',
    'cloudant': 'cloudant',
    'schematics': 'schematics',
    'watson_discovery': 'watson_discovery',
    
    # === Watson AI/ML Services ===
    'watson_machine_learning': 'watson_ml',  # IBM Watson Machine Learning
    'watson_assistant': 'watson_assistant',
    'watson_studio': 'watson_studio',
    'watson_knowledge_catalog': 'watson_knowledge_catalog',
    'watson_openscale': 'watson_openscale',
    
    # === Data & Analytics ===
    'data_virtualization': 'data_virtualization',  # IBM Cloud Pak for Data
    'datastage': 'datastage',  # IBM DataStage
    'data_refinery': 'data_refinery',
    'cognos': 'cognos_dashboard',
    
    # === Security Services ===
    'security': 'security_advisor',  # IBM Security Advisor/Advisor
    'security_advisor': 'security_advisor',
    'security_compliance': 'security_compliance_center',  # Security & Compliance Center
    'defender': 'security_advisor',  # Azure Defender → IBM Security Advisor
    
    # === Backup & Recovery ===
    'backup_recovery': 'backup',  # IBM Cloud Backup
    'backup': 'backup',
    
    # === Database Services ===
    'cloud_databases': 'databases',  # IBM Cloud Databases (ICD)
    'cos': 'object_storage',  # IBM Cloud Object Storage
    'cloudant': 'cloudant',  # IBM Cloudant (NoSQL)
    'db2': 'db2',
    'dynamodb': 'cloudant',  # AWS DynamoDB → IBM Cloudant
    'rds': 'databases',  # AWS RDS → IBM Cloud Databases
    'redshift': 'databases',  # AWS Redshift → IBM Cloud Databases
    'cloudsql': 'databases',  # GCP Cloud SQL → IBM Cloud Databases
    'sqlserver': 'databases',  # SQL Server → IBM Cloud Databases
    'postgresql': 'databases',
    'mysql': 'databases',
    'mongodb': 'databases',
    'elasticsearch': 'databases',  # IBM Databases for Elasticsearch
    'opensearch': 'databases',  # OpenSearch → IBM Databases for Elasticsearch
    'elasticache': 'databases',  # AWS ElastiCache → IBM Databases for Redis
    'neptune': 'databases',  # AWS Neptune → IBM Databases
    
    # === Compute Services ===
    'vsi': 'vpc',  # IBM Virtual Server Instances (part of VPC)
    'virtual_server': 'vpc',
    'bare_metal': 'vpc',  # Bare Metal Servers
    'awslambda': 'code_engine',  # AWS Lambda → IBM Code Engine
    'functions': 'functions',  # IBM Cloud Functions (OpenWhisk)
    
    # === Container & Kubernetes ===
    'kubernetes_service': 'containers',  # IBM Kubernetes Service (IKS)
    'openshift_service': 'containers',  # Red Hat OpenShift on IBM Cloud
    'containers': 'containers',
    
    # === Storage Services ===
    'object_storage': 'object_storage',
    'efs': 'file_storage',  # AWS EFS → IBM File Storage
    'ebs': 'block_storage',  # AWS EBS → IBM Block Storage
    
    # === Networking Services ===
    'load_balancer': 'load_balancer',
    'elb': 'load_balancer',  # AWS ELB → IBM Load Balancer
    'elbv2': 'load_balancer',  # AWS ALB/NLB → IBM Load Balancer
    'dns_services': 'dns',  # IBM DNS Services
    'dns': 'dns',
    'direct_link': 'direct_link',
    'transit_gateway': 'transit_gateway',
    
    # === Event & Messaging ===
    'event_notifications': 'event_notifications',
    'event_streams': 'event_streams',  # IBM Event Streams (Kafka)
    
    # === Integration ===
    'app_connect': 'app_connect',  # IBM App Connect
    
    # === Cost Management ===
    'cost': 'billing',  # IBM Cloud Billing/Usage
    'billing': 'billing',
    
    # === DevOps & CI/CD ===
    'continuous_delivery': 'continuous_delivery',
    'codebuild': 'continuous_delivery',  # AWS CodeBuild → IBM Continuous Delivery
    
    # === Data Catalog ===
    'glue': 'data_virtualization',  # AWS Glue → IBM Data Virtualization/Catalog
    'data_catalog': 'data_virtualization',
    
    # === Identity (Azure/Other) ===
    'entra': 'iam',  # Azure Entra ID → IBM IAM
    'app_id': 'app_id',  # IBM App ID
    
    # === Monitoring & Logging ===
    'logdna': 'log_analysis',  # IBM Log Analysis (LogDNA)
    'sysdig': 'monitoring',  # IBM Cloud Monitoring (Sysdig)
    'cloudwatch': 'monitoring',  # AWS CloudWatch → IBM Monitoring
    
    # === Misc/Unmapped ===
    'unmapped': 'resource_controller',  # Generic unmapped → Resource Controller
    'no': 'iam',  # "no checks" → IAM
    'appstream': 'code_engine',  # AWS AppStream → Code Engine
    'athena': 'databases',  # AWS Athena → IBM SQL Query
    'autoscaling': 'vpc',  # Auto Scaling → VPC
    'bedrock': 'watson_ml',  # AWS Bedrock → Watson ML
    'bigquery': 'databases',  # GCP BigQuery → IBM Db2/SQL Query
    
    # === PHASE 2: Additional Service Mappings ===
    
    # Data & Analytics (continued)
    'cognos_analytics': 'cognos_dashboard',  # IBM Cognos Analytics
    'cognos_dashboard': 'cognos_dashboard',
    
    # Event & Messaging
    'sns': 'event_notifications',  # AWS SNS → IBM Event Notifications
    'sqs': 'event_notifications',  # AWS SQS → IBM Event Notifications
    
    # Migration & Database Management
    'dms': 'databases',  # AWS DMS → IBM Database Migration (part of ICD)
    'documentdb': 'databases',  # AWS DocumentDB → IBM Databases for MongoDB
    
    # Compute & HPC
    'emr': 'analytics_engine',  # AWS EMR → IBM Analytics Engine
    'sagemaker': 'watson_ml',  # AWS SageMaker → Watson ML
    'fsx': 'file_storage',  # AWS FSx → IBM File Storage
    
    # Security & Compliance
    'kms': 'key_protect',  # AWS KMS → IBM Key Protect
    'cloudtrail': 'activity_tracker',  # AWS CloudTrail → IBM Activity Tracker
    'ssm': 'secrets_manager',  # AWS SSM Parameter Store → IBM Secrets Manager
    'networkfirewall': 'vpc',  # AWS Network Firewall → IBM VPC Security
    
    # Storage (AWS S3 variants)
    's3': 'object_storage',  # AWS S3 → IBM COS
    
    # Messaging & Queue
    'mq': 'event_streams',  # IBM MQ / AWS MQ → IBM Event Streams
    
    # Networking
    'cis': 'internet_services',  # IBM Cloud Internet Services (CIS)
    'internet_services': 'internet_services',
    'directconnect': 'direct_link',  # AWS Direct Connect → IBM Direct Link
    'directoryservice': 'iam',  # AWS Directory Service → IBM IAM
    
    # DevOps & Development
    'devops': 'continuous_delivery',  # IBM DevOps → Continuous Delivery
    
    # Generic catch-all for database variants
    'database': 'databases',  # Generic database → IBM Cloud Databases
    
    # Additional AWS services
    'guardduty': 'security_advisor',  # AWS GuardDuty → IBM Security Advisor
    'macie': 'security_advisor',  # AWS Macie → IBM Security Advisor
    'inspector': 'security_advisor',  # AWS Inspector → IBM Security Advisor
    'config': 'security_compliance_center',  # AWS Config → IBM SCC
    'cloudformation': 'schematics',  # AWS CloudFormation → IBM Schematics
    'lambda': 'code_engine',  # AWS Lambda → IBM Code Engine (duplicate entry for clarity)
    'eks': 'containers',  # AWS EKS → IBM Kubernetes Service
    'ecs': 'containers',  # AWS ECS → IBM Kubernetes/Code Engine
    'ecr': 'container_registry',  # AWS ECR → IBM Container Registry
    'route53': 'dns',  # AWS Route53 → IBM DNS Services
    'waf': 'internet_services',  # AWS WAF → IBM CIS WAF
    'shield': 'internet_services',  # AWS Shield → IBM CIS DDoS
    
    # Azure services
    'azuresql': 'databases',  # Azure SQL → IBM Cloud Databases
    'azuread': 'iam',  # Azure AD → IBM IAM
    'azuremonitor': 'monitoring',  # Azure Monitor → IBM Monitoring
    'azurestorage': 'object_storage',  # Azure Storage → IBM COS
    'azurekeyvault': 'key_protect',  # Azure Key Vault → IBM Key Protect
    
    # GCP services
    'gke': 'containers',  # GCP GKE → IBM Kubernetes Service
    'gcr': 'container_registry',  # GCP GCR → IBM Container Registry
    'cloudfunctions': 'code_engine',  # GCP Cloud Functions → IBM Code Engine
    'cloudkms': 'key_protect',  # GCP Cloud KMS → IBM Key Protect
    'cloudlogging': 'log_analysis',  # GCP Cloud Logging → IBM Log Analysis
    'cloudmonitoring': 'monitoring',  # GCP Cloud Monitoring → IBM Monitoring
    
    # IBM-specific services (already exist but ensuring completeness)
    'analytics_engine': 'analytics_engine',  # IBM Analytics Engine
    'event_streams': 'event_streams',  # IBM Event Streams (Kafka)
    'event_notifications': 'event_notifications',  # IBM Event Notifications
    'watson_studio': 'watson_studio',
    'watson_knowledge_catalog': 'watson_knowledge_catalog',
    'watson_openscale': 'watson_openscale',
    'security_compliance_center': 'security_compliance_center',
    'internet_services': 'internet_services',
    
    # Additional AWS/Azure/GCP services - Phase 3
    'elasticbeanstalk': 'code_engine',  # AWS Elastic Beanstalk → IBM Code Engine
    'keyvault': 'key_protect',  # Azure Key Vault → IBM Key Protect (duplicate mapping)
    'kinesis': 'event_streams',  # AWS Kinesis → IBM Event Streams
    'monitor': 'monitoring',  # Azure Monitor → IBM Monitoring (duplicate mapping)
    'vm': 'vpc',  # Azure VM → IBM VPC Virtual Servers
    'wafv2': 'internet_services',  # AWS WAF v2 → IBM CIS WAF
    'workspaces': 'vpc',  # AWS WorkSpaces → IBM VPC/Virtual Desktops
    'codeartifact': 'continuous_delivery',  # AWS CodeArtifact → IBM CD
    'dataproc': 'analytics_engine',  # GCP Dataproc → IBM Analytics Engine
    'datasync': 'backup',  # AWS DataSync → IBM Backup
    'ec2': 'vpc',  # AWS EC2 → IBM VPC
    'eip': 'vpc',  # AWS Elastic IP → IBM VPC Floating IP
    'securityhub': 'security_advisor',  # AWS Security Hub → IBM Security Advisor
    'servicecatalog': 'resource_controller',  # AWS Service Catalog → IBM Resource Controller
    'sql': 'databases',  # Generic SQL → IBM Databases
    'stepfunctions': 'code_engine',  # AWS Step Functions → IBM Code Engine
    'storagegateway': 'backup',  # AWS Storage Gateway → IBM Backup
    'transfer': 'backup',  # AWS Transfer Family → IBM Backup/File Storage
}

print(f"Total IBM Cloud Service Mappings: {len(IBM_CLOUD_SERVICE_MAPPINGS)}")
print("✅ Comprehensive IBM Cloud Service Mappings Complete!")

