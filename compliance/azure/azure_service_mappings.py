#!/usr/bin/env python3
"""
Comprehensive Azure Service Mappings
Maps all service names to Azure Python SDK standards
"""

# Comprehensive Azure Service Mappings
AZURE_SERVICE_MAPPINGS = {
    # === Core Azure Services (Already Valid) ===
    'active_directory': 'active_directory',
    'aad': 'active_directory',
    'ad': 'active_directory',
    'compute': 'compute',
    'vm': 'compute',
    'vmss': 'compute',
    'storage': 'storage',
    'blob': 'storage',
    'files': 'storage',
    'queue': 'storage',
    'network': 'network',
    'virtualnetwork': 'network',
    'vnet': 'network',
    'loadbalancer': 'network',
    'applicationgateway': 'network',
    'sql': 'sql',
    'postgresql': 'postgresql',
    'mysql': 'mysql',
    'cosmosdb': 'cosmosdb',
    'synapse': 'synapse',
    'aks': 'aks',
    'containerregistry': 'containerregistry',
    'acr': 'containerregistry',
    'keyvault': 'keyvault',
    'security': 'security',
    'securitycenter': 'security',
    'monitor': 'monitor',
    'loganalytics': 'monitor',
    'applicationinsights': 'monitor',
    'app': 'app',
    'appservice': 'app',
    'functionapp': 'app',
    'api': 'api',
    'machinelearning': 'machinelearning',
    'ml': 'machinelearning',
    'automation': 'automation',
    'recovery': 'recovery',
    'backup': 'backup',
    
    # === Services Needing Mapping ===
    
    # Generic 'azure' → specific services
    'azure': 'resource_manager',  # Generic Azure → Resource Manager
    
    # Machine Learning
    'machine': 'machinelearning',  # machine.learning_* → machinelearning
    
    # Data & Analytics
    'purview': 'purview',  # Microsoft Purview (Data Governance)
    'data': 'datafactory',  # data.factory_* → datafactory
    'datafactory': 'datafactory',
    'datalake': 'datalake',
    'databricks': 'databricks',
    'synapse_analytics': 'synapse',
    
    # Kubernetes/Containers
    'kubernetes': 'aks',  # kubernetes.* → aks
    'container': 'aks',
    'containers': 'aks',
    
    # Identity & Access (Active Directory variants)
    'active': 'active_directory',  # active.directory_* → active_directory
    'azuread': 'active_directory',
    'entra': 'active_directory',  # Microsoft Entra ID
    
    # Security & Compliance
    'defender': 'security',  # Microsoft Defender → Security Center
    'sentinel': 'sentinel',  # Microsoft Sentinel (SIEM)
    'policy': 'policy',  # Azure Policy
    
    # Networking
    'cdn': 'cdn',  # Azure CDN
    'frontdoor': 'frontdoor',  # Azure Front Door
    'trafficmanager': 'network',
    'dns': 'network',
    'firewall': 'network',
    'bastion': 'network',
    'vpn': 'network',
    'expressroute': 'network',
    'load': 'network',  # load.balancer → network
    
    # App Services & Serverless
    'function': 'app',  # Azure Functions → App Service
    'logicapps': 'logicapps',
    'logic': 'logicapps',  # logic.apps_* → logicapps
    'eventgrid': 'eventgrid',
    'servicebus': 'servicebus',
    'eventhub': 'eventhub',
    
    # IoT & Edge
    'iot': 'iothub',
    'iothub': 'iothub',
    'iotcentral': 'iotcentral',
    
    # AI & Cognitive Services
    'cognitive': 'cognitiveservices',
    'cognitiveservices': 'cognitiveservices',
    'openai': 'cognitiveservices',
    'bot': 'botservice',
    'search': 'search',  # Azure Cognitive Search
    'aisearch': 'search',
    
    # Database Services
    'redis': 'redis',  # Azure Cache for Redis
    'mariadb': 'mariadb',
    'sqlserver': 'sql',
    
    # DevOps & Development
    'devops': 'devops',
    'devtestlabs': 'devtestlabs',
    'artifacts': 'devops',
    
    # Management & Governance
    'management': 'resource_manager',
    'resourcemanager': 'resource_manager',
    'subscription': 'subscription',
    'costmanagement': 'costmanagement',
    'advisor': 'advisor',
    
    # Storage Variants
    'storageaccount': 'storage',
    'blobstorage': 'storage',
    'filestorage': 'storage',
    'queuestorage': 'storage',
    'tablestorage': 'storage',
    'disks': 'compute',
    
    # Batch & HPC
    'batch': 'batch',
    'hpc': 'batch',
    
    # Media & Streaming
    'media': 'mediaservices',
    'mediaservices': 'mediaservices',
    'streaming': 'mediaservices',
    
    # Notification & Communication
    'notification': 'notificationhubs',
    'notificationhubs': 'notificationhubs',
    'communication': 'communication',
    
    # Blockchain
    'blockchain': 'blockchain',
    
    # Spring Cloud
    'spring': 'springcloud',
    'springcloud': 'springcloud',
    
    # API Management
    'apim': 'api',
    'apimanagement': 'api',
    
    # Logging & Monitoring
    'log': 'monitor',  # log.* → monitor
    'logs': 'monitor',
    'insights': 'monitor',
    'metrics': 'monitor',
    
    # Maps & Location
    'maps': 'maps',
    
    # Time Series
    'timeseriesinsights': 'timeseriesinsights',
    'tsi': 'timeseriesinsights',
    
    # === Phase 2: Additional Unmapped Services ===
    
    # Web & App Services
    'site': 'app',  # site.* → app (App Service Sites)
    'webapp': 'app',  # webapp → app
    'functions': 'app',  # functions → app
    
    # Identity & Access Management
    'iam': 'active_directory',  # IAM → Active Directory
    'rbac': 'active_directory',  # RBAC → Active Directory
    'entrad': 'active_directory',  # Entra ID variant
    'graph': 'active_directory',  # Microsoft Graph → Active Directory
    
    # Cost & Billing
    'cost': 'costmanagement',
    'billing': 'costmanagement',
    
    # Power Platform
    'power': 'power_platform',  # Power BI, Power Apps, etc.
    'powerbi': 'power_platform',
    
    # Event Services
    'event': 'eventgrid',  # event.* → eventgrid
    
    # Key & Secrets (already have keyvault, but catch variants)
    'key': 'keyvault',  # key.* → keyvault
    'certificates': 'keyvault',  # certificates → keyvault
    
    # Managed Services
    'managed': 'resource_manager',  # managed.* → resource_manager
    'resource': 'resource_manager',  # resource.* → resource_manager
    
    # Application Services
    'application': 'app',  # application.* → app
    
    # Big Data & Analytics
    'hdinsight': 'hdinsight',  # Azure HDInsight
    'elastic': 'hdinsight',  # Elastic on Azure → HDInsight
    
    # Data Protection
    'dataprotection': 'backup',  # Data Protection → Backup
    'recoveryservices': 'recovery',  # Recovery Services
    
    # Networking (additional)
    'front': 'frontdoor',  # front.* → frontdoor
    'traffic': 'network',  # traffic.* → network (Traffic Manager)
    
    # Database (additional)
    'cosmos': 'cosmosdb',  # cosmos.* → cosmosdb
    
    # Caching
    'cache': 'redis',  # cache.* → redis (Azure Cache)
    
    # Compute (additional)
    'disk': 'compute',  # disk.* → compute
    
    # AWS/Other CSP Services (for cross-cloud rules)
    's3': 'storage',  # AWS S3 → Azure Storage
    'eks': 'aks',  # AWS EKS → Azure AKS
    'config': 'policy',  # AWS Config → Azure Policy
    
    # Device Management
    'intune': 'intune',  # Microsoft Intune
}

print(f"Total Azure Service Mappings: {len(AZURE_SERVICE_MAPPINGS)}")
print("✅ Comprehensive Azure Service Mappings Complete!")

