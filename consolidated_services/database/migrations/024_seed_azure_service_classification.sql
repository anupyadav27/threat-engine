-- Migration 024: Seed Azure asset types into service_classification
-- Safe to re-run (ON CONFLICT DO UPDATE).
-- CONFLICT key: (csp, resource_type)

INSERT INTO service_classification (
    csp, resource_type, service, resource_name, display_name,
    scope, category, subcategory, service_model, managed_by,
    access_pattern, is_container, container_parent,
    diagram_priority, csp_category
) VALUES
-- ── Compute ──────────────────────────────────────────────────────────────────
('azure', 'VirtualMachine',        'compute',         'VirtualMachine',        'Virtual Machine',          'regional', 'Compute',   'Virtual Machine',  'IaaS',  'customer',  'direct',    false, NULL,                    10, 'Compute'),
('azure', 'VMSS',                  'compute',         'VMSS',                  'VM Scale Set',             'regional', 'Compute',   'Auto Scaling',     'IaaS',  'customer',  'direct',    true,  'VirtualMachine',         20, 'Compute'),
-- ── Storage ──────────────────────────────────────────────────────────────────
('azure', 'StorageAccount',        'storage',         'StorageAccount',        'Storage Account',          'regional', 'Storage',   'Object Storage',   'PaaS',  'shared',    'direct',    true,  NULL,                    10, 'Storage'),
('azure', 'BlobContainer',         'storage',         'BlobContainer',         'Blob Container',           'regional', 'Storage',   'Blob Container',   'PaaS',  'shared',    'direct',    false, 'StorageAccount',         20, 'Storage'),
('azure', 'ManagedDisk',           'compute',         'ManagedDisk',           'Managed Disk',             'regional', 'Storage',   'Block Storage',    'IaaS',  'customer',  'direct',    false, 'VirtualMachine',         30, 'Storage'),
-- ── Database ─────────────────────────────────────────────────────────────────
('azure', 'SQLServer',             'sql',             'SQLServer',             'SQL Server',               'regional', 'Database',  'Relational DB',    'PaaS',  'shared',    'direct',    true,  NULL,                    10, 'Database'),
('azure', 'SQLDatabase',           'sql',             'SQLDatabase',           'SQL Database',             'regional', 'Database',  'Relational DB',    'PaaS',  'shared',    'direct',    false, 'SQLServer',              20, 'Database'),
('azure', 'CosmosDB',              'cosmosdb',        'CosmosDB',              'Cosmos DB',                'global',   'Database',  'NoSQL',            'PaaS',  'shared',    'direct',    false, NULL,                    15, 'Database'),
('azure', 'MySQLServer',           'mysql',           'MySQLServer',           'MySQL Server',             'regional', 'Database',  'Relational DB',    'PaaS',  'shared',    'direct',    false, NULL,                    20, 'Database'),
('azure', 'PostgreSQLServer',      'postgresql',      'PostgreSQLServer',      'PostgreSQL Server',        'regional', 'Database',  'Relational DB',    'PaaS',  'shared',    'direct',    false, NULL,                    20, 'Database'),
-- ── Network ───────────────────────────────────────────────────────────────────
('azure', 'VirtualNetwork',        'network',         'VirtualNetwork',        'Virtual Network',          'regional', 'Network',   'VPC',              'PaaS',  'customer',  'network',   true,  NULL,                    10, 'Networking'),
('azure', 'Subnet',                'network',         'Subnet',                'Subnet',                   'regional', 'Network',   'Subnet',           'PaaS',  'customer',  'network',   false, 'VirtualNetwork',         20, 'Networking'),
('azure', 'NetworkSecurityGroup',  'network',         'NetworkSecurityGroup',  'Network Security Group',   'regional', 'Network',   'Firewall',         'PaaS',  'customer',  'network',   false, NULL,                    15, 'Networking'),
('azure', 'LoadBalancer',          'network',         'LoadBalancer',          'Load Balancer',            'regional', 'Network',   'Load Balancer',    'PaaS',  'shared',    'network',   false, NULL,                    15, 'Networking'),
('azure', 'ApplicationGateway',    'network',         'ApplicationGateway',    'Application Gateway',      'regional', 'Network',   'WAF/Gateway',      'PaaS',  'shared',    'network',   false, NULL,                    15, 'Networking'),
('azure', 'PublicIPAddress',       'network',         'PublicIPAddress',        'Public IP Address',        'regional', 'Network',   'Public IP',        'PaaS',  'shared',    'network',   false, NULL,                    25, 'Networking'),
-- ── Security ─────────────────────────────────────────────────────────────────
('azure', 'KeyVault',              'keyvault',        'KeyVault',              'Key Vault',                'regional', 'Security',  'Key Management',   'PaaS',  'shared',    'direct',    true,  NULL,                    10, 'Security'),
-- ── Identity ─────────────────────────────────────────────────────────────────
('azure', 'ServicePrincipal',      'authorization',   'ServicePrincipal',      'Service Principal',        'global',   'Identity',  'Service Account',  'PaaS',  'shared',    'identity',  false, NULL,                    10, 'Identity'),
('azure', 'ManagedIdentity',       'msi',             'ManagedIdentity',        'Managed Identity',         'regional', 'Identity',  'Managed Identity', 'PaaS',  'shared',    'identity',  false, NULL,                    15, 'Identity'),
-- ── Container ────────────────────────────────────────────────────────────────
('azure', 'AKSCluster',            'containerservice','AKSCluster',            'AKS Cluster',              'regional', 'Container', 'Kubernetes',       'PaaS',  'shared',    'direct',    true,  NULL,                    10, 'Containers'),
('azure', 'ContainerRegistry',     'containerregistry','ContainerRegistry',    'Container Registry',       'regional', 'Container', 'Registry',         'PaaS',  'shared',    'direct',    false, NULL,                    15, 'Containers'),
-- ── Web / Serverless ─────────────────────────────────────────────────────────
('azure', 'AppService',            'web',             'AppService',            'App Service',              'regional', 'Compute',   'App Service',      'PaaS',  'shared',    'direct',    false, NULL,                    10, 'Serverless'),
('azure', 'FunctionApp',           'web',             'FunctionApp',           'Function App',             'regional', 'Compute',   'Serverless',       'FaaS',  'shared',    'direct',    false, NULL,                    15, 'Serverless')
ON CONFLICT (csp, resource_type) DO UPDATE SET
    service          = EXCLUDED.service,
    resource_name    = EXCLUDED.resource_name,
    display_name     = COALESCE(service_classification.display_name, EXCLUDED.display_name),
    scope            = EXCLUDED.scope,
    category         = EXCLUDED.category,
    subcategory      = EXCLUDED.subcategory,
    service_model    = EXCLUDED.service_model,
    managed_by       = EXCLUDED.managed_by,
    access_pattern   = EXCLUDED.access_pattern,
    is_container     = service_classification.is_container,
    container_parent = COALESCE(service_classification.container_parent, EXCLUDED.container_parent),
    diagram_priority = LEAST(service_classification.diagram_priority, EXCLUDED.diagram_priority),
    csp_category     = EXCLUDED.csp_category;
