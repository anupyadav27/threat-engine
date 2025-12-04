# Azure SDK Python Module Mapping

## Overview
Unlike AWS boto3 (single module, single client per service), Azure has:
- **Multiple packages** for different services
- **Different client classes** per service
- **Varying authentication patterns**

This document maps Azure services → Python packages → Clients for the compliance engine.

---

## 🔑 Core Packages & Authentication

### 1. Azure Identity (Auth for All Services)
**Package**: `azure-identity`
```python
from azure.identity import DefaultAzureCredential, ClientSecretCredential
```

**Used By**: ALL Azure services for authentication

---

## 📦 Service Groups by Python Package

### 2. Azure Management - Resource Manager
**Package**: `azure-mgmt-resource`
**Client**: `ResourceManagementClient`

**Services Covered**:
- `resource` - Resource groups, deployments
- `subscription` - Subscription management
- `managementgroup` - Management groups
- `policy` - Azure Policy
- `rbac` - Role-based access control (partially)

**Example**:
```python
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ManagementGroupsAPI
from azure.mgmt.resource import PolicyClient
```

### 3. Azure Management - Compute
**Package**: `azure-mgmt-compute`
**Client**: `ComputeManagementClient`

**Services Covered**:
- `compute` - Virtual machines
- `vm` - Virtual machines (alternate naming)
- `virtualmachines` - VMs
- `disk` - Managed disks
- `aks` - Azure Kubernetes Service (partially, mainly in containerservice)

**Example**:
```python
from azure.mgmt.compute import ComputeManagementClient
```

### 4. Azure Management - Storage
**Package**: `azure-mgmt-storage`
**Client**: `StorageManagementClient`

**Services Covered**:
- `storage` - Storage accounts
- `blob` - Blob storage (data plane: azure-storage-blob)
- `files` - Azure Files
- `s3` - (Note: This is AWS, likely misnamed rules)

**Example**:
```python
from azure.mgmt.storage import StorageManagementClient
# For data plane operations:
from azure.storage.blob import BlobServiceClient
```

### 5. Azure Management - Network
**Package**: `azure-mgmt-network`
**Client**: `NetworkManagementClient`

**Services Covered**:
- `network` - Virtual networks, subnets
- `networksecuritygroup` - NSGs
- `vpn` - VPN gateways
- `loadbalancer` - Load balancers
- `load` - Load balancers
- `traffic` - Traffic Manager
- `dns` - DNS zones
- `cdn` - Content Delivery Network
- `front` - Front Door

**Example**:
```python
from azure.mgmt.network import NetworkManagementClient
```

### 6. Azure Management - SQL/Databases
**Package**: `azure-mgmt-sql`
**Client**: `SqlManagementClient`

**Services Covered**:
- `sql` - Azure SQL Database
- `sqlserver` - SQL Server instances
- `server` - Database servers

**Additional Packages**:
- `azure-mgmt-rdbms` - MySQL, PostgreSQL, MariaDB
  - `mysql`
  - `postgresql`
  - `mariadb`
- `azure-mgmt-cosmosdb` - Cosmos DB
  - `cosmos`
  - `cosmosdb`

**Example**:
```python
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.rdbms.mysql import MySQLManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
```

### 7. Azure Management - Monitor & Security
**Package**: `azure-mgmt-monitor`
**Client**: `MonitorManagementClient`

**Services Covered**:
- `monitor` - Azure Monitor
- `log` - Log Analytics
- `audit` - Activity logs

**Package**: `azure-mgmt-security`
**Client**: `SecurityCenter`

**Services Covered**:
- `security` - Security Center
- `securitycenter` - Security Center
- `defender` - Microsoft Defender

**Example**:
```python
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
```

### 8. Azure Active Directory / Entra ID
**Package**: `msgraph-sdk` or `azure-graphrbac`
**Client**: `GraphRbacManagementClient` (deprecated) or MS Graph SDK

**Services Covered**:
- `aad` - Azure Active Directory
- `ad` - Active Directory
- `entra` - Entra ID (new branding)
- `entrad` - Entra ID
- `graph` - Microsoft Graph
- `user` - User management
- `password` - Password policies
- `iam` - Identity & Access (partially)

**Modern Approach** (MS Graph SDK):
```python
from msgraph import GraphServiceClient
from azure.identity import ClientSecretCredential
```

**Legacy Approach**:
```python
from azure.graphrbac import GraphRbacManagementClient
```

### 9. Azure Management - App Service
**Package**: `azure-mgmt-web`
**Client**: `WebSiteManagementClient`

**Services Covered**:
- `app` - App Services
- `appservice` - App Services
- `webapp` - Web Apps
- `function` - Azure Functions
- `functionapp` - Function Apps
- `functions` - Function Apps
- `site` - Web/Function App sites

**Example**:
```python
from azure.mgmt.web import WebSiteManagementClient
```

### 10. Azure Management - Container Services
**Package**: `azure-mgmt-containerservice`
**Client**: `ContainerServiceClient`

**Services Covered**:
- `aks` - Azure Kubernetes Service
- `kubernetes` - AKS clusters
- `container` - Container instances

**Additional Package**: `azure-mgmt-containerinstance`
- `container` - Azure Container Instances

**Example**:
```python
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
```

### 11. Azure Management - Key Vault
**Package**: `azure-mgmt-keyvault`
**Client**: `KeyVaultManagementClient` (control plane)

**Services Covered**:
- `keyvault` - Key Vault management
- `key` - Key management

**Data Plane Packages**:
- `azure-keyvault-secrets` - Secrets
- `azure-keyvault-keys` - Keys
- `azure-keyvault-certificates` - Certificates

**Example**:
```python
# Control plane (management)
from azure.mgmt.keyvault import KeyVaultManagementClient
# Data plane (access secrets/keys)
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
```

### 12. Azure Management - Backup & Recovery
**Package**: `azure-mgmt-recoveryservices`
**Client**: `RecoveryServicesClient`

**Services Covered**:
- `backup` - Azure Backup
- `recoveryservices` - Recovery Services Vaults

**Additional Package**: `azure-mgmt-dataprotection`
- `dataprotection` - Data Protection

**Example**:
```python
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.dataprotection import DataProtectionClient
```

### 13. Azure Management - Data & Analytics
**Package**: `azure-mgmt-datafactory`
**Client**: `DataFactoryManagementClient`

**Services Covered**:
- `data` - Data Factory (partially)

**Other Packages**:
- `azure-mgmt-databricks` → `databricks`
- `azure-mgmt-synapse` → `synapse`
- `azure-mgmt-hdinsight` → `hdinsight`
- `azure-mgmt-search` → `search`, `aisearch`
- `azure-mgmt-purview` → `purview`

**Example**:
```python
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.databricks import AzureDatabricksManagementClient
from azure.mgmt.synapse import SynapseManagementClient
```

### 14. Azure Management - Other Services

#### API Management
**Package**: `azure-mgmt-apimanagement`
```python
from azure.mgmt.apimanagement import ApiManagementClient
# Services: api
```

#### Automation
**Package**: `azure-mgmt-automation`
```python
from azure.mgmt.automation import AutomationClient
# Services: automation, patch
```

#### Batch
**Package**: `azure-mgmt-batch`
```python
from azure.mgmt.batch import BatchManagementClient
# Services: batch
```

#### Cache (Redis)
**Package**: `azure-mgmt-redis`
```python
from azure.mgmt.redis import RedisManagementClient
# Services: cache, redis
```

#### Billing & Cost
**Package**: `azure-mgmt-costmanagement`, `azure-mgmt-billing`
```python
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.billing import BillingManagementClient
# Services: cost, billing
```

#### Event Services
**Package**: `azure-mgmt-eventgrid`, `azure-mgmt-eventhub`
```python
from azure.mgmt.eventgrid import EventGridManagementClient
from azure.mgmt.eventhub import EventHubManagementClient
# Services: event
```

#### IoT
**Package**: `azure-mgmt-iothub`
```python
from azure.mgmt.iothub import IotHubClient
# Services: iot
```

#### Logic Apps
**Package**: `azure-mgmt-logic`
```python
from azure.mgmt.logic import LogicManagementClient
# Services: logic
```

#### Machine Learning
**Package**: `azure-mgmt-machinelearningservices`
```python
from azure.mgmt.machinelearningservices import MachineLearningServicesManagementClient
# Services: machine (partially)
```

#### Notification Hubs
**Package**: `azure-mgmt-notificationhubs`
```python
from azure.mgmt.notificationhubs import NotificationHubsManagementClient
# Services: notification
```

#### Power BI
**Package**: `azure-mgmt-powerbiembedded`
```python
from azure.mgmt.powerbiembedded import PowerBIEmbeddedManagementClient
# Services: power
```

---

## 🔀 Service Name Mapping (Your Folder → Azure Package)

| Your Service Folder | Azure Package | Client Class |
|-------------------|---------------|--------------|
| `aad` | `msgraph-sdk` | `GraphServiceClient` |
| `active` | *(needs clarification)* | - |
| `ad` | `msgraph-sdk` | `GraphServiceClient` |
| `aisearch` | `azure-mgmt-search` | `SearchManagementClient` |
| `aks` | `azure-mgmt-containerservice` | `ContainerServiceClient` |
| `api` | `azure-mgmt-apimanagement` | `ApiManagementClient` |
| `app` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `application` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `appservice` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `audit` | `azure-mgmt-monitor` | `MonitorManagementClient` |
| `automation` | `azure-mgmt-automation` | `AutomationClient` |
| `azure` | *(generic - needs breakdown)* | Multiple |
| `backup` | `azure-mgmt-recoveryservices` | `RecoveryServicesClient` |
| `batch` | `azure-mgmt-batch` | `BatchManagementClient` |
| `billing` | `azure-mgmt-billing` | `BillingManagementClient` |
| `blob` | `azure-storage-blob` | `BlobServiceClient` |
| `cache` | `azure-mgmt-redis` | `RedisManagementClient` |
| `cdn` | `azure-mgmt-cdn` | `CdnManagementClient` |
| `certificates` | `azure-keyvault-certificates` | `CertificateClient` |
| `compute` | `azure-mgmt-compute` | `ComputeManagementClient` |
| `config` | `azure-mgmt-appconfiguration` | `AppConfigurationManagementClient` |
| `container` | `azure-mgmt-containerinstance` | `ContainerInstanceManagementClient` |
| `containerregistry` | `azure-mgmt-containerregistry` | `ContainerRegistryManagementClient` |
| `cosmos` | `azure-mgmt-cosmosdb` | `CosmosDBManagementClient` |
| `cosmosdb` | `azure-mgmt-cosmosdb` | `CosmosDBManagementClient` |
| `cost` | `azure-mgmt-costmanagement` | `CostManagementClient` |
| `data` | Multiple packages | Depends on service |
| `databricks` | `azure-mgmt-databricks` | `AzureDatabricksManagementClient` |
| `dataprotection` | `azure-mgmt-dataprotection` | `DataProtectionClient` |
| `defender` | `azure-mgmt-security` | `SecurityCenter` |
| `devops` | `azure-devops` | Custom client |
| `disk` | `azure-mgmt-compute` | `ComputeManagementClient` |
| `dns` | `azure-mgmt-dns` | `DnsManagementClient` |
| `eks` | *(AWS service - wrong CSP)* | - |
| `elastic` | `azure-mgmt-elastic` | `ElasticManagementClient` |
| `enabled` | *(not a service)* | - |
| `encryption` | *(cross-cutting concern)* | - |
| `entra` | `msgraph-sdk` | `GraphServiceClient` |
| `entrad` | `msgraph-sdk` | `GraphServiceClient` |
| `event` | `azure-mgmt-eventgrid` | `EventGridManagementClient` |
| `files` | `azure-storage-file-share` | `ShareServiceClient` |
| `front` | `azure-mgmt-frontdoor` | `FrontDoorManagementClient` |
| `function` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `functionapp` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `functions` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `graph` | `msgraph-sdk` | `GraphServiceClient` |
| `hdinsight` | `azure-mgmt-hdinsight` | `HDInsightManagementClient` |
| `iam` | Multiple | RBAC + AAD |
| `intune` | `msgraph-sdk` | `GraphServiceClient` |
| `iot` | `azure-mgmt-iothub` | `IotHubClient` |
| `key` | `azure-keyvault-keys` | `KeyClient` |
| `keyvault` | `azure-mgmt-keyvault` | `KeyVaultManagementClient` |
| `kubernetes` | `azure-mgmt-containerservice` | `ContainerServiceClient` |
| `lambda` | *(AWS service - wrong CSP)* | - |
| `load` | `azure-mgmt-network` | `NetworkManagementClient` |
| `loadbalancer` | `azure-mgmt-network` | `NetworkManagementClient` |
| `log` | `azure-mgmt-loganalytics` | `LogAnalyticsManagementClient` |
| `logic` | `azure-mgmt-logic` | `LogicManagementClient` |
| `machine` | `azure-mgmt-machinelearningservices` | `MachineLearningServicesManagementClient` |
| `managed` | *(not specific)* | - |
| `management` | `azure-mgmt-managementgroups` | `ManagementGroupsAPI` |
| `managementgroup` | `azure-mgmt-managementgroups` | `ManagementGroupsAPI` |
| `mariadb` | `azure-mgmt-rdbms` | `MariaDBManagementClient` |
| `monitor` | `azure-mgmt-monitor` | `MonitorManagementClient` |
| `mysql` | `azure-mgmt-rdbms` | `MySQLManagementClient` |
| `netappfiles` | `azure-mgmt-netapp` | `NetAppManagementClient` |
| `network` | `azure-mgmt-network` | `NetworkManagementClient` |
| `networksecuritygroup` | `azure-mgmt-network` | `NetworkManagementClient` |
| `notification` | `azure-mgmt-notificationhubs` | `NotificationHubsManagementClient` |
| `password` | `msgraph-sdk` | `GraphServiceClient` |
| `patch` | `azure-mgmt-automation` | `AutomationClient` |
| `policy` | `azure-mgmt-resource` | `PolicyClient` |
| `postgresql` | `azure-mgmt-rdbms` | `PostgreSQLManagementClient` |
| `power` | `azure-mgmt-powerbiembedded` | `PowerBIEmbeddedManagementClient` |
| `purview` | `azure-mgmt-purview` | `PurviewManagementClient` |
| `rbac` | `azure-mgmt-authorization` | `AuthorizationManagementClient` |
| `recoveryservices` | `azure-mgmt-recoveryservices` | `RecoveryServicesClient` |
| `redis` | `azure-mgmt-redis` | `RedisManagementClient` |
| `region` | `azure-mgmt-subscription` | `SubscriptionClient` |
| `resource` | `azure-mgmt-resource` | `ResourceManagementClient` |
| `rotate` | *(action, not service)* | - |
| `s3` | *(AWS service - wrong CSP)* | - |
| `search` | `azure-mgmt-search` | `SearchManagementClient` |
| `security` | `azure-mgmt-security` | `SecurityCenter` |
| `securitycenter` | `azure-mgmt-security` | `SecurityCenter` |
| `server` | *(context dependent)* | Multiple |
| `site` | `azure-mgmt-web` | `WebSiteManagementClient` |
| `sql` | `azure-mgmt-sql` | `SqlManagementClient` |
| `sqlserver` | `azure-mgmt-sql` | `SqlManagementClient` |
| `storage` | `azure-mgmt-storage` | `StorageManagementClient` |
| `subscription` | `azure-mgmt-subscription` | `SubscriptionClient` |
| `synapse` | `azure-mgmt-synapse` | `SynapseManagementClient` |
| `traffic` | `azure-mgmt-trafficmanager` | `TrafficManagerManagementClient` |
| `user` | `msgraph-sdk` | `GraphServiceClient` |
| `virtualmachines` | `azure-mgmt-compute` | `ComputeManagementClient` |
| `vm` | `azure-mgmt-compute` | `ComputeManagementClient` |
| `vpn` | `azure-mgmt-network` | `NetworkManagementClient` |
| `webapp` | `azure-mgmt-web` | `WebSiteManagementClient` |

---

## ✅ Required Packages Summary

Update `requirements.txt` with:

```txt
# Core Authentication
azure-identity>=1.16.0

# Management Plane - Core
azure-mgmt-resource>=23.0.1
azure-mgmt-subscription>=3.1.1
azure-mgmt-authorization>=4.0.0

# Compute & Containers
azure-mgmt-compute>=31.0.0
azure-mgmt-containerservice>=29.0.0
azure-mgmt-containerinstance>=10.1.0
azure-mgmt-containerregistry>=10.3.0

# Storage
azure-mgmt-storage>=21.1.0
azure-storage-blob>=12.19.0
azure-storage-file-share>=12.15.0

# Networking
azure-mgmt-network>=25.2.0
azure-mgmt-dns>=8.1.0
azure-mgmt-cdn>=13.1.0
azure-mgmt-frontdoor>=1.1.0
azure-mgmt-trafficmanager>=1.1.0

# Databases
azure-mgmt-sql>=4.0.0
azure-mgmt-rdbms>=10.2.0
azure-mgmt-cosmosdb>=9.4.0
azure-mgmt-redis>=14.3.0

# Identity & Security
msgraph-sdk>=1.2.0
azure-mgmt-security>=6.0.0
azure-mgmt-keyvault>=10.3.0
azure-keyvault-secrets>=4.8.0
azure-keyvault-keys>=4.9.0
azure-keyvault-certificates>=4.8.0

# Monitoring & Management
azure-mgmt-monitor>=6.0.2
azure-mgmt-loganalytics>=13.0.0

# App Services
azure-mgmt-web>=7.2.0
azure-mgmt-apimanagement>=4.0.0
azure-mgmt-logic>=10.0.0

# Data & Analytics
azure-mgmt-datafactory>=6.1.0
azure-mgmt-databricks>=2.0.0
azure-mgmt-synapse>=2.0.0
azure-mgmt-hdinsight>=9.0.0
azure-mgmt-search>=9.1.0
azure-mgmt-purview>=1.1.0

# Other Services
azure-mgmt-automation>=1.1.0
azure-mgmt-batch>=17.2.0
azure-mgmt-billing>=6.0.0
azure-mgmt-costmanagement>=4.0.1
azure-mgmt-eventgrid>=10.2.0
azure-mgmt-eventhub>=11.0.0
azure-mgmt-iothub>=3.0.0
azure-mgmt-notificationhubs>=8.0.0
azure-mgmt-recoveryservices>=2.5.0
azure-mgmt-dataprotection>=1.3.0
azure-mgmt-netapp>=13.0.0
azure-mgmt-elastic>=1.1.0

# Utilities
PyYAML>=6.0.1
```

---

## 🎯 Next Steps

1. **Clean up misnamed services**: Remove AWS-specific folders (`eks`, `lambda`, `s3`)
2. **Consolidate duplicates**: Merge `function`, `functionapp`, `functions`
3. **Create client factory**: Similar to boto3 session, create Azure client factory
4. **Update rules YAML**: Add `package` and `client_class` fields
5. **Build service validator**: Verify package/client combinations

Would you like me to proceed with any of these steps?

