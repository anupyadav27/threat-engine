# IBM Cloud Python SDK Service and Resource Mapping

## Overview

**Important Discovery**: The IBM rule_ids.yaml contains rules for **multiple cloud providers**, not just IBM Cloud:
- IBM Cloud native services
- AWS services (ec2, s3, lambda, etc.)
- Azure services (entra, defender, keyvault, etc.)
- GCP services (bigquery, gcr, etc.)
- Kubernetes/OpenShift

This suggests the rules are for **multi-cloud CSPM** with IBM as the primary platform.

---

## IBM Cloud Native Services (Python SDK Available)

### Core IBM Cloud Services

Based on `ibm-cloud-sdk-python` and `ibm-platform-services`:

#### 1. **Activity Tracker** (`ibm-platform-services`)
```python
# Package: ibm-platform-services
from ibm_platform_services import ActivityTrackerV2

# Current Resources in Rules:
- bucket                     → Should be: event
- resource                   → Should be: event
- tracker_*                  → Should be: event
```

#### 2. **Certificate Manager** (`ibm-cloud-networking`)
```python
# Package: ibm-cloud-networking  
from ibm_cloud_networking import CertificateManagerV1

# Current Resources in Rules:
- manager                    → Should be: certificate
```

#### 3. **CIS (Cloud Internet Services)** (`ibm-cloud-networking`)
```python
# Package: ibm-cloud-networking
from ibm_cloud_networking import CisV1

# Current Resources in Rules:
- resource                   → Should be: zone (or domain)
```

#### 4. **Cloud Object Storage (COS)** (`ibm-cos-sdk`)
```python
# Package: ibm-cos-sdk
import ibm_boto3

# Current Resources in Rules:
- bucket                     → Correct ✅
```

#### 5. **Cloudant** (`cloudant`)
```python
# Package: cloudant
from cloudant.client import Cloudant

# Current Resources in Rules:
- database                   → Correct ✅
- document                   → Correct ✅
- table                      → Should be: database
```

#### 6. **Cloud Databases** (`ibm-cloud-databases`)
```python
# Package: ibm-cloud-databases
from ibm_cloud_databases import CloudDatabasesV5

# Current Resources in Rules:
- instance                   → Should be: deployment
- cluster                    → Should be: deployment
- for_postgresql_*           → Should be: deployment
```

#### 7. **Code Engine** (`ibm-code-engine-sdk`)
```python
# Package: ibm-code-engine-sdk
from ibm_code_engine_sdk import CodeEngineV2

# Current Resources in Rules:
- resource                   → Should be: project or application
```

#### 8. **Container Registry** (`ibm-container-registry`)
```python
# Package: ibm-container-registry
from ibm_container_registry import ContainerRegistryV1

# Current Resources in Rules:
- registry_repository        → Should be: namespace
- registry_policy            → Should be: namespace
- registry_lifecycle_policy  → Should be: namespace
- registry_replication_config → Should be: namespace
- resource                   → Should be: namespace
```

#### 9. **IAM (Identity and Access Management)** (`ibm-platform-services`)
```python
# Package: ibm-platform-services
from ibm_platform_services import IamIdentityV1, IamAccessGroupsV2, IamPolicyManagementV1

# Current Resources in Rules:
- access_group               → Correct ✅
- account                    → Should be: account_settings
- group                      → Should be: access_group
- identity_provider          → Should be: identity_provider ✅
- identity_federation_status → Should be: account_settings
- key                        → Should be: api_key
- policy                     → Correct ✅
- role                       → Correct ✅
- service_id                 → Should be: service_id ✅
- user                       → Should be: user ✅
```

#### 10. **Key Protect** (`ibm-key-protect`)
```python
# Package: ibm-key-protect
from ibm_key_protect import KeyProtectV1

# Current Resources in Rules:
- key                        → Correct ✅
- protect_alias              → Should be: key
- protect_certificate        → Should be: key
- protect_cmk_*              → Should be: key
- protect_configuration      → Should be: instance_policy
- protect_encryption         → Should be: key
- protect_grant              → Should be: key_policy
- protect_key                → Correct ✅
- protect_managed            → Should be: key
- protect_parameter          → Should be: instance_policy
- protect_patch              → Should be: key
- protect_private_ca         → Should be: key
- protect_store              → Should be: instance
```

#### 11. **Kubernetes Service (IKS)** (`ibm-container-service-api`)
```python
# Package: ibm-container-service-api
from ibm_container_service_api import ContainerV1

# Current Resources in Rules:
- cluster                    → Correct ✅
- resource                   → Should be: cluster
- service_addon              → Should be: cluster_addon
- service_admission_controller → Should be: cluster
- service_cluster            → Should be: cluster
- service_namespace          → Should be: cluster
- service_network_policy     → Should be: cluster
- service_serverless         → Should be: cluster
- service_service            → Should be: cluster
- service_worker_node        → Should be: worker
```

#### 12. **Logging (LogDNA / IBM Cloud Logs)** (`ibm-log-analysis`)
```python
# Package: ibm-log-analysis
from ibm_log_analysis import LogAnalysisV1

# Current Resources in Rules:
- log_destination            → Should be: target
- log_stream                 → Should be: view
- query_definition           → Should be: view
- sink                       → Should be: target
- store                      → Should be: instance
```

#### 13. **Monitoring (SysD

ig)** (`ibm-cloud-monitoring`)
```python
# Package: ibm-cloud-monitoring
from ibm_cloud_monitoring import MonitoringV1

# Current Resources in Rules:
- alert                      → Correct ✅
- anomaly_detector           → Should be: alert
- dashboard                  → Correct ✅
- log                        → Should be: capture
- notification_channel       → Should be: notification_channel ✅
- sampling_rule              → Should be: capture
- trace                      → Should be: capture
```

#### 14. **Object Storage** (see COS above)
```python
# Current Resources in Rules:
- storage                    → Should be: bucket
- storage_bucket             → Should be: bucket
- storage_notification       → Should be: notification_configuration
- storage_policy             → Should be: bucket_policy
```

#### 15. **Resource Controller** (`ibm-platform-services`)
```python
# Package: ibm-platform-services
from ibm_platform_services import ResourceControllerV2, ResourceManagerV2

# Current Resources in Rules:
- controller_aggregation     → Should be: resource_group
- controller_aggregator      → Should be: resource_group
- controller_delivery        → Should be: resource_group
- controller_folder          → Should be: resource_group
- controller_organization    → Should be: resource_group
- controller_policy          → Should be: resource_group
- controller_project         → Should be: resource_group
- controller_recorder        → Should be: resource_instance
```

#### 16. **Schematics** (`ibm-schematics`)
```python
# Package: ibm-schematics
from ibm_schematics import SchematicsV1

# Current Resources in Rules:
- managed                    → Should be: workspace
- workspace                  → Correct ✅
```

#### 17. **Secrets Manager** (`ibm-secrets-manager-sdk`)
```python
# Package: ibm-secrets-manager-sdk
from ibm_secrets_manager_sdk import SecretsManagerV2

# Current Resources in Rules:
- resource                   → Should be: secret
```

#### 18. **Security and Compliance Center** (`ibm-scc`)
```python
# Package: ibm-scc
from ibm_scc import SecurityAndComplianceCenterApiV3

# Current Resources in Rules:
- resource                   → Should be: profile or control
```

#### 19. **Virtual Private Cloud (VPC)** (`ibm-vpc`)
```python
# Package: ibm-vpc
from ibm_vpc import VpcV1

# Current Resources in Rules:
- different_regions          → Should be: vpc
- ebs                        → Should be: volume (IBM calls it "volume" not EBS)
- endpoint_connections_*     → Should be: endpoint_gateway
- endpoint_services_*        → Should be: endpoint_gateway
- group                      → Should be: security_group
- network                    → Should be: vpc
- networkacl                 → Should be: network_acl
- securitygroup              → Should be: security_group
- securitygroup_default_*    → Should be: security_group
- subnet_different_az        → Should be: subnet
- tunnel                     → Should be: vpn_gateway
```

#### 20. **Virtual Server Instances (VSI)** (`ibm-vpc`)
```python
# Package: ibm-vpc (part of VPC service)
from ibm_vpc import VpcV1

# Current Resources in Rules:
- elastic                    → Should be: floating_ip
- elastic_ip_*               → Should be: floating_ip
- instance                   → Correct ✅
- launch_template_*          → Should be: instance_template
- management_compliance      → Should be: instance
- networkacl_unused          → Should be: network_acl
- patch_compliance           → Should be: instance
- resource                   → Should be: instance
- securitygroup_*            → Should be: security_group
- snapshot                   → Should be: snapshot ✅
- volume                     → Should be: volume ✅
```

#### 21. **Watson Services** (`ibm-watson`)
```python
# Package: ibm-watson
from ibm_watson import WatsonMachineLearningV4

# Current Resources in Rules:
- machine_learning_auto_ml           → Should be: training
- machine_learning_batch_scoring     → Should be: deployment
- machine_learning_data_set          → Should be: data_asset
- machine_learning_deployment        → Should be: deployment ✅
- machine_learning_feature_store     → Should be: data_asset
- machine_learning_hyperparameter_tuning → Should be: training
- machine_learning_model             → Should be: model ✅
- machine_learning_model_monitoring  → Should be: monitor
- machine_learning_model_version     → Should be: model
- machine_learning_pipeline          → Should be: pipeline ✅
```

---

## Multi-Cloud Services (Not IBM Native)

### AWS Services in IBM Rules
These should use AWS SDK if targeting AWS resources, or map to IBM equivalents:

```yaml
# AWS Services found:
- ec2, ebs, s3, lambda, rds, dynamodb, elb, elbv2
- Should either:
  1. Use AWS SDK: boto3
  2. Map to IBM equivalents (vsi, cos, etc.)
```

### Azure Services in IBM Rules
```yaml
# Azure Services found:
- entra, defender, keyvault, monitor, vm
- Should either:
  1. Use Azure SDK: azure-*
  2. Map to IBM equivalents
```

### GCP Services in IBM Rules
```yaml
# GCP Services found:
- bigquery, gcr
- Should either:
  1. Use GCP SDK: google-cloud-*
  2. Map to IBM equivalents
```

---

## Key Findings & Recommendations

### 1. **Multi-Cloud Architecture**
The ruleset is designed for **multi-cloud CSPM** with IBM as one provider among AWS, Azure, and GCP.

### 2. **Generic Resources**
Many services use generic `resource` - should be replaced with specific IBM SDK resource types.

### 3. **AWS Terminology in IBM Rules**
Terms like `ebs`, `s3`, `ec2` appear in IBM rules - should use IBM terminology:
- `ebs` → `volume` (IBM Block Storage)
- `s3` → `cos` or `bucket` (IBM Cloud Object Storage)
- `ec2` → `vsi` or `instance` (IBM Virtual Server)

### 4. **Service Name Consolidation Needed**
- `key.protect_*` → All should be under `key` resource
- `cloud.backup_*` → All should be consolidated
- `virtual.private_cloud_*` → Should be under `vpc` service

---

## Recommended Fixes Priority

### High Priority (IBM Native Services)
1. **Fix generic "resource"** → Specific resource types
2. **Consolidate Key Protect resources** → Use `key` and `instance_policy`
3. **Fix VPC resources** → Use IBM VPC SDK naming
4. **Fix Container Registry** → Use `namespace` not `registry_*`
5. **Fix IAM resources** → Align with IBM IAM SDK

### Medium Priority (Service Consolidation)
1. Consolidate `cloud.backup_*` resources
2. Consolidate `virtual.private_cloud_*` → `vpc.*`
3. Fix Watson ML resource names

### Low Priority (Multi-Cloud Decisions)
1. Decide on AWS resources: Keep AWS or map to IBM?
2. Decide on Azure resources: Keep Azure or map to IBM?
3. Decide on GCP resources: Keep GCP or map to IBM?

---

## Next Steps

1. **Clarify Multi-Cloud Intent**: 
   - Is this meant to monitor AWS/Azure/GCP resources through IBM?
   - Or should non-IBM services be removed?

2. **Fix IBM Native Services First**:
   - Replace generic "resource"
   - Align with IBM Python SDK naming
   - Consolidate fragmented resources

3. **Create Validation Script**:
   - Similar to GCP validation
   - Check against IBM SDK documentation
   - Identify all mismatches

---

**Total Services**: 129  
**IBM Native Services**: ~40  
**AWS Services**: ~50  
**Azure Services**: ~10  
**GCP Services**: ~5  
**Multi-Cloud/K8s**: ~24

**Recommendation**: Focus on IBM native services first, then decide multi-cloud strategy.

