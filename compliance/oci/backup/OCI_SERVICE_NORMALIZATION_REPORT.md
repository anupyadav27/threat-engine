# OCI Service & Resource Normalization Report

**Generated:** 2025-11-22  
**Total Rules:** 2,130  
**Format:** `oci.service.resource.security_check_assertion`

---

## 📊 Executive Summary

| Category | Count | Percentage | Action Required |
|----------|-------|------------|-----------------|
| **✅ Valid OCI Services** | 36 | 11.7% | ✅ No action - Already correct |
| **⚠️ Need CSP Mapping** | 39 | 12.7% | ⚠️ Map to OCI equivalents |
| **❌ Unknown Services** | 232 | 75.6% | ❌ Investigate & normalize |
| **Total Services** | 307 | 100% | |

**Rules Affected:**
- ✅ **Valid:** 1,973 rules (92.6%) - Already using correct OCI service names
- ⚠️ **Need Mapping:** 157 rules (7.4%) - Using AWS/Azure/GCP service names

---

## ✅ Valid OCI Services (36 services, 1,973 rules)

These services already match OCI Python SDK naming - **NO ACTION NEEDED**

### Top 20 Valid Services:

| Service | Rules | OCI Python SDK Client |
|---------|-------|----------------------|
| `database` | 123 | `oci.database.DatabaseClient` |
| `data_science` | 123 | `oci.data_science.DataScienceClient` |
| `compute` | 113 | `oci.core.ComputeClient` |
| `data_catalog` | 103 | `oci.data_catalog.DataCatalogClient` |
| `identity` | 101 | `oci.identity.IdentityClient` |
| `monitoring` | 74 | `oci.monitoring.MonitoringClient` |
| `virtual_network` | 46 | `oci.core.VirtualNetworkClient` |
| `analytics` | 44 | `oci.analytics.AnalyticsClient` |
| `data_integration` | 43 | `oci.data_integration.DataIntegrationClient` |
| `cloud_guard` | 28 | `oci.cloud_guard.CloudGuardClient` |
| `audit` | 26 | `oci.audit.AuditClient` |
| `waf` | 26 | `oci.waf.WafClient` |
| `key_management` | 24 | `oci.key_management.KmsVaultClient` |
| `container_engine` | 23 | `oci.container_engine.ContainerEngineClient` |
| `apigateway` | 22 | `oci.apigateway.ApiGatewayClient` |
| `logging` | 22 | `oci.logging.LoggingManagementClient` |
| `object_storage` | 19 | `oci.object_storage.ObjectStorageClient` |
| `events` | 19 | `oci.events.EventsClient` |
| `nosql` | 17 | `oci.nosql.NosqlClient` |
| `block_storage` | 14 | `oci.core.BlockstorageClient` |

---

## ⚠️ Services Needing CSP Mapping (39 services, 157 rules)

These use AWS/Azure/GCP service names - **MAPPING REQUIRED**

### AWS Services → OCI Mapping

| AWS Service | Rules | Map To OCI | OCI SDK Client |
|-------------|-------|------------|----------------|
| `object` | 25 | `object_storage` | `oci.object_storage.ObjectStorageClient` |
| `defender` | 24 | `cloud_guard` | `oci.cloud_guard.CloudGuardClient` |
| `opensearch` | 10 | `analytics` | `oci.analytics.AnalyticsClient` |
| `codebuild` | 8 | `devops` | `oci.devops.DevopsClient` |
| `api` | 8 | `apigateway` | `oci.apigateway.ApiGatewayClient` |
| `sagemaker` | 8 | `data_science` | `oci.data_science.DataScienceClient` |
| `load` | 8 | `load_balancer` | `oci.load_balancer.LoadBalancerClient` |
| `efs` | 5 | `file_storage` | `oci.file_storage.FileStorageClient` |
| `neptune` | 5 | `database` | `oci.database.DatabaseClient` |
| `app` | 5 | `functions` | `oci.functions.FunctionsManagementClient` |
| `ssm` | 5 | `compute` | `oci.core.ComputeClient` (OS Management) |
| `dms` | 4 | `database` | `oci.database.DatabaseClient` |
| `cloudwatch` | 4 | `monitoring` | `oci.monitoring.MonitoringClient` |
| `autoscaling` | 4 | `compute` | `oci.core.ComputeClient` |
| `emr` | 3 | `bds` | `oci.bds.BdsClient` |
| `mq` | 3 | `streaming` | `oci.streaming.StreamClient` |
| `networkfirewall` | 3 | `network_firewall` | `oci.network_firewall.NetworkFirewallClient` |
| `kafka` | 3 | `streaming` | `oci.streaming.StreamClient` |
| `ebs` | 2 | `block_storage` | `oci.core.BlockstorageClient` |
| `guardduty` | 2 | `cloud_guard` | `oci.cloud_guard.CloudGuardClient` |
| `kinesis` | 2 | `streaming` | `oci.streaming.StreamClient` |
| `config` | 2 | `cloud_guard` | `oci.cloud_guard.CloudGuardClient` |
| `directconnect` | 2 | `virtual_network` | `oci.core.VirtualNetworkClient` |
| `sqs` | 2 | `queue` | `oci.queue.QueueClient` |
| `organizations` | 2 | `identity` | `oci.identity.IdentityClient` |
| `os` | 2 | `compute` | `oci.core.ComputeClient` |
| `wafv2` | 2 | `waf` | `oci.waf.WafClient` |
| And 12 more... | | | |

---

## ❌ Unknown/Invalid Services (232 services, needs investigation)

These are **custom service names or complex descriptive names** that don't match OCI SDK

### Categories of Unknown Services:

#### 1. **OCI-Specific Descriptive Names** (Likely need resource-level mapping)
Examples:
- `oci_api_gateway_request_response_validation_openapi` → Map to `apigateway`
- `oci_streaming_kafka_compatible` → Map to `streaming`
- `oci_object_storage_bucket` → Map to `object_storage`
- `oci_vault_key` → Map to `key_management`
- `oci_nosql_table` → Map to `nosql`

#### 2. **Kubernetes/OKE Services** (Large category - 20+ services)
Examples:
- `oke_control_plane_api_server` → Map to `container_engine`
- `oke_worker_nodes_kubelet` → Map to `container_engine`
- `oke_rbac` → Map to `container_engine`
- `oke_etcd_managed` → Map to `container_engine`

#### 3. **Cloud-Specific Services** (AWS/Azure/GCP)
Examples:
- `cloudtrail` → Map to `audit`
- `cloudwatch` → Map to `monitoring`
- `cloudsql` → Map to `mysql`
- `cloudstorage` → Map to `object_storage`
- `bigquery` → Map to `analytics`

#### 4. **Azure Services**
Examples:
- `entra` (19 rules) → Map to `identity`
- `defender` → Map to `cloud_guard`
- `keyvault` → Map to `key_management`
- `cosmosdb` → Map to `database`
- `postgresql` → Map to `mysql`

#### 5. **Composite/Descriptive Services**
Examples:
- `full_stack_dr_plans` → Map to appropriate DR service
- `functions_image_version_ocir_deployment_version` → Map to `functions` or `artifacts`
- `oracle_container_engine_for_kubernetes_oke` → Map to `container_engine`
- `service_connector_hub` → Map to `events` or appropriate service

---

## 🎯 Recommended Actions

### Phase 1: Map Known CSP Services (39 services, 157 rules)
**Priority: HIGH** - These are straightforward AWS/Azure/GCP → OCI mappings

```python
# Apply mappings from NON_OCI_SERVICE_MAPPINGS dictionary
# Example: object → object_storage, defender → cloud_guard
```

### Phase 2: Normalize OCI-Prefixed Services (50+ services)
**Priority: MEDIUM** - Services starting with `oci_` that should map to core OCI services

Examples:
- `oci_object_storage_bucket` → `object_storage` (resource: `bucket`)
- `oci_api_gateway_*` → `apigateway` (various resources)
- `oci_streaming_*` → `streaming` (various resources)
- `oci_vault_*` → `key_management` or `vault`

### Phase 3: Consolidate OKE/Kubernetes Services (20+ services)
**Priority: MEDIUM** - All OKE-related services should map to `container_engine`

Examples:
- `oke_control_plane_*` → `container_engine` (resource: `cluster`)
- `oke_worker_nodes_*` → `container_engine` (resource: `node_pool`)
- `oke_rbac` → `container_engine` (resource: `cluster`)

### Phase 4: Handle Complex/Composite Services (100+ services)
**Priority: LOW-MEDIUM** - Requires manual analysis and decision

Categories:
1. Descriptive service names that are really resource types
2. Composite services combining multiple OCI services
3. Legacy or deprecated naming conventions

---

## 📁 Generated Files

1. **`oci_service_analysis.json`** - Complete analysis of all 307 services
2. **`oci_service_mapping_report.json`** - Detailed mapping recommendations
3. **`oci_resource_analysis.json`** - Resource analysis per service

---

## 🔄 Next Steps

1. **Review** the generated JSON files for detailed mappings
2. **Create** a comprehensive service normalization script
3. **Apply** mappings in phases (CSP → OCI, then OCI consolidation)
4. **Validate** all rules still follow `oci.service.resource.assertion` format
5. **Test** a sample of rules after normalization

---

## 💡 Key Insights

- **92.6%** of rules already use valid OCI service names ✅
- Only **7.4%** need CSP mapping (AWS/Azure/GCP → OCI) ⚠️
- **75.6%** of unique service names are custom/descriptive (likely need resource-level refactoring) ❌
- Most work is consolidating descriptive service names into proper OCI SDK services

---

*Generated by OCI Service Normalization Analysis Tool*  
*Date: 2025-11-22*

