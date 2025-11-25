# AWS to OCI Service Mapping

## Overview
**Issue**: 162 OCI rules use AWS service names instead of OCI equivalents
**Services Affected**: 45 AWS-like services
**Solution**: Map AWS services to their OCI equivalents

---

## AWS → OCI Service Mappings

### Compute Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `ec2` | N/A | `compute` | `oci.core.ComputeClient` |
| `awslambda` / `lambda` | 6 | `functions` | `oci.functions.FunctionsManagementClient` |
| `ecs` | N/A | `container_instances` | `oci.container_instances` |
| `eks` | 8 | `container_engine` | `oci.container_engine.ContainerEngineClient` |
| `aks` | 3 | `container_engine` | `oci.container_engine.ContainerEngineClient` |
| `emr` | 3 | `bds` | `oci.bds.BdsClient` (Big Data Service) |
| `sagemaker` | 8 | `data_science` | `oci.data_science.DataScienceClient` |

### Storage Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `s3` | 3 | `object_storage` | `oci.object_storage.ObjectStorageClient` |
| `ebs` | N/A | `block_storage` | `oci.core.BlockstorageClient` |
| `efs` | 5 | `file_storage` | `oci.file_storage.FileStorageClient` |
| `glacier` | N/A | `object_storage` | `oci.object_storage` (Archive tier) |

### Database Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `rds` | N/A | `database` | `oci.database.DatabaseClient` |
| `dynamodb` | 11 | `nosql` | `oci.nosql.NosqlClient` |
| `redshift` | 8 | `database` | `oci.database` (Autonomous DW) |
| `elasticache` | 6 | `redis` | OCI Cache with Redis |

### Networking Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `vpc` | N/A | `virtual_network` | `oci.core.VirtualNetworkClient` |
| `elb` | 5 | `load_balancer` | `oci.load_balancer.LoadBalancerClient` |
| `elbv2` | 7 | `load_balancer` | `oci.load_balancer.LoadBalancerClient` |
| `cloudfront` | 5 | `cdn` | OCI CDN (via Akamai partnership) |
| `ipsec_vpn_tls_certificates_service_vault_kms` | 2 | `ipsec_vpn` | `oci.core.VirtualNetworkClient` |

### Security Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `kms` | 5 | `key_management` | `oci.key_management.KmsVaultClient` |
| `oci_kms` | 2 | `key_management` | `oci.key_management.KmsVaultClient` |
| `oci_vault_kms_object_storage_encryption` | 2 | `key_management` | `oci.key_management` |
| `oci_vault_secrets` | 6 | `vault` | `oci.vault.VaultsClient` |
| `acm` | N/A | `certificates` | `oci.certificates.CertificatesClient` |
| `guardduty` | N/A | `cloud_guard` | `oci.cloud_guard.CloudGuardClient` |
| `waf` | Multiple | `waf` | `oci.waf.WafClient` |
| `oci_web_application_firewall_waf` | 5 | `waf` | `oci.waf.WafClient` |
| `oci_waf_address_lists` | 4 | `waf` | `oci.waf.WafClient` |
| `oci_waf_policy_rule_groups` | 4 | `waf` | `oci.waf.WafClient` |
| `oci_waf_regex_filters` | 3 | `waf` | `oci.waf.WafClient` |
| `oci_waf_rule` | 3 | `waf` | `oci.waf.WafClient` |
| `waf_address_lists` | 3 | `waf` | `oci.waf.WafClient` |
| `waf_edge` | 3 | `waf` | `oci.waf.WafClient` |

### Monitoring & Logging

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `cloudwatch` | 4 | `monitoring` | `oci.monitoring.MonitoringClient` |
| `cloudtrail` | 5 | `audit` | `oci.audit.AuditClient` |
| `oci_observability_management_dashboards` | 3 | `monitoring` | `oci.monitoring` |

### Messaging & Integration

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `sns` | 3 | `ons` | `oci.ons.NotificationDataPlaneClient` |
| `sqs` | N/A | `queue` | `oci.queue.QueueClient` |
| `kinesis` | N/A | `streaming` | `oci.streaming.StreamClient` |

### Other Services

| AWS Service | Rules | OCI Equivalent | OCI SDK Module |
|-------------|-------|----------------|----------------|
| `cloudformation` | N/A | `resource_manager` | `oci.resource_manager.ResourceManagerClient` |
| `oci_dns_records` | 5 | `dns` | `oci.dns.DnsClient` |

---

## Comprehensive Mapping Dictionary

```python
AWS_TO_OCI_SERVICE_MAPPING = {
    # Compute
    'ec2': 'compute',
    'awslambda': 'functions',
    'lambda': 'functions',
    'ecs': 'container_instances',
    'eks': 'container_engine',
    'aks': 'container_engine',  # Azure Kubernetes → OKE
    'emr': 'bds',  # EMR → Big Data Service
    'sagemaker': 'data_science',
    
    # Storage
    's3': 'object_storage',
    'ebs': 'block_storage',
    'efs': 'file_storage',
    'glacier': 'object_storage',  # Archive tier
    
    # Database
    'rds': 'database',
    'dynamodb': 'nosql',
    'redshift': 'database',  # → Autonomous Data Warehouse
    'elasticache': 'redis',  # OCI Cache with Redis
    
    # Networking
    'vpc': 'virtual_network',
    'elb': 'load_balancer',
    'elbv2': 'load_balancer',
    'cloudfront': 'cdn',
    'ipsec_vpn_tls_certificates_service_vault_kms': 'ipsec_vpn',
    
    # Security
    'kms': 'key_management',
    'oci_kms': 'key_management',
    'oci_vault_kms_object_storage_encryption': 'key_management',
    'oci_vault_secrets': 'vault',
    'acm': 'certificates',
    'guardduty': 'cloud_guard',
    
    # WAF Services (consolidate all)
    'waf': 'waf',
    'oci_web_application_firewall_waf': 'waf',
    'oci_waf_address_lists': 'waf',
    'oci_waf_policy_rule_groups': 'waf',
    'oci_waf_regex_filters': 'waf',
    'oci_waf_rule': 'waf',
    'waf_address_lists': 'waf',
    'waf_edge': 'waf',
    
    # Monitoring & Logging
    'cloudwatch': 'monitoring',
    'cloudtrail': 'audit',
    'oci_observability_management_dashboards': 'monitoring',
    
    # Messaging
    'sns': 'ons',  # Oracle Notification Service
    'sqs': 'queue',
    'kinesis': 'streaming',
    
    # Other
    'cloudformation': 'resource_manager',
    'oci_dns_records': 'dns',
}
```

---

## Resource Mappings

### Compute Resources

```python
# awslambda → functions
'function': 'function',
'function_configuration': 'function',

# eks/aks → container_engine
'cluster': 'cluster',
'node_pool': 'node_pool',

# sagemaker → data_science
'notebook_instance': 'notebook_session',
'model': 'model',
'endpoint': 'model_deployment',

# emr → bds
'cluster': 'bds_instance',
```

### Storage Resources

```python
# s3 → object_storage
'bucket': 'bucket',
'object': 'object',

# efs → file_storage
'file_system': 'file_system',
'mount_target': 'mount_target',
```

### Database Resources

```python
# dynamodb → nosql
'table': 'table',
'accelerator': 'table',  # DAX

# redshift → database
'cluster': 'autonomous_database',

# elasticache → redis
'cluster': 'redis_cluster',
'replication_group': 'redis_cluster',
```

### Networking Resources

```python
# elb/elbv2 → load_balancer
'load_balancer': 'load_balancer',
'target_group': 'backend_set',
'listener': 'listener',

# cloudfront → cdn
'distribution': 'distribution',
```

---

## Priority Fixes

### High Priority (Most Rules)

1. **dynamodb (11 rules)** → `nosql`
2. **eks (8 rules)** → `container_engine`
3. **redshift (8 rules)** → `database`
4. **sagemaker (8 rules)** → `data_science`
5. **elbv2 (7 rules)** → `load_balancer`

### Medium Priority (5-6 Rules)

6. **awslambda (6 rules)** → `functions`
7. **elasticache (6 rules)** → `redis`
8. **oci_vault_secrets (6 rules)** → `vault`
9. **cloudfront (5 rules)** → `cdn`
10. **efs (5 rules)** → `file_storage`
11. **elb (5 rules)** → `load_balancer`
12. **kms (5 rules)** → `key_management`
13. **cloudtrail (5 rules)** → `audit`

---

## Expected Impact

- **Rules to Update**: 162
- **Services to Rename**: 45
- **Grade Improvement**: Should reach proper OCI-native status
- **SDK Alignment**: Will match official OCI Python SDK

---

## Notes

1. **WAF Services**: Many variations should consolidate to single `waf`
2. **KMS/Vault**: Multiple variants should map to `key_management` or `vault`
3. **DNS**: `oci_dns_records` should be just `dns`
4. **Monitoring**: Various observability services → `monitoring`
5. **AKS**: Azure Kubernetes Service mistakenly in OCI rules

---

## Validation Needed

After mapping, verify:
- No AWS service names remain
- All services match OCI Python SDK
- Resources are OCI-appropriate
- Assertions make sense for OCI context

