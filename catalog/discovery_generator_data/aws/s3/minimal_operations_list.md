# S3 - Minimal Operations List

**Generated:** 2026-01-20T19:31:01.813927

**Total Fields:** 89
**Total Operations Needed:** 27
**Independent Operations:** 1
**Dependent Operations:** 26
**Coverage:** 6.9%

---

## ✅ Independent Operations (Root Operations)

These operations can be called without any dependencies:

### 1. ListBuckets

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** s3.bucket_bucket_arn, s3.bucket_bucket_region, s3.bucket_creation_date, s3.bucket_name, s3.rul_prefix...

## ⚠️  Dependent Operations

These operations require inputs from other operations:

### 1. ListObjectVersions

- **Type:** Dependent
- **Entities Covered:** 10
- **Covers:** s3.checksum_checksum_type, s3.tag_set_key, s3.upload_checksum_algorithm, s3.upload_storage_class, s3.version_e_tag...
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 2. GetObject

- **Type:** Dependent
- **Entities Covered:** 10
- **Covers:** s3.body_body, s3.body_expires, s3.body_object_lock_retain_until_date, s3.body_restore, s3.checksum_checksum_crc32...
- **Requires:** s3.bucket_name, s3.tag_set_key
- **Dependencies:** s3.bucket_name, s3.tag_set_key

### 3. GetBucketLifecycleConfiguration

- **Type:** Dependent
- **Entities Covered:** 8
- **Covers:** s3.abac_statu_status, s3.analytics_configuration_filter, s3.cors_rul_id, s3.rul_abort_incomplete_multipart_upload, s3.rul_noncurrent_version_expiration...
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 4. ListBucketInventoryConfigurations

- **Type:** Dependent
- **Entities Covered:** 6
- **Covers:** s3.analytics_configuration_id, s3.inventory_configuration_destination, s3.inventory_configuration_included_object_versions, s3.inventory_configuration_is_enabled, s3.inventory_configuration_optional_fields...
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 5. GetBucketCors

- **Type:** Dependent
- **Entities Covered:** 5
- **Covers:** s3.cors_rul_allowed_headers, s3.cors_rul_allowed_methods, s3.cors_rul_allowed_origins, s3.cors_rul_expose_headers, s3.cors_rul_max_age_seconds
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 6. GetPublicAccessBlock

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** s3.public_access_block_configuration_block_public_acls, s3.public_access_block_configuration_block_public_policy, s3.public_access_block_configuration_ignore_public_acls, s3.public_access_block_configuration_restrict_public_buckets
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 7. GetBucketLogging

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** s3.logging_enabled_target_bucket, s3.logging_enabled_target_grants, s3.logging_enabled_target_object_key_format, s3.logging_enabled_target_prefix
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 8. ListMultipartUploads

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** s3.upload_initiated, s3.upload_initiator, s3.upload_upload_id
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 9. GetBucketMetadataTableConfiguration

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** s3.get_bucket_metadata_table_configuration_result_error, s3.get_bucket_metadata_table_configuration_result_get_bucket_metadata_table_configuration_result, s3.get_bucket_metadata_table_configuration_result_metadata_table_configuration_result
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 10. GetObjectAcl

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** s3.grant_grantee, s3.grant_grants, s3.grant_permission
- **Requires:** s3.bucket_name, s3.tag_set_key
- **Dependencies:** s3.bucket_name, s3.tag_set_key

### 11. GetBucketNotification

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** s3.topic_configuration_event, s3.topic_configuration_events, s3.topic_configuration_topic
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 12. GetObjectRetention

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** s3.retention_mode, s3.retention_retain_until_date, s3.retention_retention
- **Requires:** s3.bucket_name, s3.tag_set_key
- **Dependencies:** s3.bucket_name, s3.tag_set_key

### 13. GetBucketLifecycle

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** s3.rul_noncurrent_version_transition, s3.rul_transition
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 14. GetBucketWebsite

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** s3.routing_rul_condition, s3.routing_rul_redirect
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 15. GetBucketMetadataConfiguration

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** s3.get_bucket_metadata_configuration_result_get_bucket_metadata_configuration_result, s3.get_bucket_metadata_configuration_result_metadata_configuration_result
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 16. GetObjectLockConfiguration

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** s3.object_lock_configuration_object_lock_enabled, s3.object_lock_configuration_rule
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 17. ListParts

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.part_part_number
- **Requires:** s3.bucket_name, s3.tag_set_key, s3.upload_upload_id
- **Dependencies:** s3.bucket_name, s3.tag_set_key, s3.upload_upload_id

### 18. GetObjectAttributes

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.checksum_checksum
- **Requires:** s3.bucket_name, s3.tag_set_key
- **Dependencies:** s3.bucket_name, s3.tag_set_key

### 19. GetBucketIntelligentTieringConfiguration

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.intelligent_tiering_configuration_tierings
- **Requires:** s3.analytics_configuration_id, s3.bucket_name
- **Dependencies:** s3.analytics_configuration_id, s3.bucket_name

### 20. GetBucketNotificationConfiguration

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.topic_configuration_topic_arn
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 21. GetObjectTagging

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.tag_set_value
- **Requires:** s3.bucket_name, s3.tag_set_key
- **Dependencies:** s3.bucket_name, s3.tag_set_key

### 22. GetBucketAnalyticsConfiguration

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.analytics_configuration_storage_class_analysis
- **Requires:** s3.analytics_configuration_id, s3.bucket_name
- **Dependencies:** s3.analytics_configuration_id, s3.bucket_name

### 23. GetBucketReplication

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.replication_configuration_role
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 24. GetBucketRequestPayment

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.payer_payer
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 25. GetBucketPolicyStatus

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.policy_statu_is_public
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

### 26. GetBucketPolicy

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** s3.policy_policy
- **Requires:** s3.bucket_name
- **Dependencies:** s3.bucket_name

---

## 📋 Complete Operations List (In Order)

### Independent Operations:
1. `ListBuckets`

### Dependent Operations:
1. `ListObjectVersions`
1. `GetObject`
1. `GetBucketLifecycleConfiguration`
1. `ListBucketInventoryConfigurations`
1. `GetBucketCors`
1. `GetPublicAccessBlock`
1. `GetBucketLogging`
1. `ListMultipartUploads`
1. `GetBucketMetadataTableConfiguration`
1. `GetObjectAcl`
1. `GetBucketNotification`
1. `GetObjectRetention`
1. `GetBucketLifecycle`
1. `GetBucketWebsite`
1. `GetBucketMetadataConfiguration`
1. `GetObjectLockConfiguration`
1. `ListParts`
1. `GetObjectAttributes`
1. `GetBucketIntelligentTieringConfiguration`
1. `GetBucketNotificationConfiguration`
1. `GetObjectTagging`
1. `GetBucketAnalyticsConfiguration`
1. `GetBucketReplication`
1. `GetBucketRequestPayment`
1. `GetBucketPolicyStatus`
1. `GetBucketPolicy`
