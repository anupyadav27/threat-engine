# S3 - Resource Inventory Report

**Generated:** 2026-01-20T19:24:28.808951

**Root Operations:** ListBuckets, ListDirectoryBuckets

---

## Primary Resource

### bucket

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `ListBuckets`
- `ListDirectoryBuckets`

---

### bucket_bucket

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `s3.bucket_bucket_arn`

#### ✅ Can be produced from ROOT operations:

- `ListBuckets`
- `ListDirectoryBuckets`

---

## Configuration

### analytics_configuration

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetBucketAnalyticsConfiguration`
- `GetBucketIntelligentTieringConfiguration`
- `GetBucketInventoryConfiguration`
- `GetBucketMetricsConfiguration`
- `GetBucketNotification`
- `GetBucketNotificationConfiguration`
- `ListBucketAnalyticsConfigurations`
- `ListBucketIntelligentTieringConfigurations`
- `ListBucketInventoryConfigurations`
- `ListBucketMetricsConfigurations`

---

### topic_configuration_topic

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** Yes
- **ARN Entity:** `s3.topic_configuration_topic_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetBucketNotificationConfiguration`

---

## Ephemeral

### upload_upload

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `ListMultipartUploads`
- `ListParts`

---

### version_version

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetObject`
- `GetObjectAttributes`
- `GetObjectTagging`
- `ListObjectVersions`

---

## Sub Resource

### cors_rul

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetBucketCors`
- `GetBucketLifecycle`
- `GetBucketLifecycleConfiguration`

---
