#!/bin/bash
# GCP Test Resource Provisioning Script
# Creates minimal test resources for comprehensive compliance testing
# Usage: ./provision_test_resources.sh <project_id> <region>

set -e

PROJECT_ID=${1:-test-2277}
REGION=${2:-us-central1}
ZONE="${REGION}-a"
TIMESTAMP=$(date +%s)
PREFIX="compliance-test-${TIMESTAMP}"

echo "=========================================="
echo "GCP Compliance Test Resource Provisioning"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Zone: $ZONE"
echo "Prefix: $PREFIX"
echo ""

# Enable required APIs
echo "📡 Enabling required APIs..."
gcloud services enable compute.googleapis.com --project=$PROJECT_ID
gcloud services enable storage.googleapis.com --project=$PROJECT_ID
gcloud services enable pubsub.googleapis.com --project=$PROJECT_ID
gcloud services enable sqladmin.googleapis.com --project=$PROJECT_ID
gcloud services enable cloudkms.googleapis.com --project=$PROJECT_ID
gcloud services enable iam.googleapis.com --project=$PROJECT_ID
gcloud services enable bigquery.googleapis.com --project=$PROJECT_ID
gcloud services enable cloudfunctions.googleapis.com --project=$PROJECT_ID
gcloud services enable secretmanager.googleapis.com --project=$PROJECT_ID
gcloud services enable logging.googleapis.com --project=$PROJECT_ID
gcloud services enable monitoring.googleapis.com --project=$PROJECT_ID

echo "⏳ Waiting 30s for API propagation..."
sleep 30

# Track created resources for cleanup
CLEANUP_FILE="/tmp/gcp_test_resources_${PROJECT_ID}.txt"
> $CLEANUP_FILE

echo ""
echo "🚀 Creating Test Resources..."
echo ""

# ============================================================================
# 1. GCS - Cloud Storage
# ============================================================================
echo "1️⃣  GCS (Cloud Storage)..."

# Create test bucket with versioning (PASS scenario)
BUCKET_PASS="${PREFIX}-bucket-pass"
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$BUCKET_PASS/
gsutil versioning set on gs://$BUCKET_PASS/
echo "gs://$BUCKET_PASS" >> $CLEANUP_FILE
echo "  ✅ Created bucket: $BUCKET_PASS (with versioning)"

# Create test bucket without versioning (FAIL scenario)
BUCKET_FAIL="${PREFIX}-bucket-fail"
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$BUCKET_FAIL/
echo "gs://$BUCKET_FAIL" >> $CLEANUP_FILE
echo "  ✅ Created bucket: $BUCKET_FAIL (without versioning)"

# ============================================================================
# 2. Compute Engine
# ============================================================================
echo "2️⃣  Compute Engine..."

# Create test instance
INSTANCE_NAME="${PREFIX}-instance"
gcloud compute instances create $INSTANCE_NAME \
  --project=$PROJECT_ID \
  --zone=$ZONE \
  --machine-type=e2-micro \
  --image-family=debian-11 \
  --image-project=debian-cloud \
  --boot-disk-size=10GB \
  --boot-disk-type=pd-standard \
  --no-shielded-secure-boot \
  --quiet
echo "instance:$ZONE:$INSTANCE_NAME" >> $CLEANUP_FILE
echo "  ✅ Created instance: $INSTANCE_NAME"

# Create test disk
DISK_NAME="${PREFIX}-disk"
gcloud compute disks create $DISK_NAME \
  --project=$PROJECT_ID \
  --zone=$ZONE \
  --size=10GB \
  --type=pd-standard \
  --quiet
echo "disk:$ZONE:$DISK_NAME" >> $CLEANUP_FILE
echo "  ✅ Created disk: $DISK_NAME"

# Test firewall rule (insecure - FAIL scenario)
FW_NAME="${PREFIX}-allow-all"
gcloud compute firewall-rules create $FW_NAME \
  --project=$PROJECT_ID \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22,tcp:80 \
  --source-ranges=0.0.0.0/0 \
  --quiet
echo "firewall:$FW_NAME" >> $CLEANUP_FILE
echo "  ✅ Created firewall: $FW_NAME (insecure - for testing)"

# ============================================================================
# 3. Pub/Sub
# ============================================================================
echo "3️⃣  Pub/Sub..."

# Create topic with KMS (PASS scenario)
TOPIC_NAME="${PREFIX}-topic"
gcloud pubsub topics create $TOPIC_NAME --project=$PROJECT_ID --quiet
echo "pubsub-topic:$TOPIC_NAME" >> $CLEANUP_FILE
echo "  ✅ Created topic: $TOPIC_NAME"

# Create subscription
SUB_NAME="${PREFIX}-subscription"
gcloud pubsub subscriptions create $SUB_NAME \
  --topic=$TOPIC_NAME \
  --project=$PROJECT_ID \
  --quiet
echo "pubsub-sub:$SUB_NAME" >> $CLEANUP_FILE
echo "  ✅ Created subscription: $SUB_NAME"

# ============================================================================
# 4. BigQuery
# ============================================================================
echo "4️⃣  BigQuery..."

# Create dataset
DATASET_NAME="${PREFIX//-/_}_dataset"
bq --project_id=$PROJECT_ID mk --dataset --location=$REGION $DATASET_NAME
echo "bigquery-dataset:$DATASET_NAME" >> $CLEANUP_FILE
echo "  ✅ Created dataset: $DATASET_NAME"

# ============================================================================
# 5. Cloud KMS
# ============================================================================
echo "5️⃣  Cloud KMS..."

# Create key ring
KEYRING_NAME="${PREFIX}-keyring"
gcloud kms keyrings create $KEYRING_NAME \
  --location=$REGION \
  --project=$PROJECT_ID \
  --quiet 2>/dev/null || echo "  ℹ️  Key ring may already exist"
echo "kms-keyring:$REGION:$KEYRING_NAME" >> $CLEANUP_FILE

# Create key
KEY_NAME="${PREFIX}-key"
gcloud kms keys create $KEY_NAME \
  --keyring=$KEYRING_NAME \
  --location=$REGION \
  --purpose=encryption \
  --project=$PROJECT_ID \
  --quiet 2>/dev/null || echo "  ℹ️  Key may already exist"
echo "kms-key:$REGION:$KEYRING_NAME:$KEY_NAME" >> $CLEANUP_FILE
echo "  ✅ Created KMS key: $KEY_NAME"

# ============================================================================
# 6. IAM
# ============================================================================
echo "6️⃣  IAM..."

# Create test service account
SA_NAME="${PREFIX}-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts create $SA_NAME \
  --display-name="Compliance Test Service Account" \
  --project=$PROJECT_ID \
  --quiet
echo "service-account:$SA_EMAIL" >> $CLEANUP_FILE
echo "  ✅ Created service account: $SA_NAME"

# ============================================================================
# 7. Secret Manager
# ============================================================================
echo "7️⃣  Secret Manager..."

# Create secret
SECRET_NAME="${PREFIX}-secret"
echo -n "test-secret-value" | gcloud secrets create $SECRET_NAME \
  --data-file=- \
  --project=$PROJECT_ID \
  --replication-policy=automatic \
  --quiet
echo "secret:$SECRET_NAME" >> $CLEANUP_FILE
echo "  ✅ Created secret: $SECRET_NAME"

# ============================================================================
# 8. Cloud Functions (if time permits)
# ============================================================================
echo "8️⃣  Cloud Functions..."
echo "  ⏭️  Skipped (requires source code deployment)"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "✅ Resource Provisioning Complete!"
echo "=========================================="
echo ""
echo "Resources created:"
cat $CLEANUP_FILE | wc -l | xargs echo "  Total:"
echo ""
echo "Cleanup file: $CLEANUP_FILE"
echo "To cleanup later, run: ./cleanup_test_resources.sh $PROJECT_ID"
echo ""
echo "🎯 Ready to run compliance scan!"
echo "   python engine/gcp_engine.py > comprehensive_scan.json"

