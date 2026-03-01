#!/bin/bash
# setup-sqs-iam.sh
#
# One-time setup: create SQS FIFO queues and attach SQS IAM policy to the
# threat-engine-platform-role used by all engine pods via IRSA.
#
# Run this ONCE before deploying the pipeline-worker or enabling SQS mode.
#
# Prerequisites:
#   - AWS CLI configured with a profile that has:
#       sqs:CreateQueue, sqs:SetQueueAttributes, sqs:GetQueueAttributes
#       iam:CreatePolicy, iam:AttachRolePolicy, iam:GetPolicy
#   - jq installed (for JSON parsing)
#
# Usage:
#   bash scripts/setup-sqs-iam.sh [--dry-run]

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
AWS_ACCOUNT_ID="588989875114"
AWS_REGION="${AWS_REGION:-ap-south-1}"
ROLE_NAME="threat-engine-platform-role"
POLICY_NAME="ThreatEngineSQSPolicy"
POLICY_DESC="SQS access for threat engine pipeline worker and onboarding engine"

PIPELINE_QUEUE="threat-engine-scan-requests.fifo"
PIPELINE_DLQ="threat-engine-scan-requests-dlq.fifo"
EVENTS_QUEUE="threat-engine-pipeline-events.fifo"
EVENTS_DLQ="threat-engine-pipeline-events-dlq.fifo"

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "[DRY RUN] No AWS changes will be made"
fi

run() {
  if $DRY_RUN; then
    echo "[DRY RUN] $*"
  else
    "$@"
  fi
}

echo ""
echo "=== Threat Engine SQS + IAM Setup ==="
echo "Region:  $AWS_REGION"
echo "Account: $AWS_ACCOUNT_ID"
echo "Role:    $ROLE_NAME"
echo ""

# ── Step 1: Create DLQs first (required for redrive policy) ───────────────────
echo "--- Step 1: Create DLQs ---"

echo "Creating $PIPELINE_DLQ..."
PIPELINE_DLQ_URL=$(run aws sqs create-queue \
  --queue-name "$PIPELINE_DLQ" \
  --region "$AWS_REGION" \
  --attributes '{
    "FifoQueue": "true",
    "ContentBasedDeduplication": "false",
    "MessageRetentionPeriod": "1209600"
  }' \
  --query 'QueueUrl' --output text 2>/dev/null || \
  aws sqs get-queue-url --queue-name "$PIPELINE_DLQ" --region "$AWS_REGION" --query 'QueueUrl' --output text)
echo "  → $PIPELINE_DLQ_URL"

echo "Creating $EVENTS_DLQ..."
EVENTS_DLQ_URL=$(run aws sqs create-queue \
  --queue-name "$EVENTS_DLQ" \
  --region "$AWS_REGION" \
  --attributes '{
    "FifoQueue": "true",
    "ContentBasedDeduplication": "false",
    "MessageRetentionPeriod": "1209600"
  }' \
  --query 'QueueUrl' --output text 2>/dev/null || \
  aws sqs get-queue-url --queue-name "$EVENTS_DLQ" --region "$AWS_REGION" --query 'QueueUrl' --output text)
echo "  → $EVENTS_DLQ_URL"

# Get DLQ ARNs for redrive policies
PIPELINE_DLQ_ARN="arn:aws:sqs:${AWS_REGION}:${AWS_ACCOUNT_ID}:${PIPELINE_DLQ}"
EVENTS_DLQ_ARN="arn:aws:sqs:${AWS_REGION}:${AWS_ACCOUNT_ID}:${EVENTS_DLQ}"

# ── Step 2: Create main queues with redrive policies ──────────────────────────
echo ""
echo "--- Step 2: Create main queues ---"

PIPELINE_REDRIVE="{\"deadLetterTargetArn\":\"${PIPELINE_DLQ_ARN}\",\"maxReceiveCount\":\"3\"}"
EVENTS_REDRIVE="{\"deadLetterTargetArn\":\"${EVENTS_DLQ_ARN}\",\"maxReceiveCount\":\"5\"}"

echo "Creating $PIPELINE_QUEUE..."
PIPELINE_QUEUE_URL=$(run aws sqs create-queue \
  --queue-name "$PIPELINE_QUEUE" \
  --region "$AWS_REGION" \
  --attributes "{
    \"FifoQueue\": \"true\",
    \"ContentBasedDeduplication\": \"false\",
    \"VisibilityTimeout\": \"3600\",
    \"MessageRetentionPeriod\": \"86400\",
    \"RedrivePolicy\": \"${PIPELINE_REDRIVE}\"
  }" \
  --query 'QueueUrl' --output text 2>/dev/null || \
  aws sqs get-queue-url --queue-name "$PIPELINE_QUEUE" --region "$AWS_REGION" --query 'QueueUrl' --output text)
echo "  → $PIPELINE_QUEUE_URL"

echo "Creating $EVENTS_QUEUE..."
EVENTS_QUEUE_URL=$(run aws sqs create-queue \
  --queue-name "$EVENTS_QUEUE" \
  --region "$AWS_REGION" \
  --attributes "{
    \"FifoQueue\": \"true\",
    \"ContentBasedDeduplication\": \"false\",
    \"VisibilityTimeout\": \"300\",
    \"MessageRetentionPeriod\": \"259200\",
    \"RedrivePolicy\": \"${EVENTS_REDRIVE}\"
  }" \
  --query 'QueueUrl' --output text 2>/dev/null || \
  aws sqs get-queue-url --queue-name "$EVENTS_QUEUE" --region "$AWS_REGION" --query 'QueueUrl' --output text)
echo "  → $EVENTS_QUEUE_URL"

# ── Step 3: Create SQS IAM policy ─────────────────────────────────────────────
echo ""
echo "--- Step 3: Create IAM policy $POLICY_NAME ---"

POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}"
POLICY_FILE="$(cd "$(dirname "$0")/.." && pwd)/deployment/aws/eks/iam/sqs-access-policy.json"

# Create policy (or get existing ARN)
if run aws iam get-policy --policy-arn "$POLICY_ARN" --region "$AWS_REGION" &>/dev/null; then
  echo "  Policy $POLICY_NAME already exists — skipping create"
else
  run aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "file://${POLICY_FILE}" \
    --description "$POLICY_DESC" \
    --region "$AWS_REGION"
  echo "  Created policy: $POLICY_ARN"
fi

# ── Step 4: Attach policy to IRSA role ────────────────────────────────────────
echo ""
echo "--- Step 4: Attach $POLICY_NAME to role $ROLE_NAME ---"

run aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "$POLICY_ARN"
echo "  Attached"

# ── Step 5: Apply sqs-config ConfigMap to EKS ─────────────────────────────────
echo ""
echo "--- Step 5: Apply sqs-config ConfigMap ---"

run kubectl apply \
  -f "$(cd "$(dirname "$0")/.." && pwd)/deployment/aws/eks/configmaps/sqs-config.yaml" \
  -n threat-engine-engines
echo "  Applied"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete ==="
echo ""
echo "Queue URLs (use in sqs-config.yaml if different):"
echo "  Pipeline: $PIPELINE_QUEUE_URL"
echo "  Events:   $EVENTS_QUEUE_URL"
echo ""
echo "Next steps:"
echo "  1. kubectl apply -f deployment/aws/eks/pipeline-worker/pipeline-worker.yaml -n threat-engine-engines"
echo "  2. kubectl apply -f deployment/aws/eks/engines/engine-onboarding.yaml -n threat-engine-engines"
echo "  3. Verify pipeline-worker is running:"
echo "       kubectl get pods -n threat-engine-engines -l app=pipeline-worker"
echo "  4. Send a test scan trigger to enable SQS mode:"
echo "       POST /onboarding/api/v1/scan/trigger"
echo "       (returns {\"mode\":\"sqs\"} when SQS_PIPELINE_QUEUE_URL is set)"
echo ""
