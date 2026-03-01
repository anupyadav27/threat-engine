#!/bin/bash
# Create SQS FIFO queues for the threat-engine async pipeline.
#
# Run once per AWS account:
#   bash scripts/create-sqs-queues.sh
#
# Prerequisites:
#   aws CLI configured with a role that has sqs:CreateQueue + sqs:SetQueueAttributes
#   AWS_REGION set or passed as first argument.
#
# What this creates:
#   threat-engine-scan-requests.fifo         Main pipeline input queue
#   threat-engine-scan-requests-dlq.fifo     DLQ (after 3 failed receives)
#   threat-engine-pipeline-events.fifo       Monitoring/events queue
#   threat-engine-pipeline-events-dlq.fifo   Events DLQ
#
# After creating queues, update deployment/aws/eks/configmaps/sqs-config.yaml
# with the actual queue URLs returned by this script.

set -euo pipefail

REGION="${1:-${AWS_REGION:-ap-south-1}}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

echo "Creating SQS FIFO queues in region=${REGION} account=${ACCOUNT_ID}"

# ── Helper: create a FIFO queue and return its URL ──────────────────────────

create_fifo_queue() {
  local name="$1"
  local visibility_timeout="${2:-3600}"
  local receive_count="${3:-3}"
  local dlq_arn="${4:-}"

  attrs="VisibilityTimeout=${visibility_timeout},FifoQueue=true,ContentBasedDeduplication=false"
  if [[ -n "$dlq_arn" ]]; then
    redrive="{\"deadLetterTargetArn\":\"${dlq_arn}\",\"maxReceiveCount\":\"${receive_count}\"}"
    attrs="${attrs},RedrivePolicy=${redrive}"
  fi

  url=$(aws sqs create-queue \
    --queue-name "${name}" \
    --region "${REGION}" \
    --attributes "${attrs}" \
    --query QueueUrl \
    --output text 2>/dev/null || \
    aws sqs get-queue-url --queue-name "${name}" --region "${REGION}" --query QueueUrl --output text)

  echo "${url}"
}

# ── 1. DLQs first (needed for redrive policy) ───────────────────────────────

echo ""
echo "Creating Dead-Letter Queues..."

PIPELINE_DLQ_URL=$(create_fifo_queue "threat-engine-scan-requests-dlq.fifo" 86400)
PIPELINE_DLQ_ARN="arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-scan-requests-dlq.fifo"
echo "  pipeline DLQ: ${PIPELINE_DLQ_URL}"

EVENTS_DLQ_URL=$(create_fifo_queue "threat-engine-pipeline-events-dlq.fifo" 86400)
EVENTS_DLQ_ARN="arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-pipeline-events-dlq.fifo"
echo "  events  DLQ: ${EVENTS_DLQ_URL}"

# ── 2. Main queues ──────────────────────────────────────────────────────────

echo ""
echo "Creating main queues..."

PIPELINE_QUEUE_URL=$(create_fifo_queue "threat-engine-scan-requests.fifo" 3600 3 "${PIPELINE_DLQ_ARN}")
echo "  pipeline queue: ${PIPELINE_QUEUE_URL}"

EVENTS_QUEUE_URL=$(create_fifo_queue "threat-engine-pipeline-events.fifo" 300 5 "${EVENTS_DLQ_ARN}")
echo "  events  queue: ${EVENTS_QUEUE_URL}"

# ── Summary ─────────────────────────────────────────────────────────────────

cat <<EOF

=== Done!  Update sqs-config.yaml with these URLs: ===

SQS_PIPELINE_QUEUE_URL: "${PIPELINE_QUEUE_URL}"
SQS_EVENTS_QUEUE_URL:   "${EVENTS_QUEUE_URL}"

DLQ URLs (for monitoring):
  pipeline DLQ: ${PIPELINE_DLQ_URL}
  events   DLQ: ${EVENTS_DLQ_URL}

=== IAM policy snippet (attach to pipeline-worker pod role): ===

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:ChangeMessageVisibility",
        "sqs:GetQueueAttributes"
      ],
      "Resource": [
        "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-scan-requests.fifo",
        "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-pipeline-events.fifo",
        "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-scan-requests-dlq.fifo",
        "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:threat-engine-pipeline-events-dlq.fifo"
      ]
    }
  ]
}
EOF
