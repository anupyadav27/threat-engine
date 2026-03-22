"""
SQS Consumer Worker — Task 0.2.7 [Seq 19 | BD]

Long-running process that listens for S3 event notifications on an SQS queue,
parses the event to extract the S3 object key, and routes to the correct
processor (vpc_flow, cloudtrail) based on the bucket/prefix pattern.

Architecture:
  - Calls sqs.receive_message(QueueUrl, MaxNumberOfMessages=10, WaitTimeSeconds=20) in a loop
  - Matches key pattern to source_type
  - Instantiates correct processor and calls processor.process(bucket, key)
  - Deletes message from queue on success
  - Re-drives to DLQ on error after 3 retries (handled by SQS redrive policy)

K8s deployment: log-collector-worker.yaml (separate from API pod)

Dependencies:
  - Tasks 0.2.3-0.2.6 (all processors must exist)
"""

import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any, Dict, List, Optional

import asyncpg
import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.log_collector.processors.vpc_flow_processor import VPCFlowProcessor
from shared.log_collector.processors.cloudtrail_processor import CloudTrailProcessor

logger = logging.getLogger("log_collector.sqs_worker")

# ---------------------------------------------------------------------------
# Key pattern → source_type mapping
# ---------------------------------------------------------------------------
KEY_PATTERNS = [
    ("VPCFlowLogs", "vpc_flow"),
    ("vpcflowlogs", "vpc_flow"),
    ("CloudTrail", "cloudtrail"),
    ("cloudtrail", "cloudtrail"),
]


def _classify_s3_key(key: str) -> Optional[str]:
    """Match an S3 object key to a source_type based on known patterns.

    Args:
        key: The S3 object key (e.g., 'AWSLogs/123/VPCFlowLogs/us-east-1/2024/...')

    Returns:
        source_type string or None if no pattern matches.
    """
    for pattern, source_type in KEY_PATTERNS:
        if pattern in key:
            return source_type
    return None


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
class SQSWorker:
    """Long-running SQS consumer that routes S3 events to the correct processor.

    Args:
        pool: asyncpg connection pool for threat_engine_logs.
        queue_url: SQS queue URL for S3 event notifications.
        sqs_client: boto3 SQS client (optional).
        s3_client: boto3 S3 client (optional).
        customer_id: Default customer ID for multi-tenancy.
        tenant_id: Default tenant ID for multi-tenancy.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        queue_url: str,
        sqs_client: Optional[Any] = None,
        s3_client: Optional[Any] = None,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        self._pool = pool
        self._queue_url = queue_url
        self._sqs = sqs_client or boto3.client("sqs")
        self._s3 = s3_client or boto3.client("s3")
        self._customer_id = customer_id
        self._tenant_id = tenant_id
        self._running = True

        # Initialise processors
        self._processors = {
            "vpc_flow": VPCFlowProcessor(pool, self._s3),
            "cloudtrail": CloudTrailProcessor(pool, self._s3),
        }

    async def run(self) -> None:
        """Main loop — poll SQS and process messages until stopped."""
        logger.info("SQS worker starting: queue_url=%s", self._queue_url)

        while self._running:
            try:
                messages = self._receive_messages()
                if not messages:
                    continue

                for message in messages:
                    await self._handle_message(message)

            except Exception as exc:
                logger.error("Error in SQS worker loop: %s", exc, exc_info=True)
                await asyncio.sleep(5)  # Back off on error

        logger.info("SQS worker stopped")

    def stop(self) -> None:
        """Signal the worker to stop after current iteration."""
        self._running = False
        logger.info("SQS worker stop requested")

    def _receive_messages(self) -> List[Dict]:
        """Receive up to 10 messages from SQS with long polling (20s)."""
        try:
            response = self._sqs.receive_message(
                QueueUrl=self._queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                AttributeNames=["ApproximateReceiveCount"],
            )
            return response.get("Messages", [])
        except Exception as exc:
            logger.error("Failed to receive SQS messages: %s", exc)
            return []

    async def _handle_message(self, message: Dict) -> None:
        """Parse an SQS message, route to processor, and delete on success.

        Args:
            message: SQS message dict with 'Body', 'ReceiptHandle', etc.
        """
        receipt_handle = message.get("ReceiptHandle", "")
        body_str = message.get("Body", "{}")

        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            logger.error("Invalid JSON in SQS message body: %s", body_str[:200])
            self._delete_message(receipt_handle)
            return

        # Handle SNS-wrapped S3 events (SNS → SQS fanout)
        if "Message" in body:
            try:
                body = json.loads(body["Message"])
            except (json.JSONDecodeError, TypeError):
                pass

        # Extract S3 records
        s3_records = body.get("Records", [])
        if not s3_records:
            logger.warning("No S3 Records in SQS message")
            self._delete_message(receipt_handle)
            return

        for record in s3_records:
            s3_info = record.get("s3", {})
            bucket = s3_info.get("bucket", {}).get("name", "")
            key = s3_info.get("object", {}).get("key", "")

            if not bucket or not key:
                logger.warning("Missing bucket or key in S3 record")
                continue

            # Classify and route
            source_type = _classify_s3_key(key)
            if source_type is None:
                logger.info("Unrecognised S3 key pattern, skipping: %s", key[:200])
                continue

            processor = self._processors.get(source_type)
            if processor is None:
                logger.warning("No processor registered for source_type=%s", source_type)
                continue

            try:
                result = await processor.process(
                    bucket=bucket,
                    key=key,
                    customer_id=self._customer_id,
                    tenant_id=self._tenant_id,
                )
                logger.info(
                    "Processed %s event: bucket=%s key=%s result=%s",
                    source_type, bucket, key[:100], result,
                )
            except Exception as exc:
                logger.error(
                    "Failed to process %s event: bucket=%s key=%s error=%s",
                    source_type, bucket, key[:100], exc, exc_info=True,
                )
                # Don't delete — SQS will retry (redrive to DLQ after maxReceiveCount)
                return

        # All records processed successfully — delete message
        self._delete_message(receipt_handle)

    def _delete_message(self, receipt_handle: str) -> None:
        """Delete a processed message from the SQS queue."""
        try:
            self._sqs.delete_message(
                QueueUrl=self._queue_url,
                ReceiptHandle=receipt_handle,
            )
        except Exception as exc:
            logger.error("Failed to delete SQS message: %s", exc)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
async def main() -> None:
    """Start the SQS worker process."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    queue_url = os.environ.get("TH_SQS_QUEUE_URL", "")
    if not queue_url:
        logger.error("TH_SQS_QUEUE_URL environment variable is required")
        sys.exit(1)

    pool = await asyncpg.create_pool(
        host=os.environ.get("LOG_COLLECTOR_DB_HOST", "localhost"),
        port=int(os.environ.get("LOG_COLLECTOR_DB_PORT", "5432")),
        database=os.environ.get("LOG_COLLECTOR_DB_NAME", "threat_engine_logs"),
        user=os.environ.get("LOG_COLLECTOR_DB_USER", "postgres"),
        password=os.environ.get("LOG_COLLECTOR_DB_PASSWORD", ""),
        min_size=2,
        max_size=10,
    )

    worker = SQSWorker(
        pool=pool,
        queue_url=queue_url,
        customer_id=os.environ.get("TH_CUSTOMER_ID"),
        tenant_id=os.environ.get("TH_TENANT_ID"),
    )

    # Graceful shutdown on SIGTERM/SIGINT
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.stop)

    try:
        await worker.run()
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
